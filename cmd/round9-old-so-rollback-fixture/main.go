// Command round9-old-so-rollback-fixture migrates one synthetic schema-v5
// database to the current audit schema inside a marked private sandbox. It is
// not an operator migration utility and intentionally refuses paths outside
// that sandbox.
package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
)

const (
	sandboxMarkerName    = ".round9-old-so-rollback-sandbox"
	sandboxMarkerContent = "isolated-synthetic-fixture-only-v1\n"
	requiredGoVersion    = "go1.26.6"
)

type migrationResult struct {
	SourceSchemaVersion int    `json:"source_schema_version"`
	TargetSchemaVersion int    `json:"target_schema_version"`
	SQLiteQuickCheck    string `json:"sqlite_quick_check"`
	Platform            string `json:"platform"`
	GoRuntime           string `json:"go_runtime"`
	SyntheticOnly       bool   `json:"synthetic_only"`
	ProductionContacted bool   `json:"production_contacted"`
}

func main() {
	var sandboxRoot, databasePath, nowText string
	flag.StringVar(&sandboxRoot, "sandbox-root", "", "marked private synthetic sandbox")
	flag.StringVar(&databasePath, "database", "", "schema-v5 database inside the sandbox")
	flag.StringVar(&nowText, "now", "", "fixed RFC3339Nano migration time")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("positional arguments are not supported"))
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fatal(errors.New("fixture requires linux/amd64"))
	}
	if runtime.Version() != requiredGoVersion {
		fatal(fmt.Errorf("fixture requires %s, got %s", requiredGoVersion, runtime.Version()))
	}
	root, database, err := validateSandboxPaths(sandboxRoot, databasePath)
	if err != nil {
		fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, nowText)
	if err != nil || now.Location() != time.UTC {
		fatal(errors.New("--now must be an exact UTC RFC3339Nano timestamp"))
	}
	if err := requireMarker(root); err != nil {
		fatal(err)
	}
	version, quickCheck, err := inspectSQLite(database)
	if err != nil {
		fatal(fmt.Errorf("inspect schema-v5 input: %w", err))
	}
	if version != 5 || quickCheck != "ok" {
		fatal(fmt.Errorf("input schema=%d quick_check=%q, want schema=5 quick_check=ok", version, quickCheck))
	}

	store, openErr := audit.Open(audit.Config{
		Path:                  database,
		BackupBeforeMigration: false,
		MaxMigrationBackups:   1,
		Now:                   func() time.Time { return now },
		RawCapture: audit.RawCaptureConfig{
			Enabled:       true,
			OnlyBlocked:   true,
			RedactSecrets: true,
			MaxBytes:      8192,
			TTL:           10 * 365 * 24 * time.Hour,
		},
	})
	if store == nil {
		fatal(errors.New("current-schema migration returned a nil audit store"))
	}
	if openErr != nil {
		_ = store.Close()
		fatal(fmt.Errorf("current-schema migration failed: %w", openErr))
	}
	if status := store.Status(); status.SchemaVersion != audit.SchemaVersion || !status.Healthy {
		_ = store.Close()
		fatal(fmt.Errorf("migrated store status schema=%d healthy=%v", status.SchemaVersion, status.Healthy))
	}
	if err := store.Close(); err != nil {
		fatal(fmt.Errorf("close migrated audit store: %w", err))
	}
	version, quickCheck, err = inspectSQLite(database)
	if err != nil {
		fatal(fmt.Errorf("inspect current-schema output: %w", err))
	}
	if version != audit.SchemaVersion || quickCheck != "ok" {
		fatal(fmt.Errorf("output schema=%d quick_check=%q, want schema=%d quick_check=ok", version, quickCheck, audit.SchemaVersion))
	}
	result := migrationResult{
		SourceSchemaVersion: 5,
		TargetSchemaVersion: audit.SchemaVersion,
		SQLiteQuickCheck:    quickCheck,
		Platform:            "linux/amd64",
		GoRuntime:           runtime.Version(),
		SyntheticOnly:       true,
		ProductionContacted: false,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fatal(fmt.Errorf("encode migration result: %w", err))
	}
}

func validateSandboxPaths(rootText, databaseText string) (string, string, error) {
	if strings.TrimSpace(rootText) == "" || strings.TrimSpace(databaseText) == "" {
		return "", "", errors.New("--sandbox-root and --database are required")
	}
	root, err := filepath.Abs(rootText)
	if err != nil {
		return "", "", fmt.Errorf("resolve sandbox root: %w", err)
	}
	database, err := filepath.Abs(databaseText)
	if err != nil {
		return "", "", fmt.Errorf("resolve database path: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", "", fmt.Errorf("inspect sandbox root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return "", "", errors.New("sandbox root must be a private real directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || resolvedRoot != root {
		return "", "", errors.New("sandbox root or a parent resolves through a symlink")
	}
	databaseInfo, err := os.Lstat(database)
	if err != nil {
		return "", "", fmt.Errorf("inspect sandbox database: %w", err)
	}
	if databaseInfo.Mode()&os.ModeSymlink != 0 || !databaseInfo.Mode().IsRegular() || databaseInfo.Mode().Perm()&0o077 != 0 {
		return "", "", errors.New("sandbox database must be a private regular file")
	}
	relative, err := filepath.Rel(root, database)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", errors.New("sandbox database must stay below the sandbox root")
	}
	return root, database, nil
}

func requireMarker(root string) error {
	marker := filepath.Join(root, sandboxMarkerName)
	info, err := os.Lstat(marker)
	if err != nil {
		return fmt.Errorf("inspect sandbox marker: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("sandbox marker must be a private regular file")
	}
	value, err := os.ReadFile(marker)
	if err != nil {
		return fmt.Errorf("read sandbox marker: %w", err)
	}
	if string(value) != sandboxMarkerContent {
		return errors.New("sandbox marker identity changed")
	}
	return nil
}

func inspectSQLite(path string) (int, string, error) {
	parameters := url.Values{}
	parameters.Set("mode", "ro")
	parameters.Set("immutable", "1")
	parameters.Set("_query_only", "true")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: parameters.Encode()}).String()
	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return 0, "", err
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	var version int
	if err := database.QueryRow("SELECT version FROM schema_version WHERE singleton=1").Scan(&version); err != nil {
		return 0, "", err
	}
	var quickCheckText string
	if err := database.QueryRow("PRAGMA quick_check").Scan(&quickCheckText); err != nil {
		return 0, "", err
	}
	return version, quickCheckText, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Round 9 old-SO migration fixture: FAIL: %v\n", err)
	os.Exit(1)
}
