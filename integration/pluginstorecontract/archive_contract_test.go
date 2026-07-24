package pluginstorecontract

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginstore"
)

const (
	pluginID = "cyber-abuse-guard"
	goos     = "linux"
	goarch   = "amd64"
)

type buildMetadata struct {
	Version string `json:"version"`
}

func TestOfficialInstallArchiveContract(t *testing.T) {
	version := "0.15"
	binaryName := versionedLibraryName(version)
	binaryData := []byte("opaque synthetic shared-object bytes")
	archiveName := officialArchiveName(t, version)
	archiveData := makeArchive(t, map[string]archiveFile{
		binaryName: {data: binaryData, mode: 0o755},
	})

	checksum := sha256.Sum256(archiveData)
	checksums, errParse := pluginstore.ParseChecksums([]byte(fmt.Sprintf(
		"%x  %s\n",
		checksum,
		archiveName,
	)))
	if errParse != nil {
		t.Fatalf("ParseChecksums() error = %v", errParse)
	}
	if errVerify := pluginstore.VerifyChecksum(archiveName, archiveData, checksums); errVerify != nil {
		t.Fatalf("VerifyChecksum() error = %v", errVerify)
	}

	assertExactStoreArchive(t, archiveData, binaryName, binaryData)
	assertInstallLifecycle(t, archiveData, binaryData, version)
}

func TestOfficialInstallArchiveRejectsLegacyNestedLayout(t *testing.T) {
	version := "0.15"
	archiveData := makeArchive(t, map[string]archiveFile{
		"plugins/linux/amd64/" + versionedLibraryName(version): {
			data: []byte("opaque synthetic shared-object bytes"),
			mode: 0o755,
		},
	})

	_, errInstall := pluginstore.InstallArchive(archiveData, pluginstore.Plugin{
		ID:      pluginID,
		Version: version,
	}, pluginstore.InstallOptions{
		PluginsDir: t.TempDir(),
		GOOS:       goos,
		GOARCH:     goarch,
	})
	if errInstall == nil {
		t.Fatal("InstallArchive() error = nil for legacy nested layout")
	}
	if !strings.Contains(errInstall.Error(), "target dynamic library must be at zip root") {
		t.Fatalf("InstallArchive() error = %v, want nested-target rejection", errInstall)
	}
}

func TestPublishedStoreArchive(t *testing.T) {
	distDir := strings.TrimSpace(os.Getenv("DIST_DIR"))
	if distDir == "" {
		t.Skip("DIST_DIR is not set; artifact contract test is run by the packaging gate")
	}
	distDir, errAbs := filepath.Abs(distDir)
	if errAbs != nil {
		t.Fatalf("filepath.Abs(DIST_DIR) error = %v", errAbs)
	}

	metadataData, errReadMetadata := os.ReadFile(filepath.Join(distDir, "build-metadata.json"))
	if errReadMetadata != nil {
		t.Fatalf("read build metadata: %v", errReadMetadata)
	}
	var metadata buildMetadata
	if errDecode := json.Unmarshal(metadataData, &metadata); errDecode != nil {
		t.Fatalf("decode build metadata: %v", errDecode)
	}
	version := strings.TrimSpace(metadata.Version)
	if version == "" {
		t.Fatal("build metadata version is empty")
	}

	archiveName := officialArchiveName(t, version)
	binaryName := versionedLibraryName(version)
	archiveData := readRequiredFile(t, filepath.Join(distDir, archiveName))
	binaryData := readRequiredFile(t, filepath.Join(distDir, binaryName))
	checksumData := readRequiredFile(t, filepath.Join(distDir, "checksums.txt"))

	checksums, errParse := pluginstore.ParseChecksums(checksumData)
	if errParse != nil {
		t.Fatalf("ParseChecksums(checksums.txt) error = %v", errParse)
	}
	if errVerify := pluginstore.VerifyChecksum(archiveName, archiveData, checksums); errVerify != nil {
		t.Fatalf("VerifyChecksum(%s) error = %v", archiveName, errVerify)
	}

	assertExactStoreArchive(t, archiveData, binaryName, binaryData)
	assertInstallLifecycle(t, archiveData, binaryData, version)
}

func assertInstallLifecycle(t *testing.T, archiveData, binaryData []byte, version string) {
	t.Helper()

	pluginsDir := t.TempDir()
	plugin := pluginstore.Plugin{ID: pluginID, Version: version}
	options := pluginstore.InstallOptions{
		PluginsDir: pluginsDir,
		GOOS:       goos,
		GOARCH:     goarch,
	}
	wantPath := filepath.Join(pluginsDir, goos, goarch, versionedLibraryName(version))

	first, errFirst := pluginstore.InstallArchive(archiveData, plugin, options)
	if errFirst != nil {
		t.Fatalf("first InstallArchive() error = %v", errFirst)
	}
	if first.ID != pluginID || first.Version != version || first.Path != wantPath {
		t.Fatalf("first InstallArchive() result = %#v, want id=%q version=%q path=%q", first, pluginID, version, wantPath)
	}
	if first.Overwritten || first.Skipped {
		t.Fatalf("first InstallArchive() overwritten=%v skipped=%v, want false/false", first.Overwritten, first.Skipped)
	}
	assertFileBytes(t, wantPath, binaryData)

	second, errSecond := pluginstore.InstallArchive(archiveData, plugin, options)
	if errSecond != nil {
		t.Fatalf("second InstallArchive() error = %v", errSecond)
	}
	if second.Path != wantPath || !second.Overwritten || !second.Skipped {
		t.Fatalf("second InstallArchive() result = %#v, want identical install skipped at %q", second, wantPath)
	}
	assertFileBytes(t, wantPath, binaryData)

	if errWrite := os.WriteFile(wantPath, []byte("tampered installed bytes"), 0o600); errWrite != nil {
		t.Fatalf("tamper installed file: %v", errWrite)
	}
	third, errThird := pluginstore.InstallArchive(archiveData, plugin, options)
	if errThird != nil {
		t.Fatalf("repair InstallArchive() error = %v", errThird)
	}
	if third.Path != wantPath || !third.Overwritten || third.Skipped {
		t.Fatalf("repair InstallArchive() result = %#v, want overwritten and not skipped at %q", third, wantPath)
	}
	assertFileBytes(t, wantPath, binaryData)
}

func assertExactStoreArchive(t *testing.T, archiveData []byte, binaryName string, binaryData []byte) {
	t.Helper()

	reader, errZip := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if errZip != nil {
		t.Fatalf("open store ZIP: %v", errZip)
	}
	if len(reader.File) != 1 {
		t.Fatalf("store ZIP entries = %d, want exactly 1", len(reader.File))
	}
	entry := reader.File[0]
	if entry.Name != binaryName {
		t.Fatalf("store ZIP entry = %q, want %q", entry.Name, binaryName)
	}
	if strings.ContainsAny(entry.Name, `/\\`) {
		t.Fatalf("store ZIP dynamic library is not at archive root: %q", entry.Name)
	}
	if entry.FileInfo().IsDir() || !(entry.Mode().IsRegular() || entry.Mode().Type() == 0) {
		t.Fatalf("store ZIP entry %q is not a regular file", entry.Name)
	}
	if gotMode := entry.Mode().Perm(); gotMode != 0o755 {
		t.Fatalf("store ZIP entry mode = %04o, want 0755", gotMode)
	}

	handle, errOpen := entry.Open()
	if errOpen != nil {
		t.Fatalf("open store ZIP entry: %v", errOpen)
	}
	entryData, errRead := io.ReadAll(handle)
	errClose := handle.Close()
	if errRead != nil {
		t.Fatalf("read store ZIP entry: %v", errRead)
	}
	if errClose != nil {
		t.Fatalf("close store ZIP entry: %v", errClose)
	}
	if !bytes.Equal(entryData, binaryData) {
		t.Fatal("store ZIP dynamic library differs from standalone artifact")
	}
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()

	got, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read installed file %s: %v", path, errRead)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("installed file %s differs from archive payload", path)
	}
}

func readRequiredFile(t *testing.T, path string) []byte {
	t.Helper()

	info, errStat := os.Lstat(path)
	if errStat != nil {
		t.Fatalf("stat required artifact %s: %v", path, errStat)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("required artifact is not a regular file: %s", path)
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read required artifact %s: %v", path, errRead)
	}
	return data
}

func versionedLibraryName(version string) string {
	return pluginID + "-v" + version + ".so"
}

func officialArchiveName(t *testing.T, version string) string {
	t.Helper()

	want := fmt.Sprintf("%s_%s_%s_%s.zip", pluginID, version, goos, goarch)
	got := pluginstore.ArchiveName(pluginID, version, goos, goarch)
	if got != want {
		t.Fatalf("ArchiveName() = %q, want %q", got, want)
	}
	return got
}

type archiveFile struct {
	data []byte
	mode os.FileMode
}

func makeArchive(t *testing.T, files map[string]archiveFile) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, file := range files {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(file.mode)
		header.SetModTime(time.Unix(1, 0).UTC())
		handle, errCreate := writer.CreateHeader(header)
		if errCreate != nil {
			t.Fatalf("create ZIP entry %s: %v", name, errCreate)
		}
		if _, errWrite := handle.Write(file.data); errWrite != nil {
			t.Fatalf("write ZIP entry %s: %v", name, errWrite)
		}
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatalf("close ZIP writer: %v", errClose)
	}
	return buffer.Bytes()
}
