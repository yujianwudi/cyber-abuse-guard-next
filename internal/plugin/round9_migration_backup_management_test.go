package plugin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestRound9ManagementDisclosesAndDoubleConfirmsMigrationBackupCleanup(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	directory := t.TempDir()
	dataDir := filepath.ToSlash(directory)
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")

	databasePath := filepath.Join(directory, "events.db")
	backupPath := databasePath + ".pre-v6-20260720T010203.000000000Z.bak"
	manifestPath := backupPath + ".manifest.json"
	if err := os.WriteFile(backupPath, []byte("retained-sensitive-preview"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(`{"schema":"test"}`), 0o400); err != nil {
		t.Fatal(err)
	}

	// Raw Capture disable must purge the active table without silently deleting
	// the exact pre-v6 rollback snapshot.
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("reconfigure code=%d envelope=%s", code, raw)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("Raw Capture disable removed migration backup: %v", err)
	}

	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	backups, ok := status["migration_backups"].(map[string]any)
	if !ok {
		t.Fatalf("migration_backups status=%#v", status["migration_backups"])
	}
	if backups["inventory_available"] != true || backups["count"] != float64(1) ||
		backups["may_contain_sensitive_request_data"] != true ||
		backups["automatic_raw_capture_disable_cleanup"] != false ||
		backups["cleanup_path"] != managementMigrationBackupPurgePath {
		t.Fatalf("migration backup status=%#v", backups)
	}
	if backups["sensitive_data_warning"] != "migration backups are exact rollback snapshots and may retain sensitive request previews; disabling Raw Capture does not delete them" {
		t.Fatalf("sensitive warning=%#v", backups["sensitive_data_warning"])
	}

	oneConfirmation, err := json.Marshal(migrationBackupPurgeRequest{
		DeleteConfirmation: migrationBackupDeleteConfirmation,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, body := callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementMigrationBackupPurgePath, oneConfirmation))
	if response.StatusCode != http.StatusPreconditionRequired || bodyErrorCode(body) != "confirmation_required" {
		t.Fatalf("single confirmation status=%d body=%s", response.StatusCode, body)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("single confirmation removed migration backup: %v", err)
	}

	response, body = callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementMigrationBackupPurgePath,
		[]byte(`{"delete_confirmation":"DELETE_ALL_MIGRATION_BACKUPS","rollback_loss_confirmation":"ACKNOWLEDGE_OLD_SO_ROLLBACK_REQUIRES_EXTERNAL_BACKUP","unexpected":true}`)))
	if response.StatusCode != http.StatusBadRequest || bodyErrorCode(body) != "invalid_request" {
		t.Fatalf("unknown cleanup field status=%d body=%s", response.StatusCode, body)
	}

	bothConfirmations, err := json.Marshal(migrationBackupPurgeRequest{
		DeleteConfirmation:       migrationBackupDeleteConfirmation,
		RollbackLossConfirmation: migrationBackupRollbackConfirmation,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, body = callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementMigrationBackupPurgePath, bothConfirmations))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("confirmed cleanup status=%d body=%s", response.StatusCode, body)
	}
	var result struct {
		DeletedBackups   int `json:"deleted_backups"`
		DeletedManifests int `json:"deleted_manifests"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.DeletedBackups != 1 || result.DeletedManifests != 1 {
		t.Fatalf("cleanup result=%+v", result)
	}
	for _, path := range []string{backupPath, manifestPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("migration artifact still exists after cleanup: path=%s err=%v", filepath.Base(path), err)
		}
	}
	status = managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	backups = status["migration_backups"].(map[string]any)
	if backups["count"] != float64(0) || backups["may_contain_sensitive_request_data"] != false {
		t.Fatalf("post-cleanup migration backup status=%#v", backups)
	}
}

func TestRound9ManagementMigrationBackupInventoryWorksWithAuditDisabled(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	directory := t.TempDir()
	dataDir := filepath.ToSlash(directory)
	register(t, p, "mode: audit\naudit:\n  enabled: false\n  data_dir: \""+dataDir+"\"\nsubject_control:\n  enabled: false\n")

	backupPath := filepath.Join(directory, "events.db") + ".pre-v6-20260720T010203.000000000Z.bak"
	if err := os.WriteFile(backupPath, []byte("disabled-audit-sensitive-preview"), 0o400); err != nil {
		t.Fatal(err)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	backups, ok := status["migration_backups"].(map[string]any)
	if !ok || backups["inventory_available"] != true || backups["count"] != float64(1) {
		t.Fatalf("disabled-audit migration backup status=%#v", status["migration_backups"])
	}

	body, err := json.Marshal(migrationBackupPurgeRequest{
		DeleteConfirmation:       migrationBackupDeleteConfirmation,
		RollbackLossConfirmation: migrationBackupRollbackConfirmation,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, raw := callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementMigrationBackupPurgePath, body))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disabled-audit cleanup status=%d body=%s", response.StatusCode, raw)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("disabled-audit cleanup retained backup: %v", err)
	}
}
