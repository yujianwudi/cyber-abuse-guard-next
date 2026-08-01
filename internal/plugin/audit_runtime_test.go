package plugin

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAuditPathFailureDegradesVisiblyWithoutDisablingEnforcement(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	p := New()
	t.Cleanup(p.Shutdown)
	var logMu sync.Mutex
	var logs []string
	p.SetLogger(func(level, message string, fields map[string]any) {
		logMu.Lock()
		logs = append(logs, level+":"+message)
		logMu.Unlock()
	})
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(linkedDirectory)+"\"\nsubject_control:\n  enabled: false\n")

	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("audit degradation disabled enforcement: %+v", route)
	}
	runtime := p.runtime.Load()
	status := runtime.audit.Status()
	if !status.Degraded || runtime.auditStorage.PersistenceReason != "symlinked_directory" {
		t.Fatalf("audit status = %#v storage=%#v, want visible symlink degradation", status, runtime.auditStorage)
	}
	if _, err := os.Lstat(filepath.Join(realDirectory, "events.db")); !os.IsNotExist(err) {
		t.Fatalf("unsafe symlink target was opened by SQLite: %v", err)
	}
	logMu.Lock()
	defer logMu.Unlock()
	found := false
	for _, line := range logs {
		found = found || strings.Contains(line, "audit storage is degraded")
	}
	if !found {
		t.Fatalf("audit degradation was not logged: %#v", logs)
	}

	response, body := callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodGet,
		managementBasePath+"/raw-captures",
		nil,
	))
	if response.StatusCode != http.StatusServiceUnavailable || bodyErrorCode(body) != "audit_unavailable" {
		t.Fatalf("degraded disabled-capture response=%+v body=%s", response, body)
	}
}
