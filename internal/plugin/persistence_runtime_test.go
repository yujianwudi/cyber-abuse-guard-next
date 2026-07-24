package plugin

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestSubjectPersistenceRequiresStableHMAC(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "")
	t.Setenv(subject.HMACKeyFileEnvironment, "")
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t, persistenceYAML(dataDir, "balanced")))
	err := assertEnvelopeError(t, raw, code, "invalid_config", 0)
	if !strings.Contains(err.Message, "stable HMAC key") {
		t.Fatalf("unstable HMAC persistence error=%#v", err)
	}
}

func TestSubjectPersistenceRestoresAcrossReconfigureAndRestart(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	dataDir := filepath.ToSlash(t.TempDir())
	headers := http.Header{"Authorization": []string{"Bearer persistent-runtime-subject"}}

	first := New()
	register(t, first, persistenceYAML(dataDir, "balanced"))
	if route := callRouteWithHeaders(t, first, maliciousRequest, headers); !route.Handled {
		t.Fatalf("setup malicious route was not blocked: %+v", route)
	}
	if route := callRouteWithHeaders(t, first, maliciousRequest, headers); !route.Handled {
		t.Fatalf("duplicate setup route was not blocked: %+v", route)
	}
	subjectHash := first.identifier.FromHeaders(headers).Hash
	before, ok := first.runtime.Load().subject.Snapshot(subjectHash)
	if !ok || before.HitCount != 1 {
		t.Fatalf("subject before persistence=%#v, %v", before, ok)
	}
	raw, code := first.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, persistenceYAML(dataDir, "audit")))
	if code != 0 {
		t.Fatalf("persistent reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	first.Shutdown() // clean boundary performs a final atomic snapshot save

	second := New()
	t.Cleanup(second.Shutdown)
	register(t, second, persistenceYAML(dataDir, "balanced"))
	after, ok := second.runtime.Load().subject.Snapshot(subjectHash)
	if !ok || after.HitCount != before.HitCount || after.Score <= 0 {
		t.Fatalf("restored subject=%#v, %v; before=%#v", after, ok, before)
	}
	if route := callRouteWithHeaders(t, second, maliciousRequest, headers); !route.Handled {
		t.Fatalf("restored duplicate route was not blocked: %+v", route)
	}
	if afterRetry, ok := second.runtime.Load().subject.Snapshot(subjectHash); !ok || afterRetry.HitCount != 1 {
		t.Fatalf("restored duplicate request was re-accounted: %#v, %v", afterRetry, ok)
	}
	status := managementJSON(t, second, http.MethodGet, managementBasePath+"/status", nil)
	persistence, ok := status["subject_persistence"].(map[string]any)
	if !ok || persistence["enabled"] != true || persistence["degraded"] != false || persistence["restored_subjects"] != float64(1) || status["persistence_degraded"] != false {
		t.Fatalf("subject persistence status=%#v", status)
	}
}

func TestSubjectPersistenceKeyMismatchIsVisibleWithoutFailOpen(t *testing.T) {
	dataDir := filepath.ToSlash(t.TempDir())
	headers := http.Header{"Authorization": []string{"Bearer mismatched-runtime-subject"}}

	t.Setenv(subject.HMACKeyEnvironment, "11111111111111111111111111111111")
	first := New()
	register(t, first, persistenceYAML(dataDir, "balanced"))
	if route := callRouteWithHeaders(t, first, maliciousRequest, headers); !route.Handled {
		t.Fatalf("setup route was not blocked: %+v", route)
	}
	first.Shutdown()

	t.Setenv(subject.HMACKeyEnvironment, "22222222222222222222222222222222")
	second := New()
	t.Cleanup(second.Shutdown)
	register(t, second, persistenceYAML(dataDir, "balanced"))
	status := managementJSON(t, second, http.MethodGet, managementBasePath+"/status", nil)
	persistence, ok := status["subject_persistence"].(map[string]any)
	if !ok || persistence["degraded"] != true || persistence["writes_blocked"] != true || persistence["last_error"] != "subject persistence is degraded" || status["persistence_degraded"] != true {
		t.Fatalf("HMAC mismatch persistence status=%#v", status)
	}
	if route := callRouteWithHeaders(t, second, maliciousRequest, headers); !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf {
		t.Fatalf("persistence mismatch weakened in-memory enforcement: %+v", route)
	}
	second.Shutdown()

	// The mismatched runtime must not silently overwrite the old correlation
	// state during its clean shutdown. Restoring the original key can still load
	// the original snapshot for operator-directed recovery.
	t.Setenv(subject.HMACKeyEnvironment, "11111111111111111111111111111111")
	third := New()
	t.Cleanup(third.Shutdown)
	register(t, third, persistenceYAML(dataDir, "balanced"))
	originalHash := third.identifier.FromHeaders(headers).Hash
	if restored, ok := third.runtime.Load().subject.Snapshot(originalHash); !ok || restored.HitCount != 1 {
		t.Fatalf("mismatched shutdown overwrote original persisted state: %#v, %v", restored, ok)
	}
}

func TestSubjectPersistenceRestoreErrorsBlockWritesAndPreserveCorruptSnapshot(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	testCases := []struct {
		name      string
		forbidden string
		tamper    func(*testing.T, *sql.DB)
	}{
		{
			name: "row integrity",
			tamper: func(t *testing.T, db *sql.DB) {
				t.Helper()
				rowHash, persisted := loadOneRawPersistentSubject(t, db)
				digest := sha256.Sum256([]byte("different-persisted-subject"))
				persisted.SubjectHash = "hmac-sha256:" + hex.EncodeToString(digest[:])
				updateRawPersistentSubject(t, db, rowHash, persisted)
			},
		},
		{
			name: "JSON decode",
			tamper: func(t *testing.T, db *sql.DB) {
				t.Helper()
				if _, err := db.Exec(`UPDATE subject_state SET state_json = '{'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "JSON unknown field privacy",
			forbidden: "PERSISTENCE_ERROR_CANARY_76ca19e0",
			tamper: func(t *testing.T, db *sql.DB) {
				t.Helper()
				if _, err := db.Exec(`UPDATE subject_state SET state_json = '{"PERSISTENCE_ERROR_CANARY_76ca19e0":true}'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsupported version",
			tamper: func(t *testing.T, db *sql.DB) {
				t.Helper()
				if _, err := db.Exec(`UPDATE subject_state_meta SET persistence_version = ?`, subject.PersistenceVersion+1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "future save time",
			tamper: func(t *testing.T, db *sql.DB) {
				t.Helper()
				if _, err := db.Exec(`UPDATE subject_state_meta SET saved_at_ns = ?`, time.Now().UTC().Add(time.Hour).UnixNano()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "invalid score",
			tamper: func(t *testing.T, db *sql.DB) {
				t.Helper()
				rowHash, persisted := loadOneRawPersistentSubject(t, db)
				if len(persisted.Hits) == 0 {
					t.Fatal("seed snapshot contains no risk hits")
				}
				persisted.Hits[0].Score = 0
				updateRawPersistentSubject(t, db, rowHash, persisted)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dataDir := filepath.ToSlash(t.TempDir())
			databasePath := filepath.Join(filepath.FromSlash(dataDir), "events.db")
			headers := http.Header{"Authorization": []string{"Bearer corrupt-runtime-subject"}}

			first := New()
			t.Cleanup(first.Shutdown)
			register(t, first, persistenceYAML(dataDir, "balanced"))
			if route := callRouteWithHeaders(t, first, maliciousRequest, headers); !route.Handled {
				t.Fatalf("seed malicious route was not blocked: %+v", route)
			}
			first.Shutdown()

			db := openPersistenceTestDB(t, databasePath)
			testCase.tamper(t, db)
			before := rawSubjectPersistenceImage(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			second := New()
			t.Cleanup(second.Shutdown)
			register(t, second, persistenceYAML(dataDir, "balanced"))
			status := managementJSON(t, second, http.MethodGet, managementBasePath+"/status", nil)
			persistence, ok := status["subject_persistence"].(map[string]any)
			if !ok || persistence["degraded"] != true || persistence["writes_blocked"] != true || persistence["last_error"] != "subject persistence is degraded" || status["persistence_degraded"] != true {
				t.Fatalf("corrupt restore persistence status=%#v", status)
			}
			if testCase.forbidden != "" {
				encodedStatus, err := json.Marshal(status)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encodedStatus), testCase.forbidden) {
					t.Fatal("subject persistence status reflected corrupt snapshot content")
				}
			}
			if route := callRouteWithHeaders(t, second, maliciousRequest, headers); !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf {
				t.Fatalf("corrupt persistence weakened in-memory enforcement: %+v", route)
			}
			second.Shutdown() // route dirtied state; final save must remain blocked

			db = openPersistenceTestDB(t, databasePath)
			after := rawSubjectPersistenceImage(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("route/dirty/shutdown overwrote corrupt persistence snapshot\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
}

func openPersistenceTestDB(t testing.TB, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return db
}

func loadOneRawPersistentSubject(t testing.TB, db *sql.DB) (string, subject.PersistentSubject) {
	t.Helper()
	var rowHash, raw string
	if err := db.QueryRow(`SELECT subject_hash, state_json FROM subject_state ORDER BY subject_hash LIMIT 1`).Scan(&rowHash, &raw); err != nil {
		t.Fatal(err)
	}
	var persisted subject.PersistentSubject
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatal(err)
	}
	return rowHash, persisted
}

func updateRawPersistentSubject(t testing.TB, db *sql.DB, rowHash string, persisted subject.PersistentSubject) {
	t.Helper()
	raw, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE subject_state SET state_json = ? WHERE subject_hash = ?`, string(raw), rowHash); err != nil {
		t.Fatal(err)
	}
}

func rawSubjectPersistenceImage(t testing.TB, db *sql.DB) string {
	t.Helper()
	type rawRow struct {
		SubjectHash string `json:"subject_hash"`
		StateJSON   string `json:"state_json"`
		UpdatedAtNS int64  `json:"updated_at_ns"`
	}
	type rawImage struct {
		Version     int      `json:"version"`
		HMACKeyID   string   `json:"hmac_key_id"`
		SavedAtNS   int64    `json:"saved_at_ns"`
		UpdatedAtNS int64    `json:"updated_at_ns"`
		Rows        []rawRow `json:"rows"`
	}
	var image rawImage
	if err := db.QueryRow(`SELECT persistence_version, hmac_key_id, saved_at_ns, updated_at_ns FROM subject_state_meta WHERE singleton = 1`).Scan(
		&image.Version, &image.HMACKeyID, &image.SavedAtNS, &image.UpdatedAtNS,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT subject_hash, state_json, updated_at_ns FROM subject_state ORDER BY subject_hash`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var row rawRow
		if err := rows.Scan(&row.SubjectHash, &row.StateJSON, &row.UpdatedAtNS); err != nil {
			t.Fatal(err)
		}
		image.Rows = append(image.Rows, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func callRouteWithHeaders(t testing.TB, p *Plugin, body string, headers http.Header) pluginapi.ModelRouteResponse {
	t.Helper()
	request := pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "gpt-test",
		Headers:        headers,
		Body:           []byte(body),
	}
	rawRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	if code != 0 {
		t.Fatalf("model.route code=%d envelope=%s", code, raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	return route
}

func persistenceYAML(dataDir, mode string) string {
	return "mode: " + mode + "\n" +
		"audit:\n  enabled: true\n  data_dir: \"" + dataDir + "\"\n" +
		"subject_control:\n  enabled: true\n  persistence: true\n"
}
