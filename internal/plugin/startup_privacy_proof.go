package plugin

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	startupPrivacyProofHeader       = "X-Cyber-Abuse-Guard-Startup-Proof"
	startupPrivacyProofResponseCode = http.StatusTeapot
	startupPrivacyChallengeBytes    = 32
	startupPrivacyChallengeLimit    = 16
	startupPrivacyChallengeTTL      = 30 * time.Second
)

var errStartupPrivacyChallengeUnavailable = errors.New("startup privacy challenge unavailable")

func newStartupPrivacyInstanceID() string {
	raw := make([]byte, startupPrivacyChallengeBytes)
	if err := readStartupPrivacyRandom(raw); err != nil {
		clear(raw)
		return ""
	}
	instanceID := hex.EncodeToString(raw)
	clear(raw)
	return instanceID
}

type startupPrivacyChallenge struct {
	expiresAt time.Time
	consumed  bool
}

// startupPrivacyChallengeStore is a small, process-local rendezvous between
// the authenticated Management API and one non-management request. It retains
// only random opaque tokens; no request body, credential, model name, or user
// content enters this cache.
type startupPrivacyChallengeStore struct {
	mu      sync.Mutex
	entries map[string]startupPrivacyChallenge
	now     func() time.Time
	random  func([]byte) error
}

func newStartupPrivacyChallengeStore() startupPrivacyChallengeStore {
	return startupPrivacyChallengeStore{
		entries: make(map[string]startupPrivacyChallenge),
		now:     time.Now,
		random:  readStartupPrivacyRandom,
	}
}

func readStartupPrivacyRandom(destination []byte) error {
	// Match the request-fingerprint key path: use a fallible Linux random
	// device instead of crypto/rand.Read, whose documented failure mode is an
	// unrecoverable process crash on the pinned Go toolchain.
	random, err := os.Open("/dev/urandom")
	if err != nil {
		return err
	}
	defer random.Close()
	_, err = io.ReadFull(random, destination)
	return err
}

func (store *startupPrivacyChallengeStore) issue() (string, time.Time, error) {
	if store == nil || store.now == nil || store.random == nil {
		return "", time.Time{}, errStartupPrivacyChallengeUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	store.purgeExpiredLocked(now)
	if len(store.entries) >= startupPrivacyChallengeLimit {
		return "", time.Time{}, errStartupPrivacyChallengeUnavailable
	}
	for attempt := 0; attempt < 4; attempt++ {
		raw := make([]byte, startupPrivacyChallengeBytes)
		if err := store.random(raw); err != nil {
			clear(raw)
			return "", time.Time{}, errStartupPrivacyChallengeUnavailable
		}
		token := hex.EncodeToString(raw)
		clear(raw)
		if _, exists := store.entries[token]; exists {
			continue
		}
		expiresAt := now.Add(startupPrivacyChallengeTTL)
		store.entries[token] = startupPrivacyChallenge{expiresAt: expiresAt}
		return token, expiresAt, nil
	}
	return "", time.Time{}, errStartupPrivacyChallengeUnavailable
}

func (store *startupPrivacyChallengeStore) consume(token string) bool {
	if store == nil || store.now == nil || !validStartupPrivacyChallenge(token) {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	store.purgeExpiredLocked(now)
	entry, exists := store.entries[token]
	if !exists || entry.consumed {
		return false
	}
	entry.consumed = true
	store.entries[token] = entry
	return true
}

func (store *startupPrivacyChallengeStore) statusAndDeleteConsumed(token string) (known, consumed bool) {
	if store == nil || store.now == nil || !validStartupPrivacyChallenge(token) {
		return false, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	store.purgeExpiredLocked(now)
	entry, exists := store.entries[token]
	if !exists {
		return false, false
	}
	if entry.consumed {
		delete(store.entries, token)
	}
	return true, entry.consumed
}

func (store *startupPrivacyChallengeStore) clear() {
	if store == nil {
		return
	}
	store.mu.Lock()
	clear(store.entries)
	store.mu.Unlock()
}

func (store *startupPrivacyChallengeStore) purgeExpiredLocked(now time.Time) {
	for token, entry := range store.entries {
		if !entry.expiresAt.After(now) {
			delete(store.entries, token)
		}
	}
}

func validStartupPrivacyChallenge(token string) bool {
	if len(token) != startupPrivacyChallengeBytes*2 || token != strings.ToLower(token) {
		return false
	}
	decoded, err := hex.DecodeString(token)
	valid := err == nil && len(decoded) == startupPrivacyChallengeBytes
	clear(decoded)
	return valid
}

func (p *Plugin) startupPrivacyResourceResponse(request pluginapi.ManagementRequest) []byte {
	if p == nil {
		return managementError(http.StatusNotFound, "not_found", "resource not found")
	}
	if request.Method != http.MethodGet || request.Path != startupPrivacyProofResourcePath ||
		len(request.Query) != 0 || len(request.Body) != 0 ||
		!connectionDeclaresHeader(request.Headers, startupPrivacyProofHeader) {
		return managementError(http.StatusNotFound, "not_found", "resource not found")
	}
	values := request.Headers.Values(startupPrivacyProofHeader)
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) {
		return managementError(http.StatusNotFound, "not_found", "resource not found")
	}
	token := values[0]
	if !p.startupPrivacyChallenges.consume(token) {
		return managementError(http.StatusNotFound, "not_found", "resource not found")
	}
	body, err := json.Marshal(struct {
		Challenge         string `json:"challenge"`
		InstanceID        string `json:"instance_id"`
		Consumed          bool   `json:"consumed"`
		LocalOnly         bool   `json:"local_only"`
		UpstreamAttempted bool   `json:"upstream_attempted"`
	}{
		Challenge: token, InstanceID: p.startupPrivacyInstanceID,
		Consumed: true, LocalOnly: true, UpstreamAttempted: false,
	})
	if err != nil {
		return managementError(http.StatusInternalServerError, "encode_error", "failed to encode startup privacy proof")
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: startupPrivacyProofResponseCode,
		Headers: http.Header{
			"Cache-Control":           []string{"no-store"},
			"Content-Type":            []string{"application/json; charset=utf-8"},
			"X-Content-Type-Options":  []string{"nosniff"},
			startupPrivacyProofHeader: []string{token},
		},
		Body: body,
	})
}

func connectionDeclaresHeader(headers http.Header, name string) bool {
	if headers == nil || name == "" {
		return false
	}
	matches := 0
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), name) {
				matches++
			}
		}
	}
	return matches == 1
}
