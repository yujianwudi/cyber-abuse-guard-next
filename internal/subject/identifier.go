// Package subject provides privacy-preserving subject identification and
// in-memory risk accumulation. It never retains plaintext credentials.
package subject

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

const (
	// HMACKeyEnvironment contains persistent HMAC key material.
	HMACKeyEnvironment = "CYBER_ABUSE_GUARD_HMAC_KEY"
	// HMACKeyFileEnvironment points to a permission-checked persistent key file.
	HMACKeyFileEnvironment = "CYBER_ABUSE_GUARD_HMAC_KEY_FILE"
	minimumHMACKeyBytes    = 32
	maximumSecretBytes     = 4096
)

// Source describes the trusted header class used to derive an identity. It
// deliberately does not include any part of the credential itself.
type Source string

const (
	SourceAuthorization Source = "authorization_bearer"
	SourceAPIKey        Source = "x_api_key"
	SourceConflict      Source = "credential_conflict"
	SourceAnonymous     Source = "anonymous"
)

func (s Source) String() string { return string(s) }

// KeySource describes where the HMAC key came from.
type KeySource string

const (
	KeySourceEnvironment   KeySource = "environment"
	KeySourceFile          KeySource = "file"
	KeySourceProcessRandom KeySource = "process_random"
)

// Identity contains only an HMAC correlation value and a coarse source.
type Identity struct {
	Hash   string `json:"hash"`
	Source Source `json:"source"`
}

// IdentifierStatus is safe to expose from a management status endpoint.
type IdentifierStatus struct {
	Stable   bool      `json:"stable"`
	Degraded bool      `json:"degraded"`
	Source   KeySource `json:"source"`
	Warning  string    `json:"warning,omitempty"`
}

// IdentifierConfig selects an optional, explicitly configured secret file.
// Getenv and Random are dependency-injection seams for tests; nil uses the OS
// environment and crypto/rand.Reader respectively.
type IdentifierConfig struct {
	SecretFile string
	Getenv     func(string) string
	Random     io.Reader
}

// Identifier immediately HMACs supported inbound credentials. It stores only
// key material and never stores a header value or plaintext API key.
type Identifier struct {
	key    []byte
	status IdentifierStatus
}

// NewIdentifier loads the HMAC key from the environment, then from an
// explicitly configured mode-0600 regular file. If neither source is present,
// it creates a process-random key and marks the identifier degraded because
// subject hashes will change at restart.
func NewIdentifier(cfg IdentifierConfig) (*Identifier, error) {
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if value := getenv(HMACKeyEnvironment); value != "" {
		key := []byte(value)
		if err := validateKey(key); err != nil {
			return nil, fmt.Errorf("subject: %s: %w", HMACKeyEnvironment, err)
		}
		return newIdentifier(key, IdentifierStatus{Stable: true, Source: KeySourceEnvironment}), nil
	}

	secretFile := cfg.SecretFile
	if secretFile == "" {
		secretFile = getenv(HMACKeyFileEnvironment)
	}
	if secretFile != "" {
		key, err := readSecretFile(secretFile)
		if err != nil {
			return nil, err
		}
		return newIdentifier(key, IdentifierStatus{Stable: true, Source: KeySourceFile}), nil
	}

	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	key := make([]byte, minimumHMACKeyBytes)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, fmt.Errorf("subject: generate process-random HMAC key: %w", err)
	}
	return newIdentifier(key, IdentifierStatus{
		Stable:   false,
		Degraded: true,
		Source:   KeySourceProcessRandom,
		Warning:  "subject hashes are process-random and will change after restart",
	}), nil
}

func newIdentifier(key []byte, status IdentifierStatus) *Identifier {
	owned := make([]byte, len(key))
	copy(owned, key)
	return &Identifier{key: owned, status: status}
}

// Status returns a secret-free status snapshot.
func (i *Identifier) Status() IdentifierStatus {
	if i == nil {
		return IdentifierStatus{Degraded: true, Warning: "subject identifier is unavailable"}
	}
	return i.status
}

// KeyID returns a one-way identifier for the active HMAC key. It is suitable
// for deciding whether persisted subject hashes are still correlatable after
// restart; it never exposes the key itself.
func (i *Identifier) KeyID() string {
	if i == nil || len(i.key) == 0 {
		return ""
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("cyber-abuse-guard:hmac-key-id:v1\x00"))
	_, _ = digest.Write(i.key)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

// FromHeaders aggregates header names case-insensitively, rejects competing
// non-empty Authorization values as one deterministic untrusted identity, then
// prefers a sole Bearer credential over x-api-key. Unsupported sole schemes do
// not become credential material and retain the x-api-key fallback.
func (i *Identifier) FromHeaders(headers http.Header) Identity {
	if values := normalizedAuthorizationValues(headerValues(headers, "Authorization")); len(values) != 0 {
		if len(values) > 1 {
			return i.conflictingIdentity("authorization", values)
		}
		if token, ok := canonicalBearerToken(values[0]); ok {
			return Identity{Hash: i.digest(token), Source: SourceAuthorization}
		}
	}
	if tokens := nonEmptyUniqueValues(headerValues(headers, "X-API-Key")); len(tokens) != 0 {
		if len(tokens) == 1 {
			return Identity{Hash: i.digest(tokens[0]), Source: SourceAPIKey}
		}
		return i.conflictingIdentity("x_api_key", tokens)
	}
	return i.Anonymous()
}

// Anonymous returns the same non-plaintext anonymous bucket for the life of
// this Identifier.
func (i *Identifier) Anonymous() Identity {
	return Identity{Hash: i.digest("cyber-abuse-guard:anonymous"), Source: SourceAnonymous}
}

func (i *Identifier) digest(value string) string {
	mac := hmac.New(sha256.New, i.key)
	_, _ = io.WriteString(mac, value)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func (i *Identifier) conflictingIdentity(kind string, values []string) Identity {
	mac := hmac.New(sha256.New, i.key)
	_, _ = io.WriteString(mac, "cyber-abuse-guard:credential-conflict:v1\x00")
	_, _ = io.WriteString(mac, kind)
	var length [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = mac.Write(length[:])
		_, _ = io.WriteString(mac, value)
	}
	return Identity{Hash: "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), Source: SourceConflict}
}

func headerValues(headers http.Header, name string) []string {
	var matched []string
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			matched = append(matched, values...)
		}
	}
	return matched
}

const canonicalBearerPrefix = "bearer\x00"

func normalizedAuthorizationValues(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > len("Bearer") && strings.EqualFold(value[:len("Bearer")], "Bearer") {
			if boundary := value[len("Bearer")]; boundary == ' ' || boundary == '\t' {
				if token := strings.TrimSpace(value[len("Bearer"):]); token != "" {
					normalized = append(normalized, canonicalBearerPrefix+token)
					continue
				}
			}
		}
		normalized = append(normalized, "other\x00"+value)
	}
	return uniqueSortedValues(normalized)
}

func canonicalBearerToken(value string) (string, bool) {
	if !strings.HasPrefix(value, canonicalBearerPrefix) {
		return "", false
	}
	token := strings.TrimPrefix(value, canonicalBearerPrefix)
	return token, token != ""
}

func nonEmptyUniqueValues(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			normalized = append(normalized, value)
		}
	}
	return uniqueSortedValues(normalized)
}

func uniqueSortedValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func readSecretFile(path string) ([]byte, error) {
	file, err := openSecretFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Stat and read through the already-open descriptor. In particular, do not
	// re-open path after validation: an attacker able to rename entries in the
	// parent directory must not be able to swap in a different file.
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("subject: inspect opened HMAC secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("subject: HMAC secret file must be a regular file")
	}
	if err := validateSecretFileOwner(info); err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("subject: HMAC secret file permissions must be 0600, got %04o", info.Mode().Perm())
	}
	if info.Size() > maximumSecretBytes {
		return nil, fmt.Errorf("subject: HMAC secret file exceeds %d bytes", maximumSecretBytes)
	}
	// The fstat size is an early rejection, not the read bound: a writable file
	// can grow after fstat, so read at most one byte beyond the configured limit.
	data, err := io.ReadAll(io.LimitReader(file, maximumSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("subject: read HMAC secret file: %w", err)
	}
	if len(data) > maximumSecretBytes {
		return nil, fmt.Errorf("subject: HMAC secret file exceeds %d bytes", maximumSecretBytes)
	}
	data = bytes.TrimRight(data, "\r\n")
	if err := validateKey(data); err != nil {
		return nil, fmt.Errorf("subject: HMAC secret file: %w", err)
	}
	return data, nil
}

func validateKey(key []byte) error {
	if len(key) < minimumHMACKeyBytes {
		return fmt.Errorf("HMAC key must contain at least %d bytes", minimumHMACKeyBytes)
	}
	if len(key) > maximumSecretBytes {
		return fmt.Errorf("HMAC key exceeds %d bytes", maximumSecretBytes)
	}
	return nil
}

func validDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F') {
			continue
		}
		return false
	}
	return true
}
