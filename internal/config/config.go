// Package config owns the validated YAML configuration model for the guard.
// It is intentionally independent from the CPA plugin lifecycle so parsing can
// happen before a live configuration is replaced.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	MaxConfigBytes                 = 64 << 10
	MaxAllowedScanBytes            = 4 << 20
	MinAllowedTextWindowBytes      = 16 << 10
	MaxAllowedTextWindowBytes      = 1 << 20
	DefaultMaxTotalTextBytes       = 8 << 20
	DefaultMaxClassificationChunks = 2048
	StreamingOverlapBudgetBytes    = 4 << 10
	MaxAllowedTotalTextBytes       = 8 << 20
	MaxAllowedClassificationChunks = 16384
	MaxAllowedJSONDepth            = 128
	MaxAllowedTextParts            = 4096
	maxYAMLLines                   = 1024
	maxYAMLLineBytes               = 8 << 10
	maxYAMLIndent                  = 64
	maxYAMLFlowDepth               = 32
	maxPriority                    = 100000
	maxSubjectMinutes              = 30 * 24 * 60
	maxSubjectScore                = 1000000
	maxSubjectEntries              = 1000000
	maxPersistedSubjects           = 10000
	maxAuditRetentionDay           = 3650
	maxAuditDBMB                   = 10240
	maxRawCaptureBytes             = 1 << 20
	maxClassifierTimeout           = 10000
	maxDataDirBytes                = 4096
)

var (
	ErrInvalidConfig  = errors.New("config: invalid configuration")
	ErrConfigTooLarge = errors.New("config: YAML exceeds size limit")
)

// Mode determines enforcement behavior.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeObserve  Mode = "observe"
	ModeAudit    Mode = "audit"
	ModeBalanced Mode = "balanced"
	ModeStrict   Mode = "strict"
)

// OpaqueMediaPolicy controls requests whose image/audio/video payload cannot be
// inspected locally. Auto is represented by the empty value and resolves from
// Mode without fetching remote URLs: strict blocks, balanced/observe/audit
// audit, and off allows.
type OpaqueMediaPolicy string

const (
	OpaqueMediaPolicyAuto  OpaqueMediaPolicy = ""
	OpaqueMediaPolicyBlock OpaqueMediaPolicy = "block"
	OpaqueMediaPolicyAudit OpaqueMediaPolicy = "audit"
	OpaqueMediaPolicyAllow OpaqueMediaPolicy = "allow"
)

// ClassifierFailMode controls the local fallback if the optional classifier is
// unavailable. v0.15 reserves only the safe deterministic-rules fallback.
type ClassifierFailMode string

const ClassifierFailRulesOnly ClassifierFailMode = "rules_only"

// Config is the direct YAML object under plugins.configs.cyber-abuse-guard.
type Config struct {
	Enabled                   bool                      `yaml:"enabled"`
	Priority                  int                       `yaml:"priority"`
	Mode                      Mode                      `yaml:"mode"`
	MaxScanBytes              int                       `yaml:"max_scan_bytes"`
	MaxTextWindowBytes        int                       `yaml:"max_text_window_bytes"`
	MaxTotalTextBytes         int                       `yaml:"max_total_text_bytes"`
	MaxClassificationChunks   int                       `yaml:"max_classification_chunks"`
	MaxJSONDepth              int                       `yaml:"max_json_depth"`
	MaxTextParts              int                       `yaml:"max_text_parts"`
	OpaqueMediaPolicy         OpaqueMediaPolicy         `yaml:"opaque_media_policy"`
	Thresholds                Thresholds                `yaml:"thresholds"`
	AllowContext              AllowContext              `yaml:"allow_context"`
	HardBlockEvenIfAuthorized HardBlockEvenIfAuthorized `yaml:"hard_block_even_if_authorized"`
	SubjectControl            SubjectControl            `yaml:"subject_control"`
	Audit                     Audit                     `yaml:"audit"`
	TrustedProxy              TrustedProxy              `yaml:"trusted_proxy"`
	Classifier                Classifier                `yaml:"classifier"`
}

type Thresholds struct {
	Audit         int `yaml:"audit"`
	BalancedBlock int `yaml:"balanced_block"`
	HardBlock     int `yaml:"hard_block"`
}

type AllowContext struct {
	CTF                   bool `yaml:"ctf"`
	Lab                   bool `yaml:"lab"`
	AuthorizedTesting     bool `yaml:"authorized_testing"`
	DefensiveAnalysis     bool `yaml:"defensive_analysis"`
	Remediation           bool `yaml:"remediation"`
	MalwareStaticAnalysis bool `yaml:"malware_static_analysis"`
}

type HardBlockEvenIfAuthorized struct {
	CredentialTheft      bool `yaml:"credential_theft"`
	PhishingDeployment   bool `yaml:"phishing_deployment"`
	RansomwareDeployment bool `yaml:"ransomware_deployment"`
	DataExfiltration     bool `yaml:"data_exfiltration"`
}

type SubjectControl struct {
	Enabled          bool `yaml:"enabled"`
	Persistence      bool `yaml:"persistence"`
	MaxSubjects      int  `yaml:"max_subjects"`
	WindowMinutes    int  `yaml:"window_minutes"`
	CooldownScore    int  `yaml:"cooldown_score"`
	ManualBlockScore int  `yaml:"manual_block_score"`
	CooldownMinutes  int  `yaml:"cooldown_minutes"`
}

type Audit struct {
	Enabled               bool       `yaml:"enabled"`
	DataDir               string     `yaml:"data_dir"`
	RetentionDays         int        `yaml:"retention_days"`
	MaxDBMB               int        `yaml:"max_db_mb"`
	LogRequestHash        bool       `yaml:"log_request_hash"`
	LogSubjectHash        bool       `yaml:"log_subject_hash"`
	LogRuleIDs            bool       `yaml:"log_rule_ids"`
	LogCategory           bool       `yaml:"log_category"`
	PersistWrapperOnly    bool       `yaml:"persist_wrapper_only"`
	LogOriginalText       bool       `yaml:"log_original_text"`
	RawCapture            RawCapture `yaml:"raw_capture"`
	BackupBeforeMigration bool       `yaml:"backup_before_migration"`
	MaxMigrationBackups   int        `yaml:"max_migration_backups"`
}

// RawCapture is an explicit, sensitive operator-review feature. It is kept
// separate from the legacy LogOriginalText switch so raw request previews can
// remain disabled by default, bounded, short-lived, and independently
// redacted. The runtime records only requests whose final action is block or
// cooldown.
type RawCapture struct {
	Enabled       bool `yaml:"enabled"`
	OnlyBlocked   bool `yaml:"only_blocked"`
	MaxBytes      int  `yaml:"max_bytes"`
	TTLHours      int  `yaml:"ttl_hours"`
	RedactSecrets bool `yaml:"redact_secrets"`
}

type TrustedProxy struct {
	Enabled bool     `yaml:"enabled"`
	Header  string   `yaml:"header"`
	CIDRs   []string `yaml:"cidrs"`
}

// Classifier is a reserved v0.15 interface configuration. This package does not
// implement the classifier transport; it only prevents unsafe endpoints from
// entering a valid configuration.
type Classifier struct {
	Enabled   bool               `yaml:"enabled"`
	Endpoint  string             `yaml:"endpoint"`
	TimeoutMS int                `yaml:"timeout_ms"`
	FailMode  ClassifierFailMode `yaml:"fail_mode"`
}

// Default returns safe startup defaults. Enforcement and cross-request subject
// state are explicit operator opt-ins after an observe-only rollout.
func Default() Config {
	return Config{
		Enabled:      true,
		Priority:     300,
		Mode:         ModeObserve,
		MaxScanBytes: 262144,
		// MaxTextWindowBytes remains zero unless the new key is explicitly
		// configured. EffectiveTextWindowBytes then migrates the legacy
		// max_scan_bytes value from a raw/text coverage cap into a bounded
		// classifier window.
		MaxTextWindowBytes:      0,
		MaxTotalTextBytes:       DefaultMaxTotalTextBytes,
		MaxClassificationChunks: 0,
		MaxJSONDepth:            32,
		MaxTextParts:            512,
		Thresholds: Thresholds{
			Audit:         35,
			BalancedBlock: 60,
			HardBlock:     80,
		},
		AllowContext: AllowContext{
			CTF:                   true,
			Lab:                   true,
			AuthorizedTesting:     true,
			DefensiveAnalysis:     true,
			Remediation:           true,
			MalwareStaticAnalysis: true,
		},
		HardBlockEvenIfAuthorized: HardBlockEvenIfAuthorized{
			CredentialTheft:      true,
			PhishingDeployment:   true,
			RansomwareDeployment: true,
			DataExfiltration:     true,
		},
		SubjectControl: SubjectControl{
			Enabled:          false,
			Persistence:      false,
			MaxSubjects:      10000,
			WindowMinutes:    60,
			CooldownScore:    150,
			ManualBlockScore: 250,
			CooldownMinutes:  30,
		},
		Audit: Audit{
			Enabled:            true,
			DataDir:            "",
			RetentionDays:      30,
			MaxDBMB:            256,
			LogRequestHash:     true,
			LogSubjectHash:     true,
			LogRuleIDs:         true,
			LogCategory:        true,
			PersistWrapperOnly: false,
			LogOriginalText:    false,
			RawCapture: RawCapture{
				Enabled:       false,
				OnlyBlocked:   true,
				MaxBytes:      8192,
				TTLHours:      72,
				RedactSecrets: true,
			},
			BackupBeforeMigration: true,
			MaxMigrationBackups:   3,
		},
		TrustedProxy: TrustedProxy{
			Enabled: false,
			Header:  "X-Forwarded-For",
			CIDRs:   []string{},
		},
		Classifier: Classifier{
			Enabled:   false,
			Endpoint:  "",
			TimeoutMS: 300,
			FailMode:  ClassifierFailRulesOnly,
		},
	}
}

// Parse strictly decodes one YAML document on top of Default and validates the
// result. Unknown fields, duplicate keys, additional documents, oversized
// input, and unsafe values are rejected before callers can swap live config.
func Parse(data []byte) (Config, error) {
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: got %d bytes, limit is %d", ErrConfigTooLarge, len(data), MaxConfigBytes)
	}
	cfg := Default()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}
	if err := preflightYAML(data); err != nil {
		return Config{}, err
	}
	keys, err := topLevelYAMLKeys(data)
	if err != nil {
		return Config{}, invalidf("decode YAML structure")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return cfg, nil
		}
		return Config{}, invalidf("decode YAML")
	}
	if keys["max_text_window_bytes"] && cfg.MaxTextWindowBytes == 0 {
		return Config{}, invalidf("max_text_window_bytes must not be zero when explicitly configured")
	}
	if keys["max_classification_chunks"] && cfg.MaxClassificationChunks == 0 {
		return Config{}, invalidf("max_classification_chunks must not be zero when explicitly configured")
	}
	if keys["max_scan_bytes"] && keys["max_text_window_bytes"] && cfg.MaxScanBytes != cfg.MaxTextWindowBytes {
		return Config{}, invalidf("max_scan_bytes and max_text_window_bytes conflict")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, invalidf("multiple YAML documents are not allowed")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, invalidf("decode trailing YAML")
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks a complete configuration without mutating it.
func Validate(cfg Config) error {
	if !cfg.Mode.valid() {
		return invalidf("mode must be one of off, observe, audit, balanced, strict")
	}
	if cfg.Priority < 0 || cfg.Priority > maxPriority {
		return invalidf("priority must be between 0 and %d", maxPriority)
	}
	if cfg.MaxScanBytes < 1 || cfg.MaxScanBytes > MaxAllowedScanBytes {
		return invalidf("max_scan_bytes must be between 1 and %d", MaxAllowedScanBytes)
	}
	if cfg.MaxTextWindowBytes < 0 || cfg.MaxTextWindowBytes > MaxAllowedTextWindowBytes {
		return invalidf("max_text_window_bytes must be omitted or between %d and %d", MinAllowedTextWindowBytes, MaxAllowedTextWindowBytes)
	}
	if cfg.MaxTextWindowBytes > 0 && cfg.MaxTextWindowBytes < MinAllowedTextWindowBytes {
		return invalidf("max_text_window_bytes must be omitted or between %d and %d", MinAllowedTextWindowBytes, MaxAllowedTextWindowBytes)
	}
	if cfg.MaxTotalTextBytes < 1 || cfg.MaxTotalTextBytes > MaxAllowedTotalTextBytes {
		return invalidf("max_total_text_bytes must be between 1 and %d", MaxAllowedTotalTextBytes)
	}
	if cfg.MaxTotalTextBytes < cfg.EffectiveTextWindowBytes() {
		return invalidf("max_total_text_bytes must be at least the effective text window size")
	}
	if cfg.MaxClassificationChunks < 0 || cfg.MaxClassificationChunks > MaxAllowedClassificationChunks {
		return invalidf("max_classification_chunks must be omitted or between 1 and %d", MaxAllowedClassificationChunks)
	}
	minimumChunks := cfg.MinimumClassificationChunks()
	if minimumChunks > MaxAllowedClassificationChunks {
		return invalidf("effective text limits require more than %d classification chunks", MaxAllowedClassificationChunks)
	}
	if cfg.MaxClassificationChunks > 0 && cfg.MaxClassificationChunks < minimumChunks {
		return invalidf("max_classification_chunks must be at least %d for the configured text limits", minimumChunks)
	}
	if cfg.MaxJSONDepth < 1 || cfg.MaxJSONDepth > MaxAllowedJSONDepth {
		return invalidf("max_json_depth must be between 1 and %d", MaxAllowedJSONDepth)
	}
	if cfg.MaxTextParts < 1 || cfg.MaxTextParts > MaxAllowedTextParts {
		return invalidf("max_text_parts must be between 1 and %d", MaxAllowedTextParts)
	}
	if !cfg.OpaqueMediaPolicy.valid() {
		return invalidf("opaque_media_policy must be one of block, audit, allow, or omitted for mode-aware defaults")
	}

	if err := validateThresholds(cfg.Thresholds); err != nil {
		return err
	}
	if err := validateSubjectControl(cfg.SubjectControl); err != nil {
		return err
	}
	if err := validateAudit(cfg.Audit); err != nil {
		return err
	}
	if cfg.SubjectControl.Persistence && !cfg.SubjectControl.Enabled {
		return invalidf("subject_control.persistence requires subject_control.enabled")
	}
	if cfg.SubjectControl.Persistence && !cfg.Audit.Enabled {
		return invalidf("subject_control.persistence requires audit.enabled because state is stored in the local SQLite database")
	}
	if cfg.SubjectControl.Persistence && cfg.SubjectControl.MaxSubjects > maxPersistedSubjects {
		return invalidf("subject_control.max_subjects must not exceed %d when persistence is enabled", maxPersistedSubjects)
	}
	if err := validateTrustedProxy(cfg.TrustedProxy); err != nil {
		return err
	}
	if err := validateClassifier(cfg.Classifier); err != nil {
		return err
	}
	return nil
}

// EffectiveTextWindowBytes returns the bounded classifier window. The legacy
// max_scan_bytes key is retained as a compatibility alias, but it no longer
// limits raw JSON traversal or total model-visible text coverage. Very small
// legacy values are clamped to a safe streaming minimum instead of producing
// an attacker-controlled explosion of tiny chunks.
func (cfg Config) EffectiveTextWindowBytes() int {
	if cfg.MaxTextWindowBytes > 0 {
		return cfg.MaxTextWindowBytes
	}
	window := cfg.MaxScanBytes
	if window < MinAllowedTextWindowBytes {
		window = MinAllowedTextWindowBytes
	}
	if window > MaxAllowedTextWindowBytes {
		window = MaxAllowedTextWindowBytes
	}
	return window
}

// TextWindowMigrationMode is a fixed, low-cardinality status value.
func (cfg Config) TextWindowMigrationMode() string {
	if cfg.MaxTextWindowBytes > 0 {
		return "explicit_max_text_window_bytes"
	}
	if cfg.MaxScanBytes < MinAllowedTextWindowBytes || cfg.MaxScanBytes > MaxAllowedTextWindowBytes {
		return "legacy_max_scan_bytes_clamped"
	}
	return "legacy_max_scan_bytes_alias"
}

// MinimumClassificationChunks keeps logical text units and internal streaming
// chunks on separate budgets. The formula leaves one bounded role-
// reconstruction batch per logical unit, one first text window per potentially
// non-empty logical unit, enough additional overlapping windows to cover the
// configured total text limit, and one final batch for an isolated user-rune
// run finalized by ScanSession.Finish. This intentionally overestimates by up
// to MaxTextParts windows, keeping the validation formula simple and safe.
func (cfg Config) MinimumClassificationChunks() int {
	window := cfg.EffectiveTextWindowBytes()
	stride := window - StreamingOverlapBudgetBytes
	if stride < 1 {
		return MaxAllowedClassificationChunks + 1
	}
	minimum := 2*cfg.MaxTextParts + (cfg.MaxTotalTextBytes+stride-1)/stride + 1
	if minimum < DefaultMaxClassificationChunks {
		minimum = DefaultMaxClassificationChunks
	}
	return minimum
}

func (cfg Config) EffectiveMaxClassificationChunks() int {
	if cfg.MaxClassificationChunks > 0 {
		return cfg.MaxClassificationChunks
	}
	return cfg.MinimumClassificationChunks()
}

// EffectiveOpaqueMediaPolicy returns the explicit policy or the conservative
// mode-aware default. It performs no I/O and never fetches media URLs.
func (cfg Config) EffectiveOpaqueMediaPolicy() OpaqueMediaPolicy {
	if cfg.OpaqueMediaPolicy != OpaqueMediaPolicyAuto {
		return cfg.OpaqueMediaPolicy
	}
	switch cfg.Mode {
	case ModeStrict:
		return OpaqueMediaPolicyBlock
	case ModeObserve, ModeAudit, ModeBalanced:
		return OpaqueMediaPolicyAudit
	default:
		return OpaqueMediaPolicyAllow
	}
}

func (policy OpaqueMediaPolicy) valid() bool {
	switch policy {
	case OpaqueMediaPolicyAuto, OpaqueMediaPolicyBlock, OpaqueMediaPolicyAudit, OpaqueMediaPolicyAllow:
		return true
	default:
		return false
	}
}

// Validate provides method syntax for callers holding a Config value.
func (cfg Config) Validate() error {
	return Validate(cfg)
}

func (m Mode) valid() bool {
	switch m {
	case ModeOff, ModeObserve, ModeAudit, ModeBalanced, ModeStrict:
		return true
	default:
		return false
	}
}

func validateThresholds(t Thresholds) error {
	for name, value := range map[string]int{
		"audit": t.Audit, "balanced_block": t.BalancedBlock, "hard_block": t.HardBlock,
	} {
		if value < 0 || value > 100 {
			return invalidf("thresholds.%s must be between 0 and 100", name)
		}
	}
	if !(t.Audit < t.BalancedBlock && t.BalancedBlock < t.HardBlock) {
		return invalidf("thresholds must satisfy audit < balanced_block < hard_block")
	}
	return nil
}

func validateSubjectControl(s SubjectControl) error {
	if s.MaxSubjects < 1 || s.MaxSubjects > maxSubjectEntries {
		return invalidf("subject_control.max_subjects must be between 1 and %d", maxSubjectEntries)
	}
	if s.WindowMinutes < 1 || s.WindowMinutes > maxSubjectMinutes {
		return invalidf("subject_control.window_minutes must be between 1 and %d", maxSubjectMinutes)
	}
	if s.CooldownMinutes < 1 || s.CooldownMinutes > maxSubjectMinutes {
		return invalidf("subject_control.cooldown_minutes must be between 1 and %d", maxSubjectMinutes)
	}
	if s.CooldownScore < 1 || s.CooldownScore > maxSubjectScore {
		return invalidf("subject_control.cooldown_score must be between 1 and %d", maxSubjectScore)
	}
	if s.ManualBlockScore < 1 || s.ManualBlockScore > maxSubjectScore {
		return invalidf("subject_control.manual_block_score must be between 1 and %d", maxSubjectScore)
	}
	if s.ManualBlockScore <= s.CooldownScore {
		return invalidf("subject_control.manual_block_score must exceed cooldown_score")
	}
	return nil
}

func validateAudit(a Audit) error {
	if a.LogOriginalText {
		return invalidf("audit.log_original_text must remain false; use the explicit bounded audit.raw_capture feature")
	}
	if a.RetentionDays < 1 || a.RetentionDays > maxAuditRetentionDay {
		return invalidf("audit.retention_days must be between 1 and %d", maxAuditRetentionDay)
	}
	if a.MaxDBMB < 1 || a.MaxDBMB > maxAuditDBMB {
		return invalidf("audit.max_db_mb must be between 1 and %d", maxAuditDBMB)
	}
	if a.RawCapture.Enabled && !a.Enabled {
		return invalidf("audit.raw_capture.enabled requires audit.enabled")
	}
	if !a.RawCapture.OnlyBlocked {
		return invalidf("audit.raw_capture.only_blocked must remain true")
	}
	if !a.RawCapture.RedactSecrets {
		return invalidf("audit.raw_capture.redact_secrets must remain true")
	}
	if a.RawCapture.MaxBytes < 1 || a.RawCapture.MaxBytes > maxRawCaptureBytes {
		return invalidf("audit.raw_capture.max_bytes must be between 1 and %d", maxRawCaptureBytes)
	}
	if a.RawCapture.TTLHours < 1 || a.RawCapture.TTLHours > maxAuditRetentionDay*24 {
		return invalidf("audit.raw_capture.ttl_hours must be between 1 and %d", maxAuditRetentionDay*24)
	}
	if a.RawCapture.Enabled && a.RawCapture.TTLHours > a.RetentionDays*24 {
		return invalidf("audit.raw_capture.ttl_hours must not exceed audit.retention_days")
	}
	if a.MaxMigrationBackups < 0 || a.MaxMigrationBackups > 10 {
		return invalidf("audit.max_migration_backups must be between 0 and 10")
	}
	if a.BackupBeforeMigration && a.MaxMigrationBackups < 1 {
		return invalidf("audit.max_migration_backups must be at least 1 when backup_before_migration is enabled")
	}
	if err := validateDataDir(a.DataDir); err != nil {
		return err
	}
	return nil
}

func validateDataDir(path string) error {
	if path == "" {
		return nil
	}
	if len(path) > maxDataDirBytes {
		return invalidf("audit.data_dir exceeds %d bytes", maxDataDirBytes)
	}
	if strings.ContainsRune(path, 0) || strings.ContainsAny(path, "\r\n") {
		return invalidf("audit.data_dir contains control characters")
	}
	if strings.Contains(path, "://") {
		return invalidf("audit.data_dir must be a filesystem path, not a URL")
	}
	for _, segment := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return invalidf("audit.data_dir must not contain parent traversal")
		}
	}
	return nil
}

func validateTrustedProxy(p TrustedProxy) error {
	if p.Enabled {
		// CPA v7.2.95 does not expose the direct peer address to ModelRouter.
		// Without that value the plugin cannot prove that a forwarded header was
		// supplied by one of the configured proxies, so enabling it would make the
		// subject bucket attacker-controlled.
		return invalidf("trusted_proxy.enabled is unsupported with CPA v7.2.95 because ModelRouter has no trusted peer address")
	}
	if p.Header != "" && !isHTTPToken(p.Header) {
		return invalidf("trusted_proxy.header must be a valid HTTP field name")
	}

	for _, raw := range p.CIDRs {
		if raw == "" || raw != strings.TrimSpace(raw) {
			return invalidf("trusted_proxy.cidrs contains an empty or whitespace-padded entry")
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return invalidf("trusted_proxy.cidrs contains an invalid CIDR")
		}
		if prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return invalidf("trusted_proxy contains a non-canonical or overly broad CIDR")
		}
		minimumBits := 32
		if prefix.Addr().Is4() {
			minimumBits = 8
		}
		if prefix.Bits() < minimumBits {
			return invalidf("trusted_proxy contains a CIDR broader than the minimum allowed prefix")
		}
	}
	return nil
}

func validateClassifier(c Classifier) error {
	if c.TimeoutMS < 1 || c.TimeoutMS > maxClassifierTimeout {
		return invalidf("classifier.timeout_ms must be between 1 and %d", maxClassifierTimeout)
	}
	if c.FailMode != ClassifierFailRulesOnly {
		return invalidf("classifier.fail_mode must be %q", ClassifierFailRulesOnly)
	}
	if c.Enabled {
		return invalidf("classifier.enabled is reserved but unsupported in this release")
	}
	if c.Endpoint == "" {
		return nil
	}

	u, err := url.Parse(c.Endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return invalidf("classifier.endpoint must be an absolute HTTP(S) URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalidf("classifier.endpoint scheme must be http or https")
	}
	if u.User != nil {
		return invalidf("classifier.endpoint must not contain user information")
	}
	if u.Fragment != "" {
		return invalidf("classifier.endpoint must not contain a fragment")
	}
	// Calling Port forces validation of malformed bracket/port combinations on
	// supported net/url versions even though the transport is not implemented.
	_ = u.Port()
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return invalidf("classifier.endpoint host must be localhost or a literal loopback/private IP")
	}
	addr = addr.Unmap()
	if !addr.IsLoopback() && !addr.IsPrivate() {
		return invalidf("classifier.endpoint must not target a public or link-local address")
	}
	return nil
}

// preflightYAML recognizes only security-relevant lexical structure. It is a
// linear pass that rejects parser-expansion features and pathological nesting
// before yaml.v3 sees attacker-controlled configuration bytes. Anchors,
// aliases, and custom tags are unnecessary for this small static schema.
func preflightYAML(data []byte) error {
	if !utf8.Valid(data) {
		return invalidf("YAML must be valid UTF-8")
	}

	lines := 1
	lineBytes := 0
	indent := 0
	flowDepth := 0
	atLineStart := true
	inComment := false
	var quote byte
	escaped := false

	for _, b := range data {
		lineBytes++
		if lineBytes > maxYAMLLineBytes {
			return invalidf("YAML line exceeds %d bytes", maxYAMLLineBytes)
		}
		if b == '\n' {
			if quote != 0 {
				return invalidf("multiline quoted YAML scalars are not allowed")
			}
			lines++
			if lines > maxYAMLLines {
				return invalidf("YAML exceeds %d lines", maxYAMLLines)
			}
			lineBytes = 0
			indent = 0
			atLineStart = true
			inComment = false
			continue
		}
		if b == '\r' {
			continue
		}
		if b == 0 || (b < 0x20 && b != '\t') || b == 0x7f {
			return invalidf("YAML contains control characters")
		}
		if inComment {
			continue
		}
		if atLineStart {
			switch b {
			case ' ':
				indent++
				if indent > maxYAMLIndent {
					return invalidf("YAML indentation exceeds %d spaces", maxYAMLIndent)
				}
				continue
			case '\t':
				return invalidf("tabs are not allowed for YAML indentation")
			default:
				atLineStart = false
			}
		}

		if quote != 0 {
			if quote == '"' && escaped {
				escaped = false
				continue
			}
			if quote == '"' && b == '\\' {
				escaped = true
				continue
			}
			if b == quote {
				quote = 0
			}
			continue
		}

		switch b {
		case '#':
			inComment = true
		case '\'', '"':
			quote = b
		case '&', '*', '!':
			return invalidf("YAML anchors, aliases, and tags are not allowed")
		case '[', '{':
			flowDepth++
			if flowDepth > maxYAMLFlowDepth {
				return invalidf("YAML flow nesting exceeds %d", maxYAMLFlowDepth)
			}
		case ']', '}':
			if flowDepth > 0 {
				flowDepth--
			}
		}
	}
	if quote != 0 {
		return invalidf("unterminated quoted YAML scalar")
	}
	return nil
}

func topLevelYAMLKeys(data []byte) (map[string]bool, error) {
	keys := make(map[string]bool)
	if len(bytes.TrimSpace(data)) == 0 {
		return keys, nil
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if len(document.Content) == 0 || document.Content[0].Kind == 0 ||
		(document.Content[0].Kind == yaml.ScalarNode && document.Content[0].Tag == "!!null") {
		return keys, nil
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("top-level YAML must be a mapping")
	}
	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := root.Content[index]
		if key.Kind != yaml.ScalarNode {
			return nil, errors.New("top-level YAML key must be a scalar")
		}
		keys[key.Value] = true
	}
	return keys, nil
}

func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}
