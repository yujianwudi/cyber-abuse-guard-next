package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

var (
	ErrClosed                     = errors.New("audit: store is closed")
	ErrQueueFull                  = errors.New("audit: async queue is full")
	ErrInvalidEvent               = errors.New("audit: invalid event")
	ErrUnavailable                = errors.New("audit: database is unavailable")
	ErrStorageBlocked             = errors.New("audit: persistent storage access is blocked")
	ErrRawCapturePurge            = errors.New("audit: raw request capture purge failed")
	ErrRawCapturePurgeUnrecovered = errors.New("audit: raw request capture purge compensation failed")
	ErrCapacityExceeded           = errors.New("audit: database capacity exceeded")
	ErrCapacityCheckFailed        = errors.New("audit: database capacity check failed")
	ErrCapacityCleanupFailed      = errors.New("audit: database capacity cleanup failed")
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
    id                 TEXT PRIMARY KEY,
    timestamp_ns       INTEGER NOT NULL,
    action             TEXT NOT NULL,
    mode               TEXT NOT NULL,
    category           TEXT NOT NULL,
    risk_score         INTEGER NOT NULL,
    rule_ids           TEXT NOT NULL,
    request_hash       TEXT NOT NULL,
    subject_hash       TEXT NOT NULL,
    model              TEXT NOT NULL,
    source_format      TEXT NOT NULL,
    stream             INTEGER NOT NULL,
    text_bytes_scanned INTEGER NOT NULL,
    classifier         TEXT NOT NULL,
    latency_us         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action_timestamp ON audit_events(action, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_category_timestamp ON audit_events(category, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject_timestamp ON audit_events(subject_hash, timestamp_ns DESC);
`

const maxWriteBatchItems = 64

const insertEventSQL = `INSERT INTO audit_events (
    id, timestamp_ns, action, mode, category, risk_score, rule_ids,
    request_hash, subject_hash, model, source_format, stream,
	text_bytes_scanned, classifier, decision, coverage, incomplete_reason,
	scanner, latency_us, decision_explanation, disposition, explanation_schema
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// Config controls SQLite durability and bounded background work.
type Config struct {
	Path                  string
	Retention             time.Duration
	MaxBytes              int64
	QueueSize             int
	BusyTimeout           time.Duration
	CleanupInterval       time.Duration
	BackupBeforeMigration bool
	MaxMigrationBackups   int
	RawCapture            RawCaptureConfig
	// RequirePersistentStorage selects the production file-open contract. The
	// operator-owned data directory must already exist, existing SQLite files
	// are validated without chmod repair, and newly created database artifacts
	// start with private modes.
	RequirePersistentStorage bool
	// StorageAccessGate is supplied by the runtime that verified the production
	// mount. It is checked both before admission and again by the writer so a
	// latched identity/permission/capacity failure blocks queued and new writes.
	// Subject restore also uses this gate because loading state from a replaced
	// volume is no safer than writing to it.
	StorageAccessGate func() error
	// StorageActivationGate is the activation-only, uncached storage probe. A
	// deferred Store invokes it after its owner has published the candidate but
	// before SQLite creates or opens any artifact. Runtime owners must not route
	// this callback through a write-hot-path cache.
	StorageActivationGate func() error
	// StoragePostOpenBind runs immediately after SQLite has opened the database
	// and established its WAL artifacts, before schema migration, TTL deletion,
	// capacity eviction, or worker startup. It binds the opened DB/WAL/SHM set to
	// the directory identity verified by the runtime owner.
	StoragePostOpenBind func() error
	// StoragePostMutationBind refreshes the same binding after trusted startup
	// migration/TTL work has created previously absent WAL/SHM artifacts, but
	// still before capacity maintenance, activation, or worker startup.
	StoragePostMutationBind func() error
	// StoragePostMaintenanceBind is the deferred-activation final identity gate.
	// Activate invokes it only after startup maintenance and capacity measurement
	// succeed, but before publishing admission or starting the worker. The
	// callback must not call Quiesce, Close, or Discard because Activate holds
	// activateMu.
	StoragePostMaintenanceBind func() error
	// StorageReadAccessGate is an independent uncached gate for sensitive reads.
	// QueryRawCapturesPage invokes it from the same checked-out connection and
	// read transaction that returns previews.
	StorageReadAccessGate func() error
	// SkipDisabledPurgeOnOpen is an internal lifecycle coordination switch.
	// Direct callers and initial plugin registration leave it false. A hot
	// reconfiguration defers destructive purge until every migration succeeds
	// and the plugin holds its exclusive runtime swap lock.
	SkipDisabledPurgeOnOpen bool
	// SkipAllStartupMutation prepares an existing current-schema Store without
	// migrations, TTL deletion, capacity eviction, disabled-capture purge, or a
	// background maintenance worker. The runtime owner must call Activate only
	// after publishing the prepared configuration.
	SkipAllStartupMutation bool
	// AllowDeferredDatabaseCreate permits a mutation-free prepared Store when
	// the database file does not exist yet. Activate performs the actual open
	// and creation after the runtime swap.
	AllowDeferredDatabaseCreate bool
	Now                         func() time.Time
	// OnError runs synchronously. While handling an Activate failure, it must not
	// call Quiesce, Close, or Discard (including Context variants) on the same
	// Store; those methods wait for Activate to release its lifecycle lock.
	OnError func(error)
}

// Query is a parameterized event filter. An empty Query selects recent events;
// for Delete it intentionally means all events.
type Query struct {
	Limit        int       `json:"limit,omitempty"`
	Offset       int       `json:"offset,omitempty"`
	Action       string    `json:"action,omitempty"`
	DecisionKind string    `json:"decision_kind,omitempty"`
	Category     string    `json:"category,omitempty"`
	SubjectHash  string    `json:"subject_hash,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Until        time.Time `json:"until,omitempty"`
}

// Status contains only operational counters and is safe for management APIs.
type Status struct {
	Healthy            bool   `json:"healthy"`
	Degraded           bool   `json:"degraded"`
	Closed             bool   `json:"closed"`
	SchemaVersion      int    `json:"schema_version"`
	LastError          string `json:"last_error,omitempty"`
	QueueDepth         int    `json:"queue_depth"`
	QueueCapacity      int    `json:"queue_capacity"`
	Enqueued           uint64 `json:"enqueued"`
	Written            uint64 `json:"written"`
	Dropped            uint64 `json:"dropped"`
	Failed             uint64 `json:"failed"`
	Rejected           uint64 `json:"rejected"`
	RawCaptureEnqueued uint64 `json:"raw_capture_enqueued"`
	RawCaptureWritten  uint64 `json:"raw_capture_written"`
	RawCaptureDropped  uint64 `json:"raw_capture_dropped"`
	RawCaptureFailed   uint64 `json:"raw_capture_failed"`
	RawCaptureRejected uint64 `json:"raw_capture_rejected"`
	// RawCaptureDeduplicated counts previews intentionally not persisted because
	// the same complete-request raw_sha256 already had a live capture in the
	// configured TTL. It does not require or expose request_hash.
	RawCaptureDeduplicated uint64 `json:"raw_capture_deduplicated"`
	// RawCaptureQueueHighWater is the maximum number of reserved queue slots
	// observed by a raw-capture attempt, including a saturated/drop attempt.
	RawCaptureQueueHighWater uint64 `json:"raw_capture_queue_high_water"`
	// Prepare latency covers attempts that reached request preview preparation
	// after admission. Rejected metadata/body preparations are included.
	RawCapturePrepareCount       uint64                `json:"raw_capture_prepare_count"`
	RawCapturePrepareTotalUS     uint64                `json:"raw_capture_prepare_total_us"`
	RawCapturePrepareLastUS      uint64                `json:"raw_capture_prepare_last_us"`
	RawCapturePrepareMaxUS       uint64                `json:"raw_capture_prepare_max_us"`
	CleanupDeleted               uint64                `json:"cleanup_deleted"`
	CurrentLiveBytes             int64                 `json:"current_live_bytes"`
	ConfiguredMaxBytes           int64                 `json:"configured_max_bytes"`
	CapacityMeasurementAvailable bool                  `json:"capacity_measurement_available"`
	OverLimit                    bool                  `json:"over_limit"`
	CapacityCleanupRuns          uint64                `json:"capacity_cleanup_runs"`
	CapacityCleanupDeleted       uint64                `json:"capacity_cleanup_deleted"`
	CapacityRejected             uint64                `json:"capacity_rejected"`
	MigrationBackups             MigrationBackupStatus `json:"migration_backups"`
}

// Stats combines persisted aggregates with the in-memory fail-open counters.
type Stats struct {
	Total          int64 `json:"total"`
	Events         int64 `json:"events"`
	UniqueRequests int64 `json:"unique_requests"`
	RepeatEvents   int64 `json:"repeat_events"`
	UnhashedEvents int64 `json:"unhashed_events"`
	// RetryWindowSeconds is the fixed Unix-epoch-aligned window used by the
	// decision/rule retry aggregates below. The compatibility request-hash
	// fields above retain their original all-time semantics.
	RetryWindowSeconds int64 `json:"retry_window_seconds"`
	// UniqueDecisionRuleWindows counts distinct request_hash + decision +
	// canonical rule-ID-set + retry-window tuples. Unhashed events are excluded.
	UniqueDecisionRuleWindows int64 `json:"unique_decision_rule_windows"`
	// WindowRepeatEvents counts hashed events after the first event in each
	// distinct decision/rule retry window.
	WindowRepeatEvents           int64            `json:"window_repeat_events"`
	ByAction                     map[string]int64 `json:"by_action"`
	ByDecisionKind               map[string]int64 `json:"by_decision_kind"`
	ByCategory                   map[string]int64 `json:"by_category"`
	Enqueued                     uint64           `json:"enqueued"`
	Written                      uint64           `json:"written"`
	Dropped                      uint64           `json:"dropped"`
	Failed                       uint64           `json:"failed"`
	Rejected                     uint64           `json:"rejected"`
	RawCaptureEnqueued           uint64           `json:"raw_capture_enqueued"`
	RawCaptureWritten            uint64           `json:"raw_capture_written"`
	RawCaptureDropped            uint64           `json:"raw_capture_dropped"`
	RawCaptureFailed             uint64           `json:"raw_capture_failed"`
	RawCaptureRejected           uint64           `json:"raw_capture_rejected"`
	RawCaptureDeduplicated       uint64           `json:"raw_capture_deduplicated"`
	RawCaptureQueueHighWater     uint64           `json:"raw_capture_queue_high_water"`
	RawCapturePrepareCount       uint64           `json:"raw_capture_prepare_count"`
	RawCapturePrepareTotalUS     uint64           `json:"raw_capture_prepare_total_us"`
	RawCapturePrepareLastUS      uint64           `json:"raw_capture_prepare_last_us"`
	RawCapturePrepareMaxUS       uint64           `json:"raw_capture_prepare_max_us"`
	CleanupDeleted               uint64           `json:"cleanup_deleted"`
	CurrentLiveBytes             int64            `json:"current_live_bytes"`
	ConfiguredMaxBytes           int64            `json:"configured_max_bytes"`
	CapacityMeasurementAvailable bool             `json:"capacity_measurement_available"`
	OverLimit                    bool             `json:"over_limit"`
	CapacityCleanupRuns          uint64           `json:"capacity_cleanup_runs"`
	CapacityCleanupDeleted       uint64           `json:"capacity_cleanup_deleted"`
	CapacityRejected             uint64           `json:"capacity_rejected"`
}

type workItem struct {
	event      *Event
	rawCapture *RawRequestCapture
	barrier    chan struct{}
}

// Store owns SQLite and a bounded nonblocking writer. Database failures affect
// only audit counters; callers can continue classification and enforcement.
type Store struct {
	cfg          Config
	db           *sql.DB
	queue        chan workItem
	queueSlots   chan struct{}
	statsSlots   chan struct{}
	done         chan struct{}
	abort        chan struct{}
	quiescedDone chan struct{}
	closedDone   chan struct{}
	workerCtx    context.Context
	cancelWork   context.CancelFunc
	wg           sync.WaitGroup

	sendMu         sync.RWMutex
	rawAdmissionMu sync.RWMutex
	maintenanceMu  sync.Mutex
	admissionMu    sync.Mutex
	admissionCount int
	admissionIdle  chan struct{}
	closed         bool
	quiesceOnce    sync.Once
	closeOnce      sync.Once
	abortOnce      sync.Once
	closeErr       error
	activateMu     sync.Mutex
	workerStarted  bool
	activated      atomic.Bool
	databaseOpen   atomic.Bool
	closedState    atomic.Bool

	degraded               atomic.Bool
	aborted                atomic.Bool
	lastErr                atomic.Value // string
	enqueued               atomic.Uint64
	written                atomic.Uint64
	dropped                atomic.Uint64
	failed                 atomic.Uint64
	rejected               atomic.Uint64
	cleaned                atomic.Uint64
	rawEnqueued            atomic.Uint64
	rawWritten             atomic.Uint64
	rawDropped             atomic.Uint64
	rawFailed              atomic.Uint64
	rawRejected            atomic.Uint64
	rawDeduplicated        atomic.Uint64
	rawQueueHighWater      atomic.Uint64
	rawPrepareCount        atomic.Uint64
	rawPrepareTotalUS      atomic.Uint64
	rawPrepareLastUS       atomic.Uint64
	rawPrepareMaxUS        atomic.Uint64
	rawCaptureWriteBlocked atomic.Bool
	currentLiveBytes       atomic.Int64
	capacityMeasured       atomic.Bool
	overLimit              atomic.Bool
	capacityCleanupRuns    atomic.Uint64
	capacityCleanupDeleted atomic.Uint64
	capacityRejected       atomic.Uint64
	schemaVersion          atomic.Int64
	migrationBackupMu      sync.Mutex
	capacityMu             sync.Mutex

	reportMu   sync.Mutex
	lastReport time.Time

	// Tests use this hook to hold the successful activation publication boundary
	// before the worker-start lifecycle decision. Production Stores leave it nil.
	activationBeforeWorkerStartHook func()

	// Tests use this per-Store hook to deterministically cross the otherwise
	// tiny boundary between preflight and a post-commit gate. Production Stores
	// leave it nil.
	rawCapturePurgeHook func(rawCapturePurgeStage) error
}

// Open initializes the store. Even when SQLite cannot be opened, it returns a
// non-nil degraded Store plus the diagnostic error so the classification path
// remains available and failures are still counted in memory.
func Open(cfg Config) (*Store, error) {
	cfg = withDefaults(cfg)
	workerCtx, cancelWork := context.WithCancel(context.Background())
	store := &Store{
		cfg:          cfg,
		queue:        make(chan workItem, cfg.QueueSize),
		queueSlots:   make(chan struct{}, cfg.QueueSize),
		statsSlots:   make(chan struct{}, statsConcurrentLimit),
		done:         make(chan struct{}),
		abort:        make(chan struct{}),
		quiescedDone: make(chan struct{}),
		closedDone:   make(chan struct{}),
		workerCtx:    workerCtx,
		cancelWork:   cancelWork,
	}
	store.admissionIdle = make(chan struct{})
	close(store.admissionIdle)
	store.lastErr.Store("")

	var db *sql.DB
	var err error
	deferDatabaseOpen := false
	if cfg.SkipAllStartupMutation && cfg.AllowDeferredDatabaseCreate {
		if strings.TrimSpace(cfg.Path) == "" {
			err = errors.New("audit: deferred database path is empty")
		} else if _, pathErr := filepath.Abs(cfg.Path); pathErr != nil {
			err = fmt.Errorf("audit: resolve deferred database path: %w", pathErr)
		} else {
			// A hot candidate is a mutation-free placeholder regardless of whether
			// the database already exists. Even a read-write Ping or journal-mode
			// inspection can create WAL/SHM sidecars or update SQLite metadata.
			deferDatabaseOpen = true
		}
	}
	if err == nil && !deferDatabaseOpen {
		db, err = openDatabase(cfg)
	}
	if err != nil {
		store.degraded.Store(true)
		store.lastErr.Store(err.Error())
	} else if db != nil {
		store.db = db
		store.databaseOpen.Store(true)
		store.schemaVersion.Store(currentSchemaVersion)
		if !cfg.SkipAllStartupMutation {
			// A disabled capture setting is also a deletion instruction. Do an
			// initial purge before the writer starts; plugin hot reconfiguration
			// performs its final gate explicitly before activating a prepared Store.
			if !cfg.RawCapture.Enabled && !cfg.SkipDisabledPurgeOnOpen {
				if _, purgeErr := store.purgeRawCaptures(context.Background()); purgeErr != nil {
					err = fmt.Errorf("%w: %w", ErrRawCapturePurge, purgeErr)
				}
			}
			if err == nil {
				_ = store.enforceCapacity(context.Background())
			}
		}
	}
	if !cfg.SkipAllStartupMutation {
		store.activated.Store(true)
		store.startWorker()
	}
	if err != nil {
		store.report(err)
	}
	return store, err
}

// New is an alias for Open for callers that prefer constructor naming.
func New(cfg Config) (*Store, error) { return Open(cfg) }

// Activate publishes the deferred startup-mutation boundary for a Store opened
// with SkipAllStartupMutation. The owner calls it only after the candidate
// runtime has become current, while caller admission is still externally
// excluded. Capacity state is measured from the post-purge database before the
// background worker starts.
func (s *Store) Activate(ctx context.Context) error {
	if s == nil {
		return ErrUnavailable
	}
	s.activateMu.Lock()
	defer s.activateMu.Unlock()
	if s.closedState.Load() {
		return ErrClosed
	}
	if s.activated.Load() {
		return nil
	}
	if err := s.checkStorageActivationAccess(); err != nil {
		return s.finishActivation(err)
	}
	openedDuringActivation := false
	if s.db == nil {
		activationCfg := s.cfg
		activationCfg.SkipAllStartupMutation = false
		activationCfg.AllowDeferredDatabaseCreate = false
		db, err := openDatabase(activationCfg)
		if err != nil {
			return s.finishActivation(err)
		}
		s.db = db
		s.databaseOpen.Store(true)
		s.schemaVersion.Store(currentSchemaVersion)
		openedDuringActivation = true
	}
	if err := s.checkStorageAccess(); err != nil {
		return s.finishActivation(err)
	}

	s.maintenanceMu.Lock()
	var activationErr error
	switch {
	case s.cfg.RawCapture.Enabled:
		// openDatabase already performs the enabled-capture TTL cleanup when
		// activation had to open the database. A candidate that opened the
		// database during prepare still needs that mutation here. In neither
		// case may an enabled capture policy fall through to the disabled purge.
		if !openedDuringActivation {
			cutoff := s.cfg.Now().UTC().Add(-s.cfg.RawCapture.TTL).UnixNano()
			if _, err := s.db.ExecContext(ctx, "DELETE FROM raw_request_captures WHERE timestamp_ns < ?", cutoff); err != nil {
				activationErr = fmt.Errorf("audit: deferred startup raw capture TTL cleanup: %w", err)
			}
		}
	case !s.cfg.SkipDisabledPurgeOnOpen:
		if _, err := s.purgeRawCapturesLocked(ctx); err != nil {
			activationErr = fmt.Errorf("%w: %w", ErrRawCapturePurge, err)
		}
	}
	if activationErr == nil {
		activationErr = s.enforceCapacityMaintenanceLocked(ctx)
	}
	s.maintenanceMu.Unlock()
	if activationErr == nil && s.cfg.StoragePostMaintenanceBind != nil {
		if err := s.cfg.StoragePostMaintenanceBind(); err != nil {
			activationErr = fmt.Errorf("%w: bind SQLite storage identity after activation maintenance: %v", ErrStorageBlocked, err)
		}
	}

	return s.finishActivation(activationErr)
}

func (s *Store) finishActivation(activationErr error) error {
	if activationErr != nil {
		return s.failActivation(activationErr)
	}
	s.activated.Store(true)
	if hook := s.activationBeforeWorkerStartHook; hook != nil {
		hook()
	}
	// CloseContext publishes the terminal state under sendMu before waiting for
	// workers. Hold that same lock across the final check and wg.Add so close
	// either wins without a worker or waits for the worker started here.
	s.sendMu.Lock()
	if s.closedState.Load() {
		s.activated.Store(false)
		s.sendMu.Unlock()
		return s.failActivation(ErrClosed)
	}
	s.startWorker()
	s.sendMu.Unlock()
	return nil
}

func (s *Store) failActivation(activationErr error) error {
	// A deferred runtime may publish admission and its bounded queue consumer only
	// after every activation gate succeeds. Until a successful capacity
	// measurement and final storage bind exist, accepting additional evidence
	// would make the configured hard limit or storage identity unknowable. Latch
	// the capacity admission gate closed while preserving a more specific
	// activation error for Status and diagnostics.
	if !s.overLimit.Load() {
		s.capacityMu.Lock()
		s.capacityFailure(ErrCapacityCheckFailed, false)
		s.capacityMu.Unlock()
	}
	s.degraded.Store(true)
	s.lastErr.Store(activationErr.Error())
	s.report(activationErr)
	// No queue work can have been admitted before activation. Keeping the Store
	// unactivated is therefore the strongest bounded failure mode: raw reads and
	// writes both return a storage block and no worker can mutate a database whose
	// post-open identity or migration was rejected.
	return activationErr
}

func (s *Store) startWorker() {
	if s.workerStarted {
		return
	}
	s.workerStarted = true
	s.wg.Add(1)
	go s.run()
}

// DatabaseAvailable reports whether a prepared Store has already opened the
// SQLite database. Runtime owners use it only to defer post-open identity
// binding until an activation-created database exists.
func (s *Store) DatabaseAvailable() bool {
	return s != nil && s.databaseOpen.Load()
}

// IsActive reports whether this Store can currently own a hot-reconfiguration
// database. A non-nil pointer or an opened database alone is insufficient: an
// activation failure can leave DB/WAL/SHM handles open while admission remains
// permanently disabled. The predicate serializes with Activate and the close
// flag so runtime owners can distinguish that recovery state from a live Store.
func (s *Store) IsActive() bool {
	if s == nil {
		return false
	}
	return s.databaseOpen.Load() && s.activated.Load() && !s.closedState.Load()
}

func withDefaults(cfg Config) Config {
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 256 << 20
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.BusyTimeout <= 0 {
		cfg.BusyTimeout = 2500 * time.Millisecond
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = time.Hour
	}
	if cfg.MaxMigrationBackups <= 0 {
		cfg.MaxMigrationBackups = 3
	}
	if cfg.RawCapture.MaxBytes <= 0 {
		cfg.RawCapture.MaxBytes = defaultRawCaptureBytes
	} else if cfg.RawCapture.MaxBytes > maxRawCaptureBytes {
		cfg.RawCapture.MaxBytes = maxRawCaptureBytes
	}
	if cfg.RawCapture.TTL <= 0 {
		cfg.RawCapture.TTL = 72 * time.Hour
	}
	// These switches are immutable safety invariants for direct audit package
	// callers as well as validated YAML callers.
	cfg.RawCapture.OnlyBlocked = true
	cfg.RawCapture.RedactSecrets = true
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return cfg
}

func openDatabase(cfg Config) (*sql.DB, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("audit: database path is empty")
	}
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve database path: %w", err)
	}
	// A mutation-free candidate must neither create a missing directory nor
	// defer file-mode rejection until after SQLite has opened the path. Passing
	// createDirectory=false makes prepareSQLitePath enforce the regular-file and
	// private-mode contract for DB/WAL/SHM before any driver operation.
	createDirectory := !cfg.RequirePersistentStorage && !cfg.SkipAllStartupMutation
	if err := prepareSQLitePath(absPath, createDirectory); err != nil {
		return nil, err
	}
	if cfg.SkipAllStartupMutation {
		if _, err := os.Lstat(absPath); err != nil {
			return nil, fmt.Errorf("audit: deferred-mutation candidate requires an existing database: %w", err)
		}
	} else {
		// Pre-create with a private mode for both production and development. This
		// also gives the post-open identity binder a stable database object instead
		// of relying on process umask while SQLite creates it lazily.
		if err := createSQLiteDatabaseFileIfMissing(absPath, cfg.RequirePersistentStorage); err != nil {
			return nil, err
		}
	}

	parameters := url.Values{}
	parameters.Set("_busy_timeout", strconv.FormatInt(cfg.BusyTimeout.Milliseconds(), 10))
	if !cfg.SkipAllStartupMutation {
		parameters.Set("_journal_mode", "WAL")
	}
	parameters.Set("_synchronous", "NORMAL")
	parameters.Set("_foreign_keys", "on")
	// A database can still contain captures written while the feature was
	// enabled under an earlier configuration. Keep secure deletion active even
	// after capture is disabled so TTL, retention, cascade, and manual deletes
	// do not silently fall back to leaving sensitive cells in freelist pages.
	parameters.Set("_secure_delete", "true")
	// The driver opens by pathname and does not expose a project-controlled
	// fd-relative VFS/openat2 handoff. The plugin layer therefore validates
	// owner/permissions and opened-object identities before and after Open and
	// on readiness reads. That narrows, but cannot eliminate, a hostile same-UID
	// rename race; deployment must keep the whole path outside that trust domain.
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absPath), RawQuery: parameters.Encode()}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open SQLite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: connect SQLite: %w", err)
	}
	if cfg.StoragePostOpenBind != nil {
		if err := cfg.StoragePostOpenBind(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%w: bind opened SQLite storage identity: %v", ErrStorageBlocked, err)
		}
	}
	if cfg.SkipAllStartupMutation {
		var journalMode string
		if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit: inspect prepared candidate journal mode: %w", err)
		}
		if !strings.EqualFold(journalMode, "wal") {
			db.Close()
			return nil, fmt.Errorf("audit: prepared candidate journal mode is %q, want WAL", journalMode)
		}
		version, err := detectSchemaVersion(db)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("audit: detect prepared candidate schema version: %w", err)
		}
		if version != currentSchemaVersion {
			db.Close()
			return nil, fmt.Errorf("audit: prepared candidate schema version is %d, want current version %d", version, currentSchemaVersion)
		}
		if err := validateSchemaContract(db, currentSchemaVersion); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit: prepared candidate schema contract is invalid: %w", err)
		}
	} else {
		if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit: configure auto_vacuum: %w", err)
		}
		if err := migrateDatabase(db, cfg, absPath); err != nil {
			db.Close()
			return nil, err
		}
		if cfg.RawCapture.Enabled {
			cutoff := cfg.Now().UTC().Add(-cfg.RawCapture.TTL).UnixNano()
			if _, err := db.Exec("DELETE FROM raw_request_captures WHERE timestamp_ns < ?", cutoff); err != nil {
				db.Close()
				return nil, fmt.Errorf("audit: startup raw capture TTL cleanup: %w", err)
			}
		}
	}
	if !cfg.SkipAllStartupMutation && cfg.StoragePostMutationBind != nil {
		if err := cfg.StoragePostMutationBind(); err != nil {
			db.Close()
			return nil, fmt.Errorf("%w: bind SQLite storage identity after startup mutation: %v", ErrStorageBlocked, err)
		}
	}
	if err := verifySQLiteQuickCheck(db); err != nil {
		db.Close()
		return nil, err
	}
	repairPermissions := !cfg.RequirePersistentStorage && !cfg.SkipAllStartupMutation
	if err := secureSQLiteFiles(absPath, repairPermissions); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func verifySQLiteQuickCheck(db *sql.DB) error {
	if db == nil {
		return errors.New("audit: SQLite quick_check requires an open database")
	}
	var result string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("audit: SQLite quick_check failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("audit: SQLite quick_check returned %q, want exactly ok", result)
	}
	return nil
}

// Record performs a bounded, nonblocking enqueue. False means the audit event
// was rejected or dropped; it never means classification should fail.
func (s *Store) Record(event Event) bool { return s.Enqueue(event) == nil }

// Enqueue is the diagnostic form of Record.
func (s *Store) Enqueue(event Event) error {
	if s == nil || !s.activated.Load() {
		return ErrUnavailable
	}
	if err := s.rejectCapacityAdmission(1, 0); err != nil {
		return err
	}
	if err := s.checkStorageAccess(); err != nil {
		s.rejected.Add(1)
		return err
	}
	prepared, err := prepareEvent(event, s.cfg.Now())
	if err != nil {
		s.rejected.Add(1)
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := s.reserveAdmission(); err != nil {
		if errors.Is(err, ErrQueueFull) {
			s.dropped.Add(1)
		}
		return err
	}
	s.enqueued.Add(1)
	s.publishAdmission(workItem{event: &prepared})
	return nil
}

// reserveAdmission claims one bounded queue position before any expensive
// request-derived preparation. The admission generation makes the reservation
// visible to Flush and Close even before its work item enters the channel.
func (s *Store) reserveAdmission() error {
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if !s.activated.Load() {
		return ErrUnavailable
	}
	select {
	case s.queueSlots <- struct{}{}:
		s.admissionMu.Lock()
		if s.admissionCount == 0 {
			s.admissionIdle = make(chan struct{})
		}
		s.admissionCount++
		s.admissionMu.Unlock()
		return nil
	default:
		return ErrQueueFull
	}
}

func (s *Store) publishAdmission(item workItem) {
	// Every publisher owns a queueSlots token, so this send cannot exceed the
	// channel capacity even when other publishers are still preparing work.
	s.queue <- item
	s.finishAdmission()
}

func (s *Store) cancelAdmission() {
	<-s.queueSlots
	s.finishAdmission()
}

func (s *Store) releaseQueueSlot() {
	<-s.queueSlots
}

func (s *Store) waitAdmissions(ctx context.Context) error {
	s.admissionMu.Lock()
	if s.admissionCount == 0 {
		s.admissionMu.Unlock()
		return nil
	}
	idle := s.admissionIdle
	s.admissionMu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) finishAdmission() {
	s.admissionMu.Lock()
	s.admissionCount--
	if s.admissionCount < 0 {
		s.admissionMu.Unlock()
		panic("audit: admission counter became negative")
	}
	if s.admissionCount == 0 {
		close(s.admissionIdle)
	}
	s.admissionMu.Unlock()
}

// Flush waits until every event enqueued before the barrier has been attempted.
// Individual write errors remain fail-open and are reflected by Status/Stats.
func (s *Store) Flush(ctx context.Context) error {
	if s == nil {
		return ErrUnavailable
	}
	// Once close has published its terminal lifecycle state, it takes
	// precedence over an earlier activation failure. This keeps Flush stable
	// while Close waits for an in-flight Activate to release activateMu.
	if s.closedState.Load() {
		return ErrClosed
	}
	if !s.activated.Load() {
		return ErrUnavailable
	}
	barrier := make(chan struct{})
	s.sendMu.Lock()
	if s.closed {
		s.sendMu.Unlock()
		return ErrClosed
	}
	// Holding the exclusive lifecycle lock prevents new admissions while all
	// earlier reservations finish preparation and publish their work items.
	if err := s.waitAdmissions(ctx); err != nil {
		s.sendMu.Unlock()
		return err
	}
	select {
	case s.queueSlots <- struct{}{}:
	case <-ctx.Done():
		s.sendMu.Unlock()
		return ctx.Err()
	}
	s.queue <- workItem{barrier: barrier}
	s.sendMu.Unlock()
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		// Once quiesce publishes done, do not let a simultaneously ready ticker
		// start a new maintenance mutation. A tick already in progress finishes
		// before this loop returns; accepted queue work is then drained below.
		select {
		case <-s.done:
			s.drainQueuedOnStop()
			return
		default:
		}
		select {
		case item := <-s.queue:
			s.releaseQueueSlot()
			s.handleBatch(s.collectWriteBatch(item))
		case <-ticker.C:
			if err := s.cleanup(s.workerCtx); err != nil && !errors.Is(err, context.Canceled) {
				s.degraded.Store(true)
				s.report(err)
			}
		case <-s.done:
			s.drainQueuedOnStop()
			return
		}
	}
}

func (s *Store) drainQueuedOnStop() {
	for {
		if s.aborted.Load() {
			s.dropQueued()
			return
		}
		select {
		case <-s.abort:
			s.dropQueued()
			return
		case item := <-s.queue:
			s.releaseQueueSlot()
			s.handleBatch(s.collectWriteBatch(item))
		default:
			return
		}
	}
}

func (s *Store) collectWriteBatch(first workItem) []workItem {
	batch := make([]workItem, 0, maxWriteBatchItems)
	batch = append(batch, first)
	if first.barrier != nil {
		return batch
	}
	for len(batch) < maxWriteBatchItems {
		select {
		case item := <-s.queue:
			s.releaseQueueSlot()
			batch = append(batch, item)
			if item.barrier != nil {
				return batch
			}
		default:
			return batch
		}
	}
	return batch
}

func (s *Store) handleBatch(batch []workItem) {
	if len(batch) == 0 {
		return
	}
	barrier := batch[len(batch)-1].barrier
	dataItems := batch
	if barrier != nil {
		dataItems = batch[:len(batch)-1]
	}

	anySuccess := false
	hadFailure := false
	for index := 0; index < len(dataItems); index++ {
		item := dataItems[index]
		if item.event == nil && item.rawCapture == nil {
			continue
		}
		if s.overLimit.Load() {
			hadFailure = true
			s.rejectQueuedCapacityWork(item)
			continue
		}
		storageErr := s.checkStorageAccess()
		if storageErr != nil {
			hadFailure = true
			if item.event != nil {
				s.finishWork(workItem{event: item.event}, storageErr)
			}
			if item.rawCapture != nil {
				s.finishWork(workItem{rawCapture: item.rawCapture}, storageErr)
			}
			continue
		}
		if s.db == nil {
			hadFailure = true
			if item.event != nil {
				s.failed.Add(1)
			}
			if item.rawCapture != nil {
				s.failed.Add(1)
				s.rawFailed.Add(1)
			}
			// Open already retained and reported the concrete database failure.
			// Do not replace that actionable cause (for example, an unsafe symlink)
			// with the generic ErrUnavailable on every fail-open queue attempt.
			s.degraded.Store(true)
			continue
		}
		if item.event != nil && item.rawCapture != nil {
			eventItem := workItem{event: item.event}
			captureItem := workItem{rawCapture: item.rawCapture}
			eventErr, captureErr := s.writeEventCapturePair(eventItem, captureItem)
			eventWritten := s.finishWork(eventItem, eventErr)
			captureWritten := s.finishWork(captureItem, captureErr)
			anySuccess = anySuccess || eventWritten || captureWritten
			hadFailure = hadFailure || eventErr != nil || captureErr != nil
			continue
		}
		writeErr := s.writeWork(s.db, item)
		anySuccess = s.finishWork(item, writeErr) || anySuccess
		hadFailure = hadFailure || writeErr != nil
	}

	// SQLite sidecars are secured once per drained batch instead of once per
	// row. Sparse traffic retains the previous check-after-write behavior, while
	// bursts avoid repeated Lstat/Chmod calls for every event/capture pair.
	if anySuccess {
		if err := secureSQLiteFiles(s.cfg.Path, !s.cfg.RequirePersistentStorage); err != nil {
			hadFailure = true
			s.degraded.Store(true)
			s.lastErr.Store(err.Error())
			s.report(err)
		}
		if err := s.enforceCapacity(s.workerCtx); err != nil {
			hadFailure = true
		}
	}
	if anySuccess && !hadFailure && !s.overLimit.Load() && !s.rawCaptureWriteBlocked.Load() {
		s.degraded.Store(false)
		s.lastErr.Store("")
	}
	if barrier != nil {
		close(barrier)
	}
}

func (s *Store) checkStorageAccess() error {
	if s == nil {
		return ErrUnavailable
	}
	if s.cfg.StorageAccessGate == nil {
		return nil
	}
	if err := s.cfg.StorageAccessGate(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageBlocked, err)
	}
	return nil
}

func (s *Store) checkStorageActivationAccess() error {
	if s == nil {
		return ErrUnavailable
	}
	gate := s.cfg.StorageActivationGate
	if gate == nil {
		gate = s.cfg.StorageAccessGate
	}
	if gate == nil {
		return nil
	}
	if err := gate(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageBlocked, err)
	}
	return nil
}

func (s *Store) checkSensitiveReadStorageAccess() error {
	if s == nil {
		return ErrStorageBlocked
	}
	gate := s.cfg.StorageReadAccessGate
	if gate == nil {
		gate = s.cfg.StorageAccessGate
	}
	if gate == nil {
		return nil
	}
	if err := gate(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageBlocked, err)
	}
	return nil
}

func (s *Store) rejectCapacityAdmission(logicalRecords, rawCaptures uint64) error {
	if s == nil || !s.overLimit.Load() {
		return nil
	}
	s.rejected.Add(logicalRecords)
	if rawCaptures != 0 {
		s.rawRejected.Add(rawCaptures)
	}
	s.capacityRejected.Add(logicalRecords)
	return ErrCapacityExceeded
}

func (s *Store) rejectQueuedCapacityWork(item workItem) {
	logicalRecords := uint64(0)
	if item.event != nil {
		logicalRecords++
		s.failed.Add(1)
	}
	if item.rawCapture != nil {
		logicalRecords++
		s.failed.Add(1)
		s.rawFailed.Add(1)
	}
	if logicalRecords != 0 {
		s.capacityRejected.Add(logicalRecords)
	}
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *Store) writeWork(execer contextExecer, item workItem) error {
	if item.rawCapture != nil {
		if s.rawCaptureWriteBlocked.Load() {
			return ErrRawCapturePurgeUnrecovered
		}
		if err := validateRawRequestCapture(*item.rawCapture); err != nil {
			return err
		}
		if item.rawCapture.RawSHA256 == "" {
			return errors.New("audit: new raw capture requires raw_sha256")
		}
		truncated := 0
		if item.rawCapture.Truncated {
			truncated = 1
		}
		redacted := 0
		if item.rawCapture.Redacted {
			redacted = 1
		}
		if item.rawCapture.RawSHA256 != "" {
			cutoff := item.rawCapture.Timestamp.Add(-s.cfg.RawCapture.TTL).UnixNano()
			if _, err := execer.ExecContext(s.workerCtx,
				"DELETE FROM raw_request_captures WHERE raw_sha256 = ? AND timestamp_ns <= ?",
				item.rawCapture.RawSHA256, cutoff); err != nil {
				return err
			}
		}
		result, err := execer.ExecContext(s.workerCtx, insertRawCaptureSQL,
			item.rawCapture.ID, item.rawCapture.EventID, item.rawCapture.Timestamp.UnixNano(),
			item.rawCapture.RequestHash, item.rawCapture.SubjectHash, item.rawCapture.Action,
			item.rawCapture.Decision, truncated, redacted, item.rawCapture.RawPreview,
			item.rawCapture.RawSHA256, item.rawCapture.RedactionPatternHits,
			item.rawCapture.RedactionVersion, item.rawCapture.DecisionKind,
			item.rawCapture.ExplanationSchema,
		)
		if err == nil {
			written, rowsErr := result.RowsAffected()
			if rowsErr != nil {
				return rowsErr
			}
			item.rawCapture.deduplicated = written == 0
		}
		return err
	}
	if item.event == nil {
		return nil
	}
	rules, err := json.Marshal(item.event.RuleIDs)
	if err == nil {
		explanation, explanationErr := marshalDecisionExplanationForSchema(
			item.event.DecisionExplanation,
			item.event.ExplanationSchema,
		)
		if explanationErr != nil {
			return explanationErr
		}
		stream := 0
		if item.event.Stream {
			stream = 1
		}
		_, err = execer.ExecContext(s.workerCtx, insertEventSQL,
			item.event.ID, item.event.Timestamp.UnixNano(), item.event.Action,
			item.event.Mode, item.event.Category, item.event.RiskScore, string(rules),
			item.event.RequestHash, item.event.SubjectHash, item.event.Model,
			item.event.SourceFormat, stream, item.event.TextBytesScanned,
			item.event.Classifier, item.event.DecisionKind, item.event.Coverage,
			item.event.IncompleteReason, item.event.Scanner, item.event.LatencyUS,
			explanation, item.event.Decision, item.event.ExplanationSchema,
		)
	}
	return err
}

// writeEventCapturePair persists one composite queue item in a SQLite
// transaction. The audit event remains the durable priority: if
// capture insertion fails, the event is still committed and the dedicated raw
// failure counter identifies the missing review preview.
func (s *Store) writeEventCapturePair(eventItem, captureItem workItem) (eventErr, captureErr error) {
	tx, err := s.db.BeginTx(s.workerCtx, nil)
	if err != nil {
		return err, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := s.writeWork(tx, eventItem); err != nil {
		return err, fmt.Errorf("audit: raw capture skipped after event write failure: %w", err)
	}
	if err := s.writeWork(tx, captureItem); err != nil {
		if commitErr := tx.Commit(); commitErr != nil {
			committed = true
			return commitErr, errors.Join(err, commitErr)
		}
		committed = true
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		committed = true
		return err, err
	}
	committed = true
	return nil, nil
}

func (s *Store) finishWork(item workItem, err error) bool {
	if err != nil {
		s.failed.Add(1)
		if item.rawCapture != nil {
			s.rawFailed.Add(1)
		}
		s.degraded.Store(true)
		s.lastErr.Store(err.Error())
		s.report(fmt.Errorf("audit: async SQLite write failed: %w", err))
		return false
	}
	if item.rawCapture != nil && item.rawCapture.deduplicated {
		s.rawDeduplicated.Add(1)
		return false
	}
	s.written.Add(1)
	if item.rawCapture != nil {
		s.rawWritten.Add(1)
	}
	return true
}

// Status returns an operational snapshot. Counters remain lock-free; the
// configured capacity shares the capacity gate lock, and the bounded
// migration-backup inventory is serialized with explicit cleanup so a
// management response never reports a transient hidden-backup state.
func (s *Store) Status() Status {
	if s == nil {
		return Status{Degraded: true, LastError: ErrUnavailable.Error()}
	}
	s.sendMu.RLock()
	closed := s.closed
	s.sendMu.RUnlock()
	lastError, _ := s.lastErr.Load().(string)
	s.migrationBackupMu.Lock()
	migrationBackups, backupErr := InspectMigrationBackups(s.cfg.Path)
	s.migrationBackupMu.Unlock()
	s.capacityMu.Lock()
	configuredMaxBytes := s.cfg.MaxBytes
	s.capacityMu.Unlock()
	rawCaptureWriteBlocked := s.rawCaptureWriteBlocked.Load()
	activated := s.activated.Load()
	degraded := s.degraded.Load() || backupErr != nil || rawCaptureWriteBlocked || !activated
	if backupErr != nil && lastError == "" {
		lastError = MigrationBackupInventoryWarning
	} else if rawCaptureWriteBlocked && lastError == "" {
		lastError = ErrRawCapturePurgeUnrecovered.Error()
	}
	return Status{
		Healthy:                      !degraded && !closed && activated && s.databaseOpen.Load(),
		Degraded:                     degraded,
		Closed:                       closed,
		SchemaVersion:                int(s.schemaVersion.Load()),
		LastError:                    lastError,
		QueueDepth:                   len(s.queueSlots),
		QueueCapacity:                cap(s.queueSlots),
		Enqueued:                     s.enqueued.Load(),
		Written:                      s.written.Load(),
		Dropped:                      s.dropped.Load(),
		Failed:                       s.failed.Load(),
		Rejected:                     s.rejected.Load(),
		RawCaptureEnqueued:           s.rawEnqueued.Load(),
		RawCaptureWritten:            s.rawWritten.Load(),
		RawCaptureDropped:            s.rawDropped.Load(),
		RawCaptureFailed:             s.rawFailed.Load(),
		RawCaptureRejected:           s.rawRejected.Load(),
		RawCaptureDeduplicated:       s.rawDeduplicated.Load(),
		RawCaptureQueueHighWater:     s.rawQueueHighWater.Load(),
		RawCapturePrepareCount:       s.rawPrepareCount.Load(),
		RawCapturePrepareTotalUS:     s.rawPrepareTotalUS.Load(),
		RawCapturePrepareLastUS:      s.rawPrepareLastUS.Load(),
		RawCapturePrepareMaxUS:       s.rawPrepareMaxUS.Load(),
		CleanupDeleted:               s.cleaned.Load(),
		CurrentLiveBytes:             s.currentLiveBytes.Load(),
		ConfiguredMaxBytes:           configuredMaxBytes,
		CapacityMeasurementAvailable: s.capacityMeasured.Load(),
		OverLimit:                    s.overLimit.Load(),
		CapacityCleanupRuns:          s.capacityCleanupRuns.Load(),
		CapacityCleanupDeleted:       s.capacityCleanupDeleted.Load(),
		CapacityRejected:             s.capacityRejected.Load(),
		MigrationBackups:             migrationBackups,
	}
}

// SetErrorHandler replaces the optional rate-limited diagnostic callback.
// Runtime shutdown clears it before a potentially asynchronous close so no
// new host callback is started by the closing store. Handlers have the same
// reentrancy restrictions as Config.OnError.
func (s *Store) SetErrorHandler(handler func(error)) {
	if s == nil {
		return
	}
	s.reportMu.Lock()
	s.cfg.OnError = handler
	s.reportMu.Unlock()
}

// startQuiesce publishes the terminal admission state exactly once and drains
// every reservation accepted before that boundary. The worker exits only after
// its queue and maintenance loop are both stopped. SQLite deliberately remains
// open: the runtime owner must perform its final uncached storage verification
// before choosing CloseContext (checkpoint) or DiscardContext (no checkpoint).
func (s *Store) startQuiesce() {
	if s == nil {
		return
	}
	s.quiesceOnce.Do(func() {
		s.sendMu.Lock()
		s.closed = true
		s.closedState.Store(true)
		s.sendMu.Unlock()
		go func() {
			// Reservations begun before closed=true may still be redacting or
			// validating request content. Wait until every one has either published
			// or canceled before telling the writer that no more work can arrive.
			_ = s.waitAdmissions(context.Background())
			close(s.done)
			s.wg.Wait()
			// The worker owns all uses of workerCtx. Cancel only after wg confirms
			// that queued writes and an in-flight maintenance tick have finished.
			s.cancelWork()
			// Activate may have passed its initial closed-state check before this
			// quiesce began. Wait for its startup mutation and final publication
			// boundary so a successful return is a truly mutation-free storage
			// recheck surface. sendMu is not held, preserving the lifecycle lock
			// order used by finishActivation.
			s.activateMu.Lock()
			s.activateMu.Unlock()
			close(s.quiescedDone)
		}()
	})
}

// QuiesceContext atomically stops new admission and waits for every previously
// accepted item plus any in-flight background maintenance tick to finish. It
// never checkpoints or closes SQLite. A caller deadline only bounds the wait; the
// idempotent background drain continues and a later call may resume waiting.
func (s *Store) QuiesceContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.startQuiesce()
	select {
	case <-s.quiescedDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Quiesce is the unbounded form of QuiesceContext.
func (s *Store) Quiesce() error {
	return s.QuiesceContext(context.Background())
}

// startClose linearizes the finalization mode through closeOnce. If Close and
// Discard race, the first terminal call decides whether the already-quiescing
// Store may checkpoint; every caller then observes the same close result.
func (s *Store) startClose(checkpoint bool) {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if !checkpoint && !s.closedState.Load() {
			// A direct Discard that wins the terminal race preserves the historic
			// no-more-queued-work boundary. When Quiesce already won admission
			// closure, preserve its accepted-work drain instead.
			s.abortOnce.Do(func() {
				s.aborted.Store(true)
				close(s.abort)
				s.cancelWork()
			})
		}
		s.startQuiesce()
		go func() {
			<-s.quiescedDone
			// No sendMu is held while acquiring activateMu. This serializes the
			// db pointer with Activate without introducing an activateMu/sendMu
			// nesting order in either direction.
			s.activateMu.Lock()
			if s.db != nil {
				var checkpointErr error
				if checkpoint && !s.aborted.Load() && s.activated.Load() {
					checkpointErr = checkpointWAL(s.db)
					if checkpointErr != nil {
						s.degraded.Store(true)
						s.lastErr.Store(checkpointErr.Error())
					}
				}
				s.closeErr = errors.Join(checkpointErr, s.db.Close())
				s.databaseOpen.Store(false)
			}
			s.activateMu.Unlock()
			close(s.closedDone)
		}()
	})
}

// CloseContext starts an idempotent two-phase background finalizer and waits
// only until the supplied context expires. The quiesce phase drains accepted
// work and stops maintenance before the final checkpoint and database close.
func (s *Store) CloseContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.startClose(true)
	return s.waitClosed(ctx)
}

func (s *Store) waitClosed(ctx context.Context) error {
	select {
	case <-s.closedDone:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DiscardContext closes the Store without a final SQLite checkpoint. Before an
// explicit quiesce it aborts queued work immediately; after quiesce has begun it
// preserves that phase's accepted-work drain while suppressing only the final
// checkpoint. Runtime owners use it after a verified storage failure, when a
// normal close-time WAL checkpoint would violate the latched no-write boundary.
func (s *Store) DiscardContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.startClose(false)
	return s.waitClosed(ctx)
}

// Discard is the unbounded form of DiscardContext.
func (s *Store) Discard() error {
	return s.DiscardContext(context.Background())
}

func checkpointWAL(db *sql.DB) error {
	if db == nil {
		return errors.New("audit: WAL checkpoint requires an open database")
	}
	var busy, logFrames, checkpointedFrames int64
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		// A reader may keep WAL frames pinned after every writer has drained. The
		// frames are already durable and SQLite will recover/checkpoint them on a
		// later open, so SQLITE_BUSY alone is not a close failure.
		if isSQLiteBusy(err) {
			return nil
		}
		return fmt.Errorf("audit: WAL checkpoint query failed: %w", err)
	}
	if busy == 1 {
		return nil
	}
	if busy != 0 {
		return fmt.Errorf("audit: WAL checkpoint remained busy (busy=%d log=%d checkpointed=%d)", busy, logFrames, checkpointedFrames)
	}
	if logFrames < 0 || checkpointedFrames < 0 || checkpointedFrames != logFrames {
		return fmt.Errorf("audit: WAL checkpoint result is inconsistent (busy=%d log=%d checkpointed=%d)", busy, logFrames, checkpointedFrames)
	}
	return nil
}

func isSQLiteBusy(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrBusy
}

func sqliteConnectionAutoCommit(conn *sql.Conn) (bool, error) {
	if conn == nil {
		return false, errors.New("audit: inspect autocommit on nil SQLite connection")
	}
	var autoCommit bool
	err := conn.Raw(func(driverConn any) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("audit: unexpected SQLite connection driver %T", driverConn)
		}
		autoCommit = sqliteConn.AutoCommit()
		return nil
	})
	return autoCommit, err
}

func discardSQLiteConnection(conn *sql.Conn) {
	if conn == nil {
		return
	}
	// ErrBadConn prevents a connection with an unresolved transaction from
	// returning to the pool. database/sql closes the underlying SQLite handle,
	// which rolls back any uncommitted transaction.
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}

// Close drains the queue without a deadline. Runtime owners that have a
// shutdown budget should call CloseContext instead.
func (s *Store) Close() error {
	return s.CloseContext(context.Background())
}

func (s *Store) report(err error) {
	if err == nil {
		return
	}
	s.lastErr.Store(err.Error())
	now := s.cfg.Now()
	s.reportMu.Lock()
	handler := s.cfg.OnError
	if handler == nil {
		s.reportMu.Unlock()
		return
	}
	if !s.lastReport.IsZero() && now.Sub(s.lastReport) < time.Minute {
		s.reportMu.Unlock()
		return
	}
	s.lastReport = now
	s.reportMu.Unlock()
	func() {
		defer func() { _ = recover() }()
		handler(err)
	}()
}

func (s *Store) dropQueued() {
	for {
		select {
		case item := <-s.queue:
			s.releaseQueueSlot()
			if item.event != nil {
				s.dropped.Add(1)
			}
			if item.rawCapture != nil {
				s.dropped.Add(1)
				s.rawDropped.Add(1)
			}
			if item.barrier != nil {
				close(item.barrier)
			}
		default:
			return
		}
	}
}

func secureSQLiteFiles(path string, repair bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("audit: resolve SQLite permissions path: %w", err)
	}
	for _, candidate := range []string{absPath, absPath + "-wal", absPath + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("audit: inspect SQLite file permissions: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("audit: SQLite files must be regular files, not symlinks or directories")
		}
		if !repair {
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("audit: SQLite file has unsafe permissions: %s", filepath.Base(candidate))
			}
			continue
		}
		file, err := os.OpenFile(candidate, os.O_RDWR, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("audit: open SQLite file for descriptor-level permission repair: %w", err)
		}
		openedInfo, statErr := file.Stat()
		currentInfo, lstatErr := os.Lstat(candidate)
		if statErr != nil || lstatErr != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) {
			_ = file.Close()
			return errors.New("audit: SQLite file identity changed during permission repair")
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return fmt.Errorf("audit: secure opened SQLite file: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("audit: close secured SQLite file: %w", err)
		}
	}
	return nil
}

func prepareSQLitePath(absPath string, createDirectory bool) error {
	directory := filepath.Dir(absPath)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if !createDirectory {
			return errors.New("audit: required persistent database directory does not exist")
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("audit: create database directory: %w", err)
		}
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return fmt.Errorf("audit: inspect database directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("audit: database directory must be a real directory, not a symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("audit: database directory must not be group- or world-writable")
	}
	for _, candidate := range []string{absPath, absPath + "-wal", absPath + "-shm"} {
		info, candidateErr := os.Lstat(candidate)
		if errors.Is(candidateErr, os.ErrNotExist) {
			continue
		}
		if candidateErr != nil {
			return fmt.Errorf("audit: inspect SQLite path: %w", candidateErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("audit: database, WAL, and SHM paths must be regular files, not symlinks or directories")
		}
		if !createDirectory && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("audit: SQLite file has unsafe permissions: %s", filepath.Base(candidate))
		}
	}
	return nil
}

func createSQLiteDatabaseFileIfMissing(path string, requirePrivate bool) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return fmt.Errorf("audit: recheck concurrently created SQLite database: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || requirePrivate && info.Mode().Perm()&0o077 != 0 {
			return errors.New("audit: concurrently created SQLite database is unsafe")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit: securely create SQLite database: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("audit: close newly created SQLite database: %w", err)
	}
	return nil
}
