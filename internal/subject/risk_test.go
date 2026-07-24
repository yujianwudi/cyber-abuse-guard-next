package subject

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestControllerCooldownManualBlockAndSafeRequests(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	hash := riskHash("subject-one")

	if decision := controller.Evaluate(hash, 10); decision.Blocked || decision.Score != 0 {
		t.Fatalf("safe initial request = %#v", decision)
	}
	if controller.Count() != 0 {
		t.Fatal("safe requests should not allocate risk state")
	}

	first := controller.Evaluate(hash, 60)
	if first.Blocked || first.Score != 60 || first.Multiplier != 1 || first.RepeatCount != 1 {
		t.Fatalf("first risky request = %#v", first)
	}
	second := controller.Evaluate(hash, 60)
	if !second.Blocked || second.Reason != ReasonCooldown || second.Score != 150 || second.Multiplier != 1.5 || second.RepeatCount != 2 {
		t.Fatalf("second risky request = %#v", second)
	}

	// Cooldown and manual states are scoped to new risky requests. A normal
	// request must remain usable rather than turning one false positive into a
	// permanent account denial.
	safe := controller.Evaluate(hash, 5)
	if safe.Blocked || safe.Reason != ReasonSafe || !safe.CooldownUntil.Equal(second.CooldownUntil) {
		t.Fatalf("safe request during cooldown = %#v", safe)
	}

	clock.Add(61 * time.Minute)
	afterWindow := controller.Evaluate(hash, 40)
	if afterWindow.Blocked || afterWindow.Score != 40 || afterWindow.RepeatCount != 1 {
		t.Fatalf("request after rolling window = %#v", afterWindow)
	}

	manualHash := riskHash("manual")
	if got := controller.Evaluate(manualHash, 100); got.Blocked {
		t.Fatalf("first manual-threshold hit = %#v", got)
	}
	manual := controller.Evaluate(manualHash, 100)
	if !manual.Blocked || manual.Reason != ReasonManualBlock || !manual.ManualBlocked || manual.Score != 250 {
		t.Fatalf("manual block decision = %#v", manual)
	}
	if got := controller.Evaluate(manualHash, 1); got.Blocked || got.Reason != ReasonSafe || !got.ManualBlocked {
		t.Fatalf("safe request under manual state = %#v", got)
	}
	if !controller.Unblock(manualHash) {
		t.Fatal("Unblock() returned false for an existing subject")
	}
	if controller.Unblock(manualHash) {
		t.Fatal("Unblock() returned true for an absent subject")
	}
	if got := controller.Evaluate(manualHash, 40); got.Blocked || got.Score != 40 {
		t.Fatalf("risk history survived Unblock(): %#v", got)
	}
}

func TestControllerRollingLinearDecayAndRepeatBound(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	hash := riskHash("decay")
	if got := controller.Evaluate(hash, 100); got.Score != 100 {
		t.Fatalf("first score = %#v", got)
	}
	clock.Add(30 * time.Minute)
	state, ok := controller.Snapshot(hash)
	if !ok || state.Score != 50 {
		t.Fatalf("half-window Snapshot() = (%#v, %v)", state, ok)
	}

	// Repeat multipliers grow but are explicitly bounded.
	for i := 0; i < 10; i++ {
		decision := controller.Evaluate(riskHash("repeat"), 35)
		if decision.Multiplier > 3 {
			t.Fatalf("repeat multiplier escaped bound: %#v", decision)
		}
	}
}

func TestControllerConcurrentSafety(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	hash := riskHash("concurrent")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = controller.Evaluate(hash, 35)
		}()
	}
	wg.Wait()
	if controller.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", controller.Count())
	}
	state, ok := controller.Snapshot(hash)
	if !ok || !state.ManualBlocked || state.HitCount != 100 {
		t.Fatalf("concurrent State = (%#v, %v)", state, ok)
	}
	if !controller.Unblock(hash) || controller.Count() != 0 {
		t.Fatalf("concurrent Unblock failed; count=%d", controller.Count())
	}
}

func TestControllerRejectsUnsafeConfig(t *testing.T) {
	t.Parallel()

	valid := Config{
		Enabled:          true,
		Window:           time.Hour,
		AuditThreshold:   35,
		CooldownScore:    150,
		ManualBlockScore: 250,
		Cooldown:         30 * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"window", func(c *Config) { c.Window = 0 }},
		{"audit threshold", func(c *Config) { c.AuditThreshold = 0 }},
		{"cooldown score", func(c *Config) { c.CooldownScore = 0 }},
		{"threshold order", func(c *Config) { c.ManualBlockScore = c.CooldownScore }},
		{"cooldown", func(c *Config) { c.Cooldown = 0 }},
		{"repeat multiplier", func(c *Config) { c.RepeatMultiplier = .5 }},
		{"max multiplier", func(c *Config) { c.MaxMultiplier = 1 }},
		{"negative subject capacity", func(c *Config) { c.MaxSubjects = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.edit(&cfg)
			if _, err := NewController(cfg); err == nil {
				t.Fatalf("NewController(%s) succeeded: %#v", tc.name, cfg)
			}
		})
	}
}

func TestControllerCapacityEvictsOldestAndUsesSafeDefault(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	defaults := newTestController(t, clock)
	if got := defaults.Stats(); got.MaxSubjects != DefaultMaxSubjects {
		t.Fatalf("default Stats() = %#v, want max_subjects=%d", got, DefaultMaxSubjects)
	}

	controller := newCapacityController(t, clock, 64)
	for i := 0; i < 1000; i++ {
		decision := controller.Evaluate(riskHash(fmt.Sprintf("capacity-%04d", i)), 35)
		if decision.Reason == ReasonCapacity {
			t.Fatalf("non-manual entry was not evictable at i=%d: %#v", i, decision)
		}
		if got := controller.Count(); got > 64 {
			t.Fatalf("Count() = %d at i=%d, exceeds hard limit", got, i)
		}
	}
	stats := controller.Stats()
	if stats.Subjects != 64 || stats.MaxSubjects != 64 || stats.Evicted != 936 || stats.RejectedCapacity != 0 {
		t.Fatalf("capacity Stats() = %#v", stats)
	}
	if _, ok := controller.Snapshot(riskHash("capacity-0000")); ok {
		t.Fatal("oldest active subject survived capacity eviction")
	}
	if _, ok := controller.Snapshot(riskHash("capacity-0999")); !ok {
		t.Fatal("newest active subject was unexpectedly evicted")
	}
}

func TestControllerCapacityNeverEvictsManualBlocks(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newCapacityController(t, clock, 2)
	manualOne := riskHash("manual-capacity-one")
	manualTwo := riskHash("manual-capacity-two")
	for _, hash := range []string{manualOne, manualTwo} {
		_ = controller.Evaluate(hash, 100)
		if got := controller.Evaluate(hash, 100); !got.ManualBlocked {
			t.Fatalf("subject did not become manual-blocked: %#v", got)
		}
	}

	rejectedHash := riskHash("manual-capacity-rejected")
	decision := controller.Evaluate(rejectedHash, 35)
	if !decision.Blocked || decision.Reason != ReasonCapacity || decision.SubjectHash != rejectedHash {
		t.Fatalf("capacity rejection = %#v", decision)
	}
	stats := controller.Stats()
	if stats.Subjects != 2 || stats.ManualBlocked != 2 || stats.Evicted != 0 || stats.RejectedCapacity != 1 {
		t.Fatalf("manual capacity Stats() = %#v", stats)
	}
	for _, hash := range []string{manualOne, manualTwo} {
		if state, ok := controller.Snapshot(hash); !ok || !state.ManualBlocked {
			t.Fatalf("manual block was evicted: hash=%s state=%#v ok=%v", hash, state, ok)
		}
	}
	if controller.Unblock(manualOne) != true {
		t.Fatal("failed to unblock protected subject")
	}
	if got := controller.Evaluate(rejectedHash, 35); got.Reason == ReasonCapacity {
		t.Fatalf("capacity was not reusable after unblock: %#v", got)
	}
}

func TestControllerIncrementalCleanupHasFixedBatch(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newCapacityController(t, clock, 100)
	for i := 0; i < 100; i++ {
		_ = controller.Evaluate(riskHash(fmt.Sprintf("expired-%03d", i)), 35)
	}
	clock.Add(2 * time.Hour)
	stats := controller.Stats()
	if want := 100 - maintenanceBatch; stats.Subjects != want {
		t.Fatalf("one maintenance pass removed %d subjects, want fixed batch %d; stats=%#v", 100-stats.Subjects, maintenanceBatch, stats)
	}
	for stats.Subjects != 0 {
		stats = controller.Stats()
	}
	if stats.Evicted != 0 || stats.RejectedCapacity != 0 {
		t.Fatalf("expiration cleanup was counted as capacity pressure: %#v", stats)
	}
}

func TestControllerCapacityPrefersExpiredBehindActiveCooldown(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	cfg := capacityConfig(clock, 2)
	cfg.Window = time.Minute
	controller, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cooling := riskHash("capacity-cooling-oldest")
	expired := riskHash("capacity-expired-newer")
	newest := riskHash("capacity-newest")
	if got := controller.Evaluate(cooling, 150); got.Reason != ReasonCooldown {
		t.Fatalf("cooling subject decision = %#v", got)
	}
	clock.Add(30 * time.Second)
	_ = controller.Evaluate(expired, 35)
	clock.Add(90 * time.Second)

	if got := controller.Evaluate(newest, 35); got.Reason == ReasonCapacity {
		t.Fatalf("expired capacity was not reclaimed: %#v", got)
	}
	stats := controller.Stats()
	if stats.Subjects != 2 || stats.Evicted != 0 || stats.RejectedCapacity != 0 {
		t.Fatalf("expiration preference Stats() = %#v", stats)
	}
	if state, ok := controller.Snapshot(cooling); !ok || state.CooldownUntil.IsZero() {
		t.Fatalf("active cooldown was evicted: state=%#v ok=%v", state, ok)
	}
	if _, ok := controller.Snapshot(expired); ok {
		t.Fatal("expired subject survived while an active subject was evicted")
	}
}

func TestControllerReconfigurePreservesAndSafelyShrinksState(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newCapacityController(t, clock, 3)
	manualOne := riskHash("reconfigure-manual-one")
	manualTwo := riskHash("reconfigure-manual-two")
	nonManual := riskHash("reconfigure-non-manual")
	for _, hash := range []string{manualOne, manualTwo} {
		_ = controller.Evaluate(hash, 100)
		_ = controller.Evaluate(hash, 100)
	}
	_ = controller.Evaluate(nonManual, 35)

	cfg := capacityConfig(clock, 2)
	cfg.CooldownScore = 175
	cfg.ManualBlockScore = 275
	if err := controller.Reconfigure(cfg); err != nil {
		t.Fatalf("Reconfigure(shrink to manual count): %v", err)
	}
	stats := controller.Stats()
	if stats.Subjects != 2 || stats.ManualBlocked != 2 || stats.MaxSubjects != 2 || stats.Evicted != 1 {
		t.Fatalf("post-shrink Stats() = %#v", stats)
	}
	if _, ok := controller.Snapshot(nonManual); ok {
		t.Fatal("non-manual subject survived capacity shrink")
	}
	for _, hash := range []string{manualOne, manualTwo} {
		if state, ok := controller.Snapshot(hash); !ok || !state.ManualBlocked {
			t.Fatalf("manual state not preserved across reconfigure: %#v, %v", state, ok)
		}
	}

	tooSmall := capacityConfig(clock, 1)
	if err := controller.Reconfigure(tooSmall); err == nil {
		t.Fatal("Reconfigure below protected manual count succeeded")
	}
	if got := controller.Stats(); got.MaxSubjects != 2 || got.Subjects != 2 {
		t.Fatalf("failed Reconfigure partially changed state: %#v", got)
	}
	invalid := capacityConfig(clock, 2)
	invalid.CooldownScore = 0
	if err := controller.Reconfigure(invalid); err == nil {
		t.Fatal("Reconfigure accepted invalid thresholds")
	}
	if got := controller.Stats(); got.MaxSubjects != 2 || got.Subjects != 2 || got.ManualBlocked != 2 {
		t.Fatalf("invalid Reconfigure partially changed state: %#v", got)
	}

	if err := controller.Reconfigure(Config{Enabled: false, MaxSubjects: 1, Now: clock.Now}); err != nil {
		t.Fatalf("Reconfigure(disabled): %v", err)
	}
	if got := controller.Stats(); got.Enabled || got.Subjects != 0 || got.ManualBlocked != 0 {
		t.Fatalf("disabled Stats() = %#v", got)
	}
	if got := controller.Evaluate(riskHash("disabled"), 1000); got.Reason != ReasonDisabled {
		t.Fatalf("disabled Evaluate() = %#v", got)
	}
}

func TestControllerConcurrentUniqueCapacityAndReconfigure(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newCapacityController(t, clock, 128)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 125; i++ {
				_ = controller.Evaluate(riskHash(fmt.Sprintf("concurrent-unique-%02d-%03d", worker, i)), 35)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 100; i++ {
			limit := 64
			if i%2 == 0 {
				limit = 128
			}
			if err := controller.Reconfigure(capacityConfig(clock, limit)); err != nil {
				t.Errorf("concurrent Reconfigure(%d): %v", limit, err)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	stats := controller.Stats()
	if stats.Subjects > stats.MaxSubjects || stats.MaxSubjects != 64 {
		t.Fatalf("concurrent capacity Stats() = %#v", stats)
	}
	if stats.Evicted == 0 {
		t.Fatalf("concurrent pressure did not produce observable evictions: %#v", stats)
	}
}

func TestControllerNeverStoresPlaintextSubject(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	decision := controller.Evaluate("plaintext-api-key-canary", 1000)
	if decision.Blocked || decision.Reason != ReasonInvalidHash || decision.SubjectHash != "" {
		t.Fatal("plaintext subject was reflected in a decision")
	}
	requestDecision := controller.EvaluateRequest("plaintext-api-key-canary", "not-a-request-digest", 1000)
	if requestDecision.Blocked || requestDecision.Reason != ReasonInvalidHash || requestDecision.SubjectHash != "" {
		t.Fatal("plaintext subject was reflected when the request digest was invalid")
	}
	if controller.Count() != 0 {
		t.Fatal("controller retained a plaintext subject")
	}
}

func newTestController(t testing.TB, clock *testClock) *Controller {
	t.Helper()
	controller, err := NewController(Config{
		Enabled:          true,
		Window:           time.Hour,
		AuditThreshold:   35,
		CooldownScore:    150,
		ManualBlockScore: 250,
		Cooldown:         30 * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
		Now:              clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func newCapacityController(t *testing.T, clock *testClock, maxSubjects int) *Controller {
	t.Helper()
	controller, err := NewController(capacityConfig(clock, maxSubjects))
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func capacityConfig(clock *testClock, maxSubjects int) Config {
	return Config{
		Enabled:          true,
		Window:           time.Hour,
		AuditThreshold:   35,
		CooldownScore:    150,
		ManualBlockScore: 250,
		Cooldown:         30 * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
		MaxSubjects:      maxSubjects,
		Now:              clock.Now,
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func (c *testClock) String() string {
	return fmt.Sprint(c.Now())
}

func riskHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(sum[:])
}
