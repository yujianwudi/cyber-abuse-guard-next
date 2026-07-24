package subject

import (
	"reflect"
	"testing"
	"time"
)

func TestObservationAccumulateFalseIsReadOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setup       func(*Controller, string)
		riskScore   int
		wantBlocked bool
		wantReason  Reason
		wantScore   float64
		wantRepeats int
		wantManual  bool
	}{
		{name: "absent subject", riskScore: 1000, wantReason: ReasonSafe},
		{
			name: "existing risk",
			setup: func(controller *Controller, subjectHash string) {
				_ = controller.Evaluate(subjectHash, 60)
			},
			riskScore:   1000,
			wantReason:  ReasonSafe,
			wantScore:   60,
			wantRepeats: 1,
		},
		{
			name: "audit threshold candidate inherits cooldown",
			setup: func(controller *Controller, subjectHash string) {
				_ = controller.Evaluate(subjectHash, 60)
				_ = controller.Evaluate(subjectHash, 60)
			},
			riskScore:   35,
			wantBlocked: true,
			wantReason:  ReasonCooldown,
			wantScore:   150,
			wantRepeats: 2,
		},
		{
			name: "below hard candidate inherits cooldown",
			setup: func(controller *Controller, subjectHash string) {
				_ = controller.Evaluate(subjectHash, 60)
				_ = controller.Evaluate(subjectHash, 60)
			},
			riskScore:   79,
			wantBlocked: true,
			wantReason:  ReasonCooldown,
			wantScore:   150,
			wantRepeats: 2,
		},
		{
			name: "clean request bypasses cooldown",
			setup: func(controller *Controller, subjectHash string) {
				_ = controller.Evaluate(subjectHash, 60)
				_ = controller.Evaluate(subjectHash, 60)
			},
			wantReason:  ReasonSafe,
			wantScore:   150,
			wantRepeats: 2,
		},
		{
			name: "audit candidate inherits manual block",
			setup: func(controller *Controller, subjectHash string) {
				_ = controller.Evaluate(subjectHash, 100)
				_ = controller.Evaluate(subjectHash, 100)
			},
			riskScore:   35,
			wantBlocked: true,
			wantReason:  ReasonManualBlock,
			wantScore:   250,
			wantRepeats: 2,
			wantManual:  true,
		},
		{
			name: "clean request bypasses manual block",
			setup: func(controller *Controller, subjectHash string) {
				_ = controller.Evaluate(subjectHash, 100)
				_ = controller.Evaluate(subjectHash, 100)
			},
			wantReason:  ReasonSafe,
			wantScore:   250,
			wantRepeats: 2,
			wantManual:  true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			clock := &testClock{now: time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)}
			controller := newTestController(t, clock)
			subjectHash := riskHash("observation-" + testCase.name)
			if testCase.setup != nil {
				testCase.setup(controller, subjectHash)
			}

			before, beforePresent := controller.Snapshot(subjectHash)
			beforeCount := controller.Count()
			decision := controller.ObserveRequest(subjectHash, riskRequestHash(testCase.name), Observation{
				RiskScore:  testCase.riskScore,
				Accumulate: false,
			})
			if decision.Blocked != testCase.wantBlocked || decision.Reason != testCase.wantReason ||
				decision.Score != testCase.wantScore || decision.RepeatCount != testCase.wantRepeats ||
				decision.ManualBlocked != testCase.wantManual {
				t.Fatalf("read-only observation = %#v", decision)
			}
			if decision.AddedScore != 0 || decision.Multiplier != 0 || decision.Duplicate {
				t.Fatalf("read-only observation changed accounting fields: %#v", decision)
			}
			if got := controller.Count(); got != beforeCount {
				t.Fatalf("subject count = %d after read-only observation, want %d", got, beforeCount)
			}
			after, afterPresent := controller.Snapshot(subjectHash)
			if afterPresent != beforePresent || !reflect.DeepEqual(after, before) {
				t.Fatalf("subject state changed: before=(%#v,%t) after=(%#v,%t)", before, beforePresent, after, afterPresent)
			}
		})
	}
}

func TestIneligibleObservationCleansExpiredStateAndReceipt(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 19, 2, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	subjectHash := riskHash("observation-expiry")
	requestHash := riskRequestHash("observation-expiry")
	if got := controller.EvaluateRequest(subjectHash, requestHash, 60); got.AddedScore != 60 {
		t.Fatalf("initial observation = %#v", got)
	}
	clock.Add(61 * time.Minute)

	decision := controller.ObserveRequest(subjectHash, requestHash, Observation{RiskScore: 35, Accumulate: false})
	if decision.Blocked || decision.Reason != ReasonSafe || decision.Score != 0 || decision.RepeatCount != 0 {
		t.Fatalf("expired ineligible observation = %#v", decision)
	}
	if len(controller.entries) != 0 {
		t.Fatalf("expired state retained after ineligible observation: %d entries", len(controller.entries))
	}

	admitted := controller.ObserveRequest(subjectHash, requestHash, Observation{RiskScore: 60, Accumulate: true})
	if admitted.Duplicate || admitted.AddedScore != 60 || admitted.Multiplier != 1 || admitted.RepeatCount != 1 {
		t.Fatalf("expired receipt suppressed later eligible observation: %#v", admitted)
	}
}

func TestIneligibleObservationDoesNotCreateRequestReceipt(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	subjectHash := riskHash("observation-receipt")
	requestHash := riskRequestHash("observation-receipt")

	ignored := controller.ObserveRequest(subjectHash, requestHash, Observation{RiskScore: 1000, Accumulate: false})
	if ignored.AddedScore != 0 || ignored.Multiplier != 0 || ignored.Duplicate || controller.Count() != 0 {
		t.Fatalf("ineligible observation persisted accounting: %#v", ignored)
	}

	admitted := controller.ObserveRequest(subjectHash, requestHash, Observation{RiskScore: 60, Accumulate: true})
	if admitted.Duplicate || admitted.AddedScore != 60 || admitted.Multiplier != 1 || admitted.RepeatCount != 1 {
		t.Fatalf("later eligible observation was suppressed: %#v", admitted)
	}
	duplicate := controller.ObserveRequest(subjectHash, requestHash, Observation{RiskScore: 60, Accumulate: true})
	if !duplicate.Duplicate || duplicate.AddedScore != 0 || duplicate.RepeatCount != 1 {
		t.Fatalf("eligible observation did not create its receipt: %#v", duplicate)
	}
}
