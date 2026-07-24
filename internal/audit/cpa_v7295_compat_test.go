package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCPAV7295CodexAlphaSearchSourceFormatIsCanonical(t *testing.T) {
	for _, input := range []string{
		"codex-alpha-search",
		" CODEX-ALPHA-SEARCH ",
	} {
		if got := CanonicalSourceFormat(input); got != SourceFormatCodexAlphaSearch {
			t.Fatalf("CanonicalSourceFormat(%q) = %q, want %q", input, got, SourceFormatCodexAlphaSearch)
		}
	}
}

func TestCPAV7295CodexAlphaSearchAuditEventPersists(t *testing.T) {
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "cpa-v7295-alpha-search.db"),
		Now:  func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	event := testEvent("cpa-v7295-alpha-search", now)
	event.SourceFormat = SourceFormatCodexAlphaSearch
	if !store.Record(event) {
		t.Fatal("Record() rejected a CPA v7.2.95 codex-alpha-search event")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(events) != 1 || events[0].SourceFormat != SourceFormatCodexAlphaSearch {
		t.Fatalf("persisted events = %#v, want one %q event", events, SourceFormatCodexAlphaSearch)
	}
}
