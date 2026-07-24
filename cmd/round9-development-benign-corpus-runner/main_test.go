package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestRound9DevelopmentWilsonUpperBoundForZeroOfTwelveHundred(t *testing.T) {
	t.Parallel()
	got := wilsonUpper95(0, 1200) * 100
	if math.Abs(got-0.319) > 0.01 {
		t.Fatalf("Wilson upper=%.6f%% want approximately 0.319%%", got)
	}
}

func TestRound9DevelopmentFileIdentity(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "visible-development.json")
	if err := os.WriteFile(path, []byte("development\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bytes != 12 || got.SHA256 != "69dced1fc82b64513842ce628727ee18744ebe7cecbd16ed47c753b76873f9be" {
		t.Fatalf("unexpected identity: %+v", got)
	}
}
