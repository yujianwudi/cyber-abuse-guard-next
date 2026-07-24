package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDevelopmentAdversarialV11PrepCorpus(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	metrics, err := validateDevelopmentCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.Total < 32 || metrics.Block < 8 || metrics.Allow < 8 || metrics.Audit < 8 || metrics.Boundary < 3 {
		t.Fatalf("unexpected development metrics: %+v", metrics)
	}
}
