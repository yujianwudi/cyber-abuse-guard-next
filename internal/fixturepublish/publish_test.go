package fixturepublish

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishPublishesCompleteDirectoryAndRefusesOverwrite(t *testing.T) {
	t.Parallel()
	destination := filepath.Join(t.TempDir(), "holdout")
	files := []File{
		{Name: "benign.jsonl", Data: []byte("benign\n")},
		{Name: "malicious.jsonl", Data: []byte("malicious\n")},
	}
	if err := Publish(destination, files); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for _, item := range files {
		data, err := os.ReadFile(filepath.Join(destination, item.Name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != string(item.Data) {
			t.Fatalf("%s content mismatch", item.Name)
		}
	}
	if err := Publish(destination, files); err == nil {
		t.Fatal("existing fixture directory was overwritten")
	}
}

func TestPublishFailureDoesNotExposePartialSet(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	destination := filepath.Join(parent, "holdout")
	files := []File{{Name: "one.jsonl", Data: []byte("one\n")}, {Name: "two.jsonl", Data: []byte("two\n")}}
	writes := 0
	err := PublishWithWriter(destination, files, func(path string, data []byte) error {
		writes++
		if writes == 2 {
			return errors.New("injected second-file failure")
		}
		return WriteSyncedFile(path, data)
	})
	if err == nil {
		t.Fatal("expected publication failure")
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("partial fixture set became visible: %v", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(parent, ".holdout.tmp-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("staging directories were not cleaned up: %v", matches)
	}
}

func TestRenameNoReplaceRefusesExistingEmptyDirectory(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	staging := filepath.Join(parent, "staging")
	destination := filepath.Join(parent, "destination")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "fixture"), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(staging, destination); err == nil {
		t.Fatal("renameNoReplace replaced an existing empty directory")
	}
	if data, err := os.ReadFile(filepath.Join(staging, "fixture")); err != nil || string(data) != "staged" {
		t.Fatalf("staging changed after rejected rename: data=%q err=%v", data, err)
	}
	if info, err := os.Stat(destination); err != nil || !info.IsDir() {
		t.Fatalf("destination changed after rejected rename: info=%v err=%v", info, err)
	}
}

func TestRenameNoReplaceRefusesExistingFile(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	staging := filepath.Join(parent, "staging")
	destination := filepath.Join(parent, "destination")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "fixture"), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(staging, destination); err == nil {
		t.Fatal("renameNoReplace replaced an existing file")
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "existing" {
		t.Fatalf("destination changed after rejected rename: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(staging, "fixture")); err != nil || string(data) != "staged" {
		t.Fatalf("staging changed after rejected rename: data=%q err=%v", data, err)
	}
}

func TestRenameNoReplaceRefusesExistingSymlink(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	staging := filepath.Join(parent, "staging")
	target := filepath.Join(parent, "target")
	destination := filepath.Join(parent, "destination")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "fixture"), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, destination); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := renameNoReplace(staging, destination); err == nil {
		t.Fatal("renameNoReplace replaced an existing symlink")
	}
	info, err := os.Lstat(destination)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("destination symlink changed after rejected rename: info=%v err=%v", info, err)
	}
	if data, err := os.ReadFile(filepath.Join(staging, "fixture")); err != nil || string(data) != "staged" {
		t.Fatalf("staging changed after rejected rename: data=%q err=%v", data, err)
	}
}

func TestPublishRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	t.Parallel()
	destination := filepath.Join(t.TempDir(), "holdout")
	for _, name := range []string{"", ".", "..", "nested/file", `nested\file`} {
		if err := Publish(destination, []File{{Name: name, Data: []byte("x")}}); err == nil {
			t.Fatalf("unsafe filename %q was accepted", name)
		}
	}
	if err := Publish(destination, []File{{Name: "same", Data: []byte("one")}, {Name: "same", Data: []byte("two")}}); err == nil {
		t.Fatal("duplicate filename was accepted")
	}
	if err := Publish(destination, nil); err == nil {
		t.Fatal("empty publication was accepted")
	}
	if err := PublishWithWriter(destination, []File{{Name: "one", Data: []byte("x")}}, nil); err == nil {
		t.Fatal("nil writer was accepted")
	}
}
