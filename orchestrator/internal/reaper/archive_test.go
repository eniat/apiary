package reaper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

func seed(t *testing.T, root string) {
	t.Helper()
	dirs := []string{filepath.Join(root, "log"), filepath.Join(root, "state", "tty")}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(root, "log", "cowrie.json"):              `{"eventid":"cowrie.session.connect"}`,
		filepath.Join(root, "state", "tty", "20261012-0i.log"): "keystrokes",
	}
	for p, c := range files {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestArchiveCopiesAndVerifies(t *testing.T) {
	logs, dest := t.TempDir(), t.TempDir()
	seed(t, filepath.Join(logs, "a"))

	a := DirArchiver{LogRoot: logs, Dest: dest}
	if err := a.Archive(context.Background(), &apiary.Honeypot{ID: "a"}); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"log/cowrie.json", "state/tty/20261012-0i.log"} {
		if _, err := os.Stat(filepath.Join(dest, "a", rel)); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
}

func TestArchiveCatchesCorruption(t *testing.T) {
	logs, dest := t.TempDir(), t.TempDir()
	src := filepath.Join(logs, "a")
	seed(t, src)

	if err := copyTree(src, filepath.Join(dest, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "a", "log", "cowrie.json"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyTree(src, filepath.Join(dest, "a")); err == nil {
		t.Error("want a mismatch, got nil")
	}
}

func TestArchiveMissingSource(t *testing.T) {
	a := DirArchiver{LogRoot: t.TempDir(), Dest: t.TempDir()}
	if err := a.Archive(context.Background(), &apiary.Honeypot{ID: "gone"}); err == nil {
		t.Error("want an error, got nil")
	}
}
