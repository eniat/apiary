package reaper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/eniat/apiary/orchestrator/internal/apiary"
)

// copies a honeypot's host side logs then proves the copy
type DirArchiver struct {
	LogRoot string
	Dest    string
}

func (d DirArchiver) Archive(_ context.Context, hp *apiary.Honeypot) error {
	src := filepath.Join(d.LogRoot, hp.ID)
	dst := filepath.Join(d.Dest, hp.ID)
	if err := copyTree(src, dst); err != nil {
		return err
	}
	return verifyTree(src, dst)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if e.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		// sockets and symlinks carry nothing
		if !e.Type().IsRegular() {
			return nil
		}
		return copyFile(p, out)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	// durable means on the disk not in the page cache
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// byte for byte or it does not count as archived
func verifyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		a, err := sum(p)
		if err != nil {
			return err
		}
		b, err := sum(filepath.Join(dst, rel))
		if err != nil {
			return err
		}
		if a != b {
			return fmt.Errorf("%s: %s does not match %s", rel, a, b)
		}
		return nil
	})
}

func sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
