//go:build linux

package initos

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadPolicy reads the policy fortressctl apply stored at path. An edge
// nobody applied a policy to has none: nil, and no error.
func LoadPolicy(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// StorePolicy replaces the policy at path whole: a power cut leaves the
// old one or the new one, never part of either.
func StorePolicy(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".policy-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
