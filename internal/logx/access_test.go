package logx

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAccessRotatesAndKeepsMaxFiles(t *testing.T) {
	dir := t.TempDir()
	a := &accessFile{dir: dir, boot: "b", id: "old", max: 30, keep: 3}
	if err := a.rotate(); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"one 12345678901234\n", "two 12345678901234\n", "three 123456789012\n", "four\n"} {
		if _, err := a.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	// Four files were written; the oldest went, and current.log counts.
	if got := read(t, filepath.Join(dir, "current.log")); got != "# boot b.3\nfour\n" {
		t.Fatalf("current.log=%q", got)
	}
	if got := read(t, filepath.Join(dir, "b.2.log")); got != "# boot b.2\nthree 123456789012\n" {
		t.Fatalf("b.2.log=%q", got)
	}
	if got := read(t, filepath.Join(dir, "b.1.log")); got != "# boot b.1\ntwo 12345678901234\n" {
		t.Fatalf("b.1.log=%q", got)
	}
	names := func() []string {
		var out []string
		for _, p := range Rotated(dir) {
			out = append(out, filepath.Base(p))
		}
		return out
	}
	if got := names(); !slices.Equal(got, []string{"b.2.log", "b.1.log"}) {
		t.Fatalf("rotated=%v", got)
	}
}

func TestAccessOneFileKeepsNoHistory(t *testing.T) {
	dir := t.TempDir()
	a := &accessFile{dir: dir, boot: "b", id: "old", max: 20, keep: 1}
	if err := a.rotate(); err != nil {
		t.Fatal(err)
	}
	a.Write([]byte("one 1234567890\n"))
	a.Write([]byte("two 1234567890\n"))
	if got := Rotated(dir); len(got) != 0 {
		t.Fatalf("rotated=%v", got)
	}
	if got := read(t, filepath.Join(dir, "current.log")); got != "# boot b.1\ntwo 1234567890\n" {
		t.Fatalf("current.log=%q", got)
	}
}

func TestAccessKeepsLastBootByID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "current.log"), []byte("# boot old\nx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAccess(dir, 1<<20, 3); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dir, "old.log")); got != "# boot old\nx\n" {
		t.Fatalf("old.log=%q", got)
	}
}
