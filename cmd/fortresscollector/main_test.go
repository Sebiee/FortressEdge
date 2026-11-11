package main

import (
	"testing"

	"github.com/Sebiee/fortressedge/internal/collect"
)

func TestParseEdges(t *testing.T) {
	got, err := parseEdges("a=10.4.1.11, b=10.4.1.12:8443,")
	if err != nil {
		t.Fatal(err)
	}
	want := []collect.Edge{{Name: "a", Addr: "10.4.1.11:443"}, {Name: "b", Addr: "10.4.1.12:8443"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"", "a", "=10.4.1.11", "a="} {
		if _, err := parseEdges(bad); err == nil {
			t.Fatalf("-edges %q was accepted", bad)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1GiB": 1 << 30, "512MiB": 512 << 20, "64KiB": 64 << 10} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Fatalf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "1", "1GB", "0MiB", "-1GiB", "xGiB"} {
		if _, err := parseSize(bad); err == nil {
			t.Fatalf("size %q was accepted", bad)
		}
	}
}
