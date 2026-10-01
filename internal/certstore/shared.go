package certstore

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/Sebiee/fortressedge/internal/metrics"
)

// Remote is the shared store: Vault.
type Remote interface {
	certmagic.Storage
}

// Shared is certmagic.Storage on the edge's disk and a store the edges
// share. The shared store is the truth: every read asks it first, so a
// certificate another edge obtained or renewed is used, and keeps a copy
// on disk; every write goes to disk, then to the shared store. A key the
// shared store does not have is not there, unless this edge wrote it
// while the store was down and has not got it there yet (pending).
//
// When the shared store cannot be reached, the disk serves alone: the
// edge keeps its certificates, renews them by itself (the shared lock
// falls back to the disk's), and writes what the store missed once it is
// back. An unreachable store is not asked again for downFor, so boot does
// not wait on it call after call. Run first writes what the disk has and
// the store does not: an edge that kept its certificates on disk before
// shares them, rather than order them again.
type Shared struct {
	Local  certmagic.Storage
	Remote Remote

	downUntil atomic.Int64 // unix nanoseconds
	lastOK    atomic.Int64 // unix nanoseconds of the last call that worked
	errs      sync.Map     // op -> *atomic.Int64

	mu       sync.Mutex
	pending  map[string]bool // keys written to disk only
	seeded   bool
	lastErr  string
	localLck map[string]bool // locks taken on disk, the store being down
}

// downFor is how long the shared store is left alone after a call failed.
var downFor = 30 * time.Second

// syncEvery is how often keys the shared store missed are written again.
const syncEvery = time.Minute

func NewShared(local certmagic.Storage, remote Remote) *Shared {
	return &Shared{Local: local, Remote: remote, pending: map[string]bool{}, localLck: map[string]bool{}}
}

// Run writes the keys the shared store missed until ctx ends.
func (s *Shared) Run(ctx context.Context) {
	s.Seed(ctx)
	t := time.NewTicker(syncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Seed(ctx)
			s.flush(ctx)
		}
	}
}

// Seed marks the keys on disk that the shared store lacks as pending,
// once, when the store answers.
func (s *Shared) Seed(ctx context.Context) {
	s.mu.Lock()
	seeded := s.seeded
	s.mu.Unlock()
	if seeded || !s.up() {
		return
	}
	local, err := s.Local.List(ctx, "", true)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return
	}
	remote, err := s.Remote.List(ctx, "", true)
	if !answered(ctx, err) {
		s.fail("list", err)
		return
	}
	s.ok()
	have := map[string]bool{}
	for _, k := range remote {
		have[k] = true
	}
	var missing []string
	for _, k := range local {
		if have[k] {
			continue
		}
		if info, err := s.Local.Stat(ctx, k); err != nil || !info.IsTerminal {
			continue
		}
		missing = append(missing, k)
	}
	s.mu.Lock()
	for _, k := range missing {
		s.pending[k] = true
	}
	s.seeded = true
	s.mu.Unlock()
	if len(missing) > 0 {
		slog.Info("cert store: sharing what the disk has", "keys", len(missing))
		s.flush(ctx)
	}
}

// isPending is whether the disk's k is newer than the shared store's:
// written while the store was down, or, before Seed has compared them,
// any key.
func (s *Shared) isPending(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending[k] || !s.seeded
}

func (s *Shared) flush(ctx context.Context) {
	if !s.up() {
		return
	}
	s.mu.Lock()
	keys := slices.Sorted(maps.Keys(s.pending))
	s.mu.Unlock()
	for _, k := range keys {
		v, err := s.Local.Load(ctx, k)
		if errors.Is(err, fs.ErrNotExist) {
			s.done(k)
			continue
		}
		if err != nil {
			continue
		}
		if err := s.Remote.Store(ctx, k, v); err != nil {
			s.fail("store", err)
			return
		}
		s.ok()
		s.done(k)
	}
}

func (s *Shared) done(k string) {
	s.mu.Lock()
	delete(s.pending, k)
	s.mu.Unlock()
}

func (s *Shared) up() bool { return time.Now().UnixNano() >= s.downUntil.Load() }

func (s *Shared) ok() { s.lastOK.Store(time.Now().UnixNano()) }

// fail counts a call to the shared store that failed. Not found is an
// answer, not a failure; nor is a caller that gave up.
func (s *Shared) fail(op string, err error) {
	c, _ := s.errs.LoadOrStore(op, new(atomic.Int64))
	c.(*atomic.Int64).Add(1)
	first := s.up()
	s.downUntil.Store(time.Now().Add(downFor).UnixNano())
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
	if first {
		slog.Warn("cert store: shared store unreachable; serving from disk", "op", op, "err", err, "retry_in", downFor)
	}
}

// answered is whether err came from the shared store answering.
func answered(ctx context.Context, err error) bool {
	return err == nil || errors.Is(err, fs.ErrNotExist) || ctx.Err() != nil
}

func (s *Shared) Store(ctx context.Context, key string, value []byte) error {
	if err := s.Local.Store(ctx, key, value); err != nil {
		return err
	}
	if s.up() {
		err := s.Remote.Store(ctx, key, value)
		if err == nil {
			s.ok()
			return nil
		}
		if !answered(ctx, err) {
			s.fail("store", err)
		}
	}
	s.mu.Lock()
	s.pending[key] = true
	s.mu.Unlock()
	return nil
}

func (s *Shared) Load(ctx context.Context, key string) ([]byte, error) {
	if s.up() {
		v, err := s.Remote.Load(ctx, key)
		switch {
		case err == nil:
			s.ok()
			if cur, lerr := s.Local.Load(ctx, key); lerr != nil || !bytes.Equal(cur, v) {
				_ = s.Local.Store(ctx, key, v) // the copy for when the store is down
			}
			return v, nil
		case errors.Is(err, fs.ErrNotExist):
			s.ok()
			if s.isPending(key) {
				return s.Local.Load(ctx, key) // not there yet
			}
			return nil, err
		case ctx.Err() == nil:
			s.fail("load", err)
		}
	}
	return s.Local.Load(ctx, key)
}

func (s *Shared) Delete(ctx context.Context, key string) error {
	err := s.Local.Delete(ctx, key)
	s.done(key)
	if s.up() {
		if rerr := s.Remote.Delete(ctx, key); answered(ctx, rerr) {
			s.ok()
		} else {
			s.fail("delete", rerr)
		}
	}
	return err
}

func (s *Shared) Exists(ctx context.Context, key string) bool {
	_, err := s.Stat(ctx, key)
	return err == nil
}

func (s *Shared) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	if s.up() {
		info, err := s.Remote.Stat(ctx, key)
		switch {
		case err == nil:
			s.ok()
			return info, nil
		case errors.Is(err, fs.ErrNotExist):
			s.ok()
			if !s.isPending(key) {
				return info, err
			}
		case ctx.Err() == nil:
			s.fail("stat", err)
		}
	}
	return s.Local.Stat(ctx, key)
}

// List is what the shared store has under prefix, and the pending keys
// there; the disk's, when the store is down.
func (s *Shared) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if s.up() {
		keys, err := s.Remote.List(ctx, prefix, recursive)
		if answered(ctx, err) {
			s.ok()
			local, _ := s.Local.List(ctx, prefix, recursive)
			for _, k := range local {
				if s.isPending(k) {
					keys = append(keys, k)
				}
			}
			slices.Sort(keys)
			keys = slices.Compact(keys)
			if len(keys) == 0 && err != nil {
				return nil, err
			}
			return keys, nil
		}
		s.fail("list", err)
	}
	return s.Local.List(ctx, prefix, recursive)
}

// Lock takes the shared lock, so two edges do not order the same
// certificate at once; with the store down, the disk's.
func (s *Shared) Lock(ctx context.Context, name string) error {
	if s.up() {
		err := s.Remote.Lock(ctx, name)
		if err == nil {
			s.ok()
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		s.fail("lock", err)
	}
	if err := s.Local.Lock(ctx, name); err != nil {
		return err
	}
	s.mu.Lock()
	s.localLck[name] = true
	s.mu.Unlock()
	return nil
}

func (s *Shared) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	local := s.localLck[name]
	delete(s.localLck, name)
	s.mu.Unlock()
	if local {
		return s.Local.Unlock(ctx, name)
	}
	err := s.Remote.Unlock(ctx, name)
	if err != nil && ctx.Err() == nil {
		s.fail("unlock", err) // it expires after lockTTL
	}
	return err
}

// Status is the shared store's health, for the status's cert_store.
func (s *Shared) Status() map[string]any {
	s.mu.Lock()
	m := map[string]any{"pending": len(s.pending), "last_error": s.lastErr}
	s.mu.Unlock()
	m["reachable"] = s.up()
	if t := s.lastOK.Load(); t > 0 {
		m["last_ok"] = time.Unix(0, t).UTC().Format(time.RFC3339)
	}
	errs := map[string]int64{}
	s.errs.Range(func(k, v any) bool {
		errs[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	m["errors"] = errs
	return m
}

func (s *Shared) WriteMetrics(w *metrics.Writer) {
	w.Family("fortressedge_cert_store_errors_total", "counter",
		"Calls to the shared certificate store (Vault) that failed, by op: load, store, stat, list, delete, lock, unlock. The edge served from its disk instead.")
	var ops []string
	s.errs.Range(func(k, _ any) bool { ops = append(ops, k.(string)); return true })
	slices.Sort(ops)
	for _, op := range ops {
		c, _ := s.errs.Load(op)
		w.Int("fortressedge_cert_store_errors_total", c.(*atomic.Int64).Load(), "op", op)
	}
	if t := s.lastOK.Load(); t > 0 {
		w.Family("fortressedge_cert_store_last_success_timestamp_seconds", "gauge",
			"When a call to the shared certificate store last worked, in Unix seconds.")
		w.Sample("fortressedge_cert_store_last_success_timestamp_seconds", float64(t/1e6)/1e3)
	}
	s.mu.Lock()
	n := len(s.pending)
	s.mu.Unlock()
	w.Family("fortressedge_cert_store_pending", "gauge",
		"Keys written to the edge's disk that the shared store has not got yet; written again each minute.")
	w.Int("fortressedge_cert_store_pending", int64(n))
}

var _ certmagic.Storage = (*Shared)(nil)
