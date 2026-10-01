// Package certstore keeps the edge's certificates, ACME account, and
// challenge data where several edges can share them: a Vault KV v2 path,
// with the edge's own disk as the copy it serves from when Vault cannot
// be reached (Shared).
package certstore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

// VaultConfig is how the edge reaches its Vault path.
type VaultConfig struct {
	URL      string // https://vault.example.com:8200
	CA       []byte // PEM: the only roots the connection trusts; empty is the system's
	Mount    string // the KV v2 mount, such as edge-certs
	Path     string // the edges' path in it, such as test/private
	RoleID   string // AppRole
	SecretID string
}

// Vault is certmagic.Storage on a KV v2 path. Each key is a secret at
// <path>/<key> holding the value; a lock is a secret at
// <path>/_locks/<name>, created only where none is (check-and-set 0), so
// two edges cannot both take it.
type Vault struct {
	c     *vault.Client
	kv    *vault.KVv2
	mount string
	root  string
	auth  *approle.AppRoleAuth

	mu        sync.Mutex // token
	expires   time.Time
	renewable bool

	locksMu sync.Mutex
	locks   map[string]*heldLock
}

// requestTimeout bounds each call to Vault: the edge falls back to its
// disk rather than wait (Shared). A Vault whose machine is off answers no
// SYN, and one that hangs answers no handshake: the dial gives up after a
// second, the handshake after two, so a boot with Vault down waits that
// long once (Shared then leaves it alone), not a whole request timeout.
const (
	requestTimeout = 10 * time.Second
	dialTimeout    = time.Second
)

func NewVault(cfg VaultConfig) (*Vault, error) {
	vc := vault.DefaultConfig()
	vc.Address = cfg.URL
	vc.Timeout = requestTimeout
	vc.MaxRetries = 0 // Shared falls back and retries later
	if len(cfg.CA) > 0 {
		if err := vc.ConfigureTLS(&vault.TLSConfig{CACertBytes: cfg.CA}); err != nil {
			return nil, fmt.Errorf("vault_ca: %w", err)
		}
	}
	if tr, ok := vc.HttpClient.Transport.(*http.Transport); ok {
		tr.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
		tr.TLSHandshakeTimeout = 2 * time.Second
	}
	c, err := vault.NewClient(vc)
	if err != nil {
		return nil, err
	}
	c.ClearToken() // never one from the environment
	auth, err := approle.NewAppRoleAuth(cfg.RoleID, &approle.SecretID{FromString: cfg.SecretID})
	if err != nil {
		return nil, err
	}
	return &Vault{
		c:     c,
		kv:    c.KVv2(cfg.Mount),
		mount: strings.Trim(cfg.Mount, "/"),
		root:  strings.Trim(cfg.Path, "/"),
		auth:  auth,
		locks: map[string]*heldLock{},
	}, nil
}

// token logs in, or renews the token, when it has less than two minutes
// left.
func (v *Vault) token(ctx context.Context, force bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !force && v.c.Token() != "" && time.Until(v.expires) > 2*time.Minute {
		return nil
	}
	if !force && v.c.Token() != "" && v.renewable {
		if s, err := v.c.Auth().Token().RenewSelfWithContext(ctx, 0); err == nil && s != nil && s.Auth != nil {
			v.set(s)
			return nil
		}
	}
	s, err := v.c.Auth().Login(ctx, v.auth)
	if err != nil {
		v.c.ClearToken()
		return fmt.Errorf("vault: approle login: %w", err)
	}
	if s == nil || s.Auth == nil {
		return errors.New("vault: approle login: no token")
	}
	v.set(s)
	return nil
}

func (v *Vault) set(s *vault.Secret) {
	ttl := time.Duration(s.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour // no expiry: look again in a day
	}
	v.expires = time.Now().Add(ttl)
	v.renewable = s.Auth.Renewable
}

// do runs f with a valid token, logging in again once if Vault says the
// token is no good.
func (v *Vault) do(ctx context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := v.token(ctx, false); err != nil {
		return err
	}
	err := f(ctx)
	if status(err) == http.StatusForbidden {
		if err := v.token(ctx, true); err != nil {
			return err
		}
		err = f(ctx)
	}
	return err
}

func status(err error) int {
	var re *vault.ResponseError
	if errors.As(err, &re) {
		return re.StatusCode
	}
	return 0
}

// casMismatch is a check-and-set write refused: the secret is not at the
// version given.
func casMismatch(err error) bool {
	var re *vault.ResponseError
	if !errors.As(err, &re) || re.StatusCode != http.StatusBadRequest {
		return false
	}
	for _, e := range re.Errors {
		if strings.Contains(e, "check-and-set") {
			return true
		}
	}
	return false
}

func (v *Vault) key(key string) (string, error) {
	k := strings.Trim(key, "/")
	if k == "" || path.Clean(k) != k || strings.HasPrefix(k, "../") || k == ".." || strings.HasPrefix(k, "_locks") {
		return "", fmt.Errorf("vault: bad key %q", key)
	}
	return v.root + "/" + k, nil
}

func (v *Vault) dir(prefix string) string {
	p := strings.Trim(prefix, "/")
	if p == "" {
		return v.root
	}
	return v.root + "/" + p
}

func (v *Vault) Store(ctx context.Context, key string, value []byte) error {
	p, err := v.key(key)
	if err != nil {
		return err
	}
	return v.do(ctx, func(ctx context.Context) error {
		_, err := v.kv.Put(ctx, p, map[string]any{"value": value})
		return err
	})
}

func (v *Vault) Load(ctx context.Context, key string) ([]byte, error) {
	p, err := v.key(key)
	if err != nil {
		return nil, err
	}
	var out []byte
	err = v.do(ctx, func(ctx context.Context) error {
		s, err := v.kv.Get(ctx, p)
		if errors.Is(err, vault.ErrSecretNotFound) || (err == nil && s.Data == nil) {
			return fs.ErrNotExist
		}
		if err != nil {
			return err
		}
		out, err = decodeValue(s.Data["value"])
		return err
	})
	return out, err
}

// decodeValue reads back what Store wrote: []byte travels as base64 in
// JSON.
func decodeValue(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("vault: secret has no value")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vault: value: %w", err)
	}
	return b, nil
}

func (v *Vault) Delete(ctx context.Context, key string) error {
	p, err := v.key(key)
	if err != nil {
		return err
	}
	// A key can be a "directory" too, as on disk: delete what is under it.
	children, err := v.List(ctx, key, true)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, c := range children {
		cp, _ := v.key(c)
		if err := v.do(ctx, func(ctx context.Context) error { return v.kv.DeleteMetadata(ctx, cp) }); err != nil {
			return err
		}
	}
	return v.do(ctx, func(ctx context.Context) error { return v.kv.DeleteMetadata(ctx, p) })
}

func (v *Vault) Exists(ctx context.Context, key string) bool {
	_, err := v.Stat(ctx, key)
	return err == nil
}

func (v *Vault) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	p, err := v.key(key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	var info certmagic.KeyInfo
	err = v.do(ctx, func(ctx context.Context) error {
		md, err := v.kv.GetMetadata(ctx, p)
		if errors.Is(err, vault.ErrSecretNotFound) {
			return fs.ErrNotExist
		}
		if err != nil {
			return err
		}
		info = certmagic.KeyInfo{Key: key, Modified: md.UpdatedTime, IsTerminal: true}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		// Not a secret: a "directory" when something is under it.
		if names, lerr := v.list(ctx, v.dir(key)); lerr == nil && len(names) > 0 {
			return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
		}
	}
	return info, err
}

// List lists keys under prefix, as FileStorage does: with recursive,
// "directories" and everything under them.
func (v *Vault) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	prefix = strings.Trim(prefix, "/")
	names, err := v.list(ctx, v.dir(prefix))
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, n := range names {
		dir := strings.HasSuffix(n, "/")
		k := path.Join(prefix, strings.TrimSuffix(n, "/"))
		if k == "_locks" {
			continue
		}
		keys = append(keys, k)
		if dir && recursive {
			sub, err := v.List(ctx, k, true)
			if err != nil {
				return nil, err
			}
			keys = append(keys, sub...)
		}
	}
	return keys, nil
}

func (v *Vault) list(ctx context.Context, dir string) ([]string, error) {
	var names []string
	err := v.do(ctx, func(ctx context.Context) error {
		s, err := v.c.Logical().ListWithContext(ctx, v.mount+"/metadata/"+dir)
		if err != nil {
			return err
		}
		if s == nil || s.Data == nil {
			return fs.ErrNotExist
		}
		raw, _ := s.Data["keys"].([]any)
		for _, k := range raw {
			if n, ok := k.(string); ok {
				names = append(names, n)
			}
		}
		return nil
	})
	return names, err
}

// lockTTL is how long a lock outlives an edge that died holding it. The
// holder refreshes it every third of that.
const lockTTL = time.Minute

type heldLock struct {
	path    string
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	version int
}

func (v *Vault) lockPath(name string) string {
	return v.root + "/_locks/" + strings.ReplaceAll(strings.Trim(name, "/"), "/", "_")
}

// Lock takes the lock name, waiting while another edge holds it and has
// refreshed it within lockTTL.
func (v *Vault) Lock(ctx context.Context, name string) error {
	p := v.lockPath(name)
	for {
		ver, err := v.tryLock(ctx, p)
		if err == nil {
			v.hold(name, p, ver)
			return nil
		}
		if !errors.Is(err, errLocked) {
			return err
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

var errLocked = errors.New("vault: locked")

func lockData() map[string]any {
	return map[string]any{"expires": time.Now().Add(lockTTL).Unix()}
}

// tryLock creates the lock, or takes over one whose holder stopped
// refreshing it. Both are check-and-set writes: of two edges, one wins.
func (v *Vault) tryLock(ctx context.Context, p string) (int, error) {
	var ver int
	err := v.do(ctx, func(ctx context.Context) error {
		s, err := v.kv.Put(ctx, p, lockData(), vault.WithCheckAndSet(0))
		if err == nil {
			ver = s.VersionMetadata.Version
			return nil
		}
		if !casMismatch(err) {
			return err
		}
		cur, err := v.kv.Get(ctx, p)
		if errors.Is(err, vault.ErrSecretNotFound) {
			return errLocked // released meanwhile: try again
		}
		if err != nil {
			return err
		}
		if exp, ok := expiry(cur.Data); ok && time.Now().Before(exp) {
			return errLocked
		}
		s, err = v.kv.Put(ctx, p, lockData(), vault.WithCheckAndSet(cur.VersionMetadata.Version))
		if casMismatch(err) {
			return errLocked
		}
		if err != nil {
			return err
		}
		ver = s.VersionMetadata.Version
		return nil
	})
	return ver, err
}

func expiry(data map[string]any) (time.Time, bool) {
	switch e := data["expires"].(type) {
	case float64:
		return time.Unix(int64(e), 0), true
	case interface{ Int64() (int64, error) }:
		n, err := e.Int64()
		return time.Unix(n, 0), err == nil
	}
	return time.Time{}, false
}

func (v *Vault) hold(name, p string, ver int) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &heldLock{path: p, cancel: cancel, done: make(chan struct{}), version: ver}
	v.locksMu.Lock()
	v.locks[name] = l
	v.locksMu.Unlock()
	go func() {
		defer close(l.done)
		t := time.NewTicker(lockTTL / 3)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			l.mu.Lock()
			ver := l.version
			l.mu.Unlock()
			var s *vault.KVSecret
			err := v.do(ctx, func(ctx context.Context) error {
				var err error
				s, err = v.kv.Put(ctx, p, lockData(), vault.WithCheckAndSet(ver))
				return err
			})
			if casMismatch(err) {
				return // taken over: it had expired
			}
			if err == nil {
				l.mu.Lock()
				l.version = s.VersionMetadata.Version
				l.mu.Unlock()
			}
		}
	}()
}

// Unlock releases a lock this edge holds: it deletes the lock, unless
// another edge took it over meanwhile.
func (v *Vault) Unlock(ctx context.Context, name string) error {
	v.locksMu.Lock()
	l := v.locks[name]
	delete(v.locks, name)
	v.locksMu.Unlock()
	if l == nil {
		return fmt.Errorf("vault: %s is not locked", name)
	}
	l.cancel()
	<-l.done
	return v.do(ctx, func(ctx context.Context) error {
		cur, err := v.kv.Get(ctx, l.path)
		if errors.Is(err, vault.ErrSecretNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		l.mu.Lock()
		mine := cur.VersionMetadata.Version == l.version
		l.mu.Unlock()
		if !mine {
			return nil
		}
		return v.kv.DeleteMetadata(ctx, l.path)
	})
}

var _ certmagic.Storage = (*Vault)(nil)
