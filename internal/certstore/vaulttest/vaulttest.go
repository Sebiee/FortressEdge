// Package vaulttest is a Vault server for tests: AppRole login and token
// renewal, and one KV v2 mount with check-and-set, metadata, and lists,
// answering as Vault does, behind TLS. A token may use only its role's
// path, as a policy would allow.
package vaulttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server is a running fake Vault.
type Server struct {
	URL   string
	CA    []byte // PEM of the server's certificate
	Mount string
	// RoleID and SecretID log in to Path.
	RoleID, SecretID, Path string

	srv  *httptest.Server
	down atomic.Bool

	mu      sync.Mutex
	tokens  map[string]time.Time // token -> expiry
	secrets map[string]*secret   // path under the mount -> secret
	Logins  atomic.Int64
	Calls   atomic.Int64
}

type secret struct {
	versions []map[string]any
	updated  time.Time
	created  time.Time
}

// Start runs a Vault on addr ("127.0.0.1:0" for any port) with a KV v2
// mount and one AppRole for path in it.
func Start(addr, mount, path string) (*Server, error) {
	s := &Server{
		Mount: mount, Path: strings.Trim(path, "/"),
		RoleID: rnd(), SecretID: rnd(),
		tokens: map[string]time.Time{}, secrets: map[string]*secret{},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	// A certificate of its own: httptest's is the same for every server.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "vaulttest"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		// The host as a lab VM reaches it too: slirp's 10.0.2.2, a tap's 10.77.0.1.
		IPAddresses: []net.IP{net.ParseIP(host), net.IPv4(10, 0, 2, 2), net.IPv4(10, 77, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.srv.Listener.Close()
	s.srv.Listener = ln
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.srv.StartTLS()
	s.URL = "https://" + ln.Addr().String()
	s.CA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return s, nil
}

func (s *Server) Close() { s.srv.Close() }

// SetDown makes the server drop every connection, as an unreachable one
// would fail, or serve again.
func (s *Server) SetDown(down bool) {
	s.down.Store(down)
	if down {
		s.srv.CloseClientConnections()
	}
}

// RevokeTokens forgets every token, as a Vault restart without storage
// would: clients must log in again.
func (s *Server) RevokeTokens() {
	s.mu.Lock()
	clear(s.tokens)
	s.mu.Unlock()
}

// Keys lists the secrets' paths under the mount, sorted.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for k := range s.secrets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Value is the latest value Store wrote at path under the mount.
func (s *Server) Value(path string) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secrets[path]
	if sec == nil {
		return nil, false
	}
	return sec.versions[len(sec.versions)-1]["value"], true
}

func rnd() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func fail(w http.ResponseWriter, code int, msg ...string) {
	if msg == nil {
		msg = []string{}
	}
	reply(w, code, map[string]any{"errors": msg})
}

func (s *Server) auth(token string) map[string]any {
	return map[string]any{"auth": map[string]any{
		"client_token": token, "lease_duration": 3600, "renewable": true, "policies": []string{"edge"},
	}}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if s.down.Load() {
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
				return
			}
		}
		fail(w, http.StatusServiceUnavailable)
		return
	}
	s.Calls.Add(1)
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case p == "auth/approle/login" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		var in struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.RoleID != s.RoleID || in.SecretID != s.SecretID {
			fail(w, http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		tok := "hvs." + rnd()
		s.mu.Lock()
		s.tokens[tok] = time.Now().Add(time.Hour)
		s.mu.Unlock()
		s.Logins.Add(1)
		reply(w, http.StatusOK, s.auth(tok))
		return
	}
	tok := r.Header.Get("X-Vault-Token")
	s.mu.Lock()
	exp, ok := s.tokens[tok]
	s.mu.Unlock()
	if !ok || time.Now().After(exp) {
		fail(w, http.StatusForbidden, "permission denied")
		return
	}
	if p == "auth/token/renew-self" {
		s.mu.Lock()
		s.tokens[tok] = time.Now().Add(time.Hour)
		s.mu.Unlock()
		reply(w, http.StatusOK, s.auth(tok))
		return
	}
	kind, rest, ok := strings.Cut(strings.TrimPrefix(p, s.Mount+"/"), "/")
	list := r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true")
	// The policy allows <path>/* only. Vault checks a list as a path that
	// ends in a slash, so the path itself can be listed.
	checked := rest
	if list && !strings.HasSuffix(checked, "/") {
		checked += "/"
	}
	if !strings.HasPrefix(p, s.Mount+"/") || !ok || !strings.HasPrefix(checked, s.Path+"/") {
		fail(w, http.StatusForbidden, "permission denied")
		return
	}
	switch {
	case kind == "data" && r.Method == http.MethodGet:
		s.read(w, rest)
	case kind == "data" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		s.write(w, r, rest)
	case kind == "metadata" && list:
		s.list(w, strings.TrimSuffix(rest, "/"))
	case kind == "metadata" && r.Method == http.MethodGet:
		s.metadata(w, rest)
	case kind == "metadata" && r.Method == http.MethodDelete:
		s.mu.Lock()
		delete(s.secrets, rest)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "unsupported")
	}
}

func (s *Server) read(w http.ResponseWriter, p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secrets[p]
	if sec == nil {
		fail(w, http.StatusNotFound)
		return
	}
	reply(w, http.StatusOK, map[string]any{"data": map[string]any{
		"data":     sec.versions[len(sec.versions)-1],
		"metadata": s.versionMeta(sec),
	}})
}

func (s *Server) versionMeta(sec *secret) map[string]any {
	return map[string]any{
		"version": len(sec.versions), "created_time": sec.updated.Format(time.RFC3339Nano),
		"deletion_time": "", "destroyed": false, "custom_metadata": nil,
	}
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, p string) {
	var in struct {
		Data    map[string]any `json:"data"`
		Options struct {
			CAS *int `json:"cas"`
		} `json:"options"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Data == nil {
		fail(w, http.StatusBadRequest, "no data provided")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secrets[p]
	cur := 0
	if sec != nil {
		cur = len(sec.versions)
	}
	if in.Options.CAS != nil && *in.Options.CAS != cur {
		fail(w, http.StatusBadRequest, "check-and-set parameter did not match the current version")
		return
	}
	now := time.Now().UTC()
	if sec == nil {
		sec = &secret{created: now}
		s.secrets[p] = sec
	}
	sec.versions = append(sec.versions, in.Data)
	sec.updated = now
	reply(w, http.StatusOK, map[string]any{"data": s.versionMeta(sec)})
}

func (s *Server) metadata(w http.ResponseWriter, p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secrets[p]
	if sec == nil {
		fail(w, http.StatusNotFound)
		return
	}
	reply(w, http.StatusOK, map[string]any{"data": map[string]any{
		"cas_required": false, "created_time": sec.created.Format(time.RFC3339Nano),
		"current_version": len(sec.versions), "delete_version_after": "0s", "max_versions": 0,
		"oldest_version": 1, "updated_time": sec.updated.Format(time.RFC3339Nano),
		"custom_metadata": nil, "versions": map[string]any{},
	}})
}

// list answers as Vault does: the names right under dir, a "directory"
// with a trailing slash; 404 when there is none.
func (s *Server) list(w http.ResponseWriter, dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for k := range s.secrets {
		rest, ok := strings.CutPrefix(k, dir+"/")
		if !ok {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1]
		}
		seen[rest] = true
	}
	if len(seen) == 0 {
		fail(w, http.StatusNotFound)
		return
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	reply(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
}
