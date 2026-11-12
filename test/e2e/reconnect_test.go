//go:build e2e

package e2e

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// An edge restarting: it powers off at once on the power button, even
// with a request hanging, and closes its tunnels. A dark node's tunnel
// comes back by itself once the edge listens again, graceful restart or
// hard reset, and in between the site answers 503 with Retry-After,
// never a closed connection.
func TestTunnelComesBack(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{Tap: lab.HasTap()})
	vm, web, ops := e.VM, e.Web, e.Ops
	crt, key := e.Cert(ca.RoleNode, "node1")
	vm.Publish(t, "wss", e.Roots, crt, key, lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "back")
	})), "back.example.com")
	up := func(c *assert.CollectT) {
		_, body, err := lab.Get(web, "https://back.example.com/")
		require.NoError(c, err)
		assert.Equal(c, "back", body)
	}
	require.EventuallyWithT(t, up, lab.Until(t), lab.Tick)

	// back measures from the edge answering its ops API again to the site
	// answering through its tunnel, and checks every site request between
	// got an answer: 503 with Retry-After.
	back := func(t *testing.T, within time.Duration) {
		var ready time.Time
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, _, err := lab.Get(ops, lab.OpsURL+"status")
			require.NoError(c, err)
			ready = time.Now()
		}, lab.Until(t), 20*time.Millisecond)
		quick := &http.Client{Transport: web.Transport, Timeout: 2 * time.Second}
		gap := 0
		for {
			resp, body, err := lab.Get(quick, "https://back.example.com/")
			require.NoError(t, err, "the edge listens: the site must answer")
			if resp.StatusCode == http.StatusOK && body == "back" {
				break
			}
			require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, body)
			require.Equal(t, "1", resp.Header.Get("Retry-After"))
			gap++
			require.Less(t, time.Since(ready), lab.Until(t), "the tunnel never came back")
			time.Sleep(20 * time.Millisecond)
		}
		took := time.Since(ready)
		t.Logf("tunnel back %s after the edge listened; %d requests answered 503 meanwhile", took.Round(time.Millisecond), gap)
		assert.Less(t, took, within)
	}

	step(t, "the power button powers off within seconds, a hanging request and all", func(t *testing.T) {
		go lab.Get(&http.Client{Transport: web.Transport, Timeout: 30 * time.Second}, "https://back.example.com/hang")
		time.Sleep(300 * time.Millisecond)
		start := time.Now()
		vm.PowerDown(t)
		took := time.Since(start)
		t.Logf("powered off in %s", took.Round(time.Millisecond))
		assert.Less(t, took, 5*time.Second)
	})
	step(t, "after a restart the tunnel is back within a second of the edge listening", func(t *testing.T) {
		// On a tap, this host sees the edge's own port open: probed with
		// short dials, so none waits out a SYN retransmission.
		opened := make(chan time.Time, 1)
		if lab.HasTap() {
			go func() {
				addr := net.JoinHostPort(vm.Addr, strconv.Itoa(vm.HTTPS))
				for end := time.Now().Add(lab.Until(t)); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
					if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
						opened <- time.Now()
						c.Close()
						return
					}
				}
			}()
		}
		vm.Restart(t)
		back(t, 1500*time.Millisecond)
		if lab.HasTap() {
			// The edge's ready time, by its clock as boot set it, is when
			// its port opened, by this host's: the lab's NTP is this host.
			at := <-opened
			_, body, err := lab.Get(ops, lab.OpsURL+"metrics")
			require.NoError(t, err)
			var ready float64
			for line := range strings.Lines(body) {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "fortressedge_ready_time_seconds "); ok {
					ready, _ = strconv.ParseFloat(v, 64)
				}
			}
			diff := at.Sub(time.UnixMilli(int64(ready * 1e3)))
			t.Logf("port open by this host %s after the edge's ready time", diff.Round(time.Millisecond))
			assert.Less(t, diff.Abs(), 150*time.Millisecond)
		}
	})
	step(t, "after a hard reset the tunnel comes back too", func(t *testing.T) {
		// On QEMU's user-mode network, the tunnel ends at QEMU's socket on
		// this host, which stays open and acknowledges everything while the
		// machine behind it resets: frpc cannot tell, until QEMU gives up.
		// On a tap, as on a real network, the edge's kernel is the peer.
		within := 5 * time.Second
		if !lab.HasTap() {
			within = lab.Until(t)
		}
		vm.Reset(t)
		// The edge takes a moment to go away: wait until it has.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, _, err := lab.Get(&http.Client{Transport: ops.Transport, Timeout: 200 * time.Millisecond}, lab.OpsURL+"status")
			assert.Error(c, err)
		}, lab.Until(t), 20*time.Millisecond)
		back(t, within)
	})
}

// An edge behind a load balancer stops in two stages. For three seconds
// after the power button it fails the policy's health check site itself,
// serves every other site to new connections, and closes each connection
// after its response. Only then does it close its ports and power off.
func TestStopLeavesBeforeItCloses(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{
		Policy: "limits:\n  requests_per_second: 0\n  connections_per_source: 0\n  new_connections_per_second: 0\n" +
			"sites:\n  check.example.com:\n    health_check: true\n"})
	vm, web := e.VM, e.Web
	crt, key := e.Cert(ca.RoleNode, "node1")
	vm.Publish(t, "wss", e.Roots, crt, key, lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})), "app.example.com", "check.example.com")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, host := range []string{"app.example.com", "check.example.com"} {
			resp, _, err := lab.Get(web, "https://"+host+"/")
			require.NoError(c, err)
			assert.Equal(c, http.StatusOK, resp.StatusCode, host)
		}
	}, lab.Until(t), lab.Tick)

	// fresh opens a connection for each request, as a balancer's check and
	// a new visitor do. kept reuses its connection, as a visitor who was
	// there before does, over HTTP/1, where a response says when it closes
	// the connection.
	tr := web.Transport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	fresh := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	tr = web.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	kept := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	type answer struct {
		at     time.Time
		host   string
		status int
		closes bool
		err    error
	}
	var answers []answer
	stop, probed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(probed)
		for {
			for _, host := range []string{"check.example.com", "app.example.com", ""} {
				a := answer{at: time.Now(), host: host}
				c := fresh
				if host == "" { // the visitor who was there before
					c, host = kept, "app.example.com"
				}
				resp, _, err := lab.Get(c, "https://"+host+"/")
				if a.err = err; err == nil {
					a.status, a.closes = resp.StatusCode, resp.Close
				}
				answers = append(answers, a)
			}
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	time.Sleep(time.Second)
	pressed := time.Now()
	vm.PowerDown(t)
	took := time.Since(pressed)
	close(stop)
	<-probed
	t.Logf("powered off %s after the press", took.Round(time.Millisecond))
	assert.Greater(t, took, 3*time.Second, "the edge serves for 3 s first")
	assert.Less(t, took, 8*time.Second)

	// Requests begun from 0.5 s after the press, the edge's time to notice
	// it, until 2.5 s after: well inside the stage.
	before, during := 0, 0
	for _, a := range answers {
		since, who := a.at.Sub(pressed), a.host
		if who == "" {
			who = "the kept connection"
		}
		switch {
		case since < -100*time.Millisecond:
			before++
			require.NoError(t, a.err, "%s before the press", who)
			assert.Equal(t, http.StatusOK, a.status, "%s before the press", who)
			if a.host == "" {
				assert.False(t, a.closes, "before the press the edge closed a visitor's connection")
			}
		case since > 500*time.Millisecond && since < 2500*time.Millisecond:
			during++
			require.NoError(t, a.err, "%s %s after the press: it must be served", who, since.Round(time.Millisecond))
			want := http.StatusOK
			if a.host == "check.example.com" {
				want = http.StatusServiceUnavailable
			}
			assert.Equal(t, want, a.status, "%s %s after the press", who, since.Round(time.Millisecond))
			if a.host == "" {
				assert.True(t, a.closes, "%s after the press: the response left the visitor's connection open", since.Round(time.Millisecond))
			}
		}
	}
	// Few on a busy host, where a request takes long; never none.
	assert.Greater(t, before, 2, "requests before the press")
	assert.Greater(t, during, 8, "requests while the edge left")
	t.Logf("%d requests before the press, %d while the edge left, all answered", before, during)
}
