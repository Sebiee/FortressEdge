//go:build e2e

package e2e

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// Deploy an edge as an operator does: the release ISO baked with
// fortress.yml, a NoCloud drive as Proxmox writes one (the fqdn and the
// address), a blank disk, and later a policy. Then check the behavior an
// operator and a dark node rely on.
func TestProvisionedEdge(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{})
	vm, web, ops, caFile := e.VM, e.Web, e.Ops, e.Roots
	node1Crt, node1Key := e.Cert(ca.RoleNode, "node1")
	logsCrt, logsKey := e.Cert(ca.RoleLogs, "shipper")

	step(t, "once it is up", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			check func(t *testing.T)
		}{
			{"plain HTTP redirects to HTTPS", func(t *testing.T) { lab.Redirects(t, web) }},
			{"the frp control port is not reachable", func(t *testing.T) {
				// frps answers HTTP on its control port too (its vhost is
				// muxed there), within milliseconds. QEMU's forward always
				// accepts, so silence is what shows the port is closed.
				c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vm.Ctl)), lab.Attempt)
				require.NoError(t, err)
				defer c.Close()
				io.WriteString(c, "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\n\r\n")
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := c.Read(make([]byte, 1))
				assert.Zero(t, n, "bytes from the frp control port")
			}},
			{"a request for the site returns the dark node's page over HTTPS", func(t *testing.T) {
				vm.Tunnel(t, web, "wss", "wss.example.com", caFile, node1Crt, node1Key)
			}},
			{"a request for the site returns the dark node's page over QUIC", func(t *testing.T) {
				vm.Tunnel(t, web, "quic", "quic.example.com", caFile, node1Crt, node1Key)
			}},
			{"a dark-node certificate is refused by the ops API", func(t *testing.T) {
				resp, _, err := lab.Get(vm.Client(t, caFile, node1Crt, node1Key), lab.OpsURL+"status")
				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			}},
			{"the log cursor identifies this boot", func(t *testing.T) {
				resp, _, err := lab.Get(ops, lab.OpsURL+"logs")
				require.NoError(t, err)
				boot, _, _ := strings.Cut(resp.Header.Get("X-Log-Cursor"), ":")
				assert.Equal(t, lab.BootID(t, ops), boot)
			}},
			{"reading the log again from that cursor returns only newer lines", func(t *testing.T) {
				must := require.New(t)
				resp, first, err := lab.Get(ops, lab.OpsURL+"logs")
				must.NoError(err)
				_, next, err := lab.Get(ops, lab.OpsURL+"logs?cursor="+resp.Header.Get("X-Log-Cursor"))
				must.NoError(err)
				_, all, err := lab.Get(ops, lab.OpsURL+"logs")
				must.NoError(err)
				must.GreaterOrEqual(len(all), len(first+next))
				assert.Equal(t, first+next, all[:len(first+next)])
			}},
			{"a cursor from a boot the edge no longer has is reported as a gap", func(t *testing.T) {
				resp, _, err := lab.Get(ops, lab.OpsURL+"logs?cursor=00000000-0000-0000-0000-000000000000:0")
				require.NoError(t, err)
				assert.Equal(t, "true", resp.Header.Get("X-Log-Gap"))
			}},
			{"a cursor of now returns no lines", func(t *testing.T) {
				is := assert.New(t)
				resp, body, err := lab.Get(ops, lab.OpsURL+"logs?cursor=now")
				require.NoError(t, err)
				is.Equal(http.StatusOK, resp.StatusCode)
				is.Empty(body)
			}},
			{"status describes this edge", func(t *testing.T) {
				is := assert.New(t)
				_, body, err := lab.Get(ops, lab.OpsURL+"status")
				require.NoError(t, err)
				var s struct {
					BootID    string `json:"boot_id"`
					Tunnel    string `json:"tunnel"`
					QUIC      bool   `json:"quic"`
					LogCursor string `json:"log_cursor"`
				}
				require.NoError(t, json.Unmarshal([]byte(body), &s), body)
				is.Equal(lab.Tunnel, s.Tunnel, "the fqdn from the drive")
				is.True(s.QUIC, "quic from the ISO's fortress.yml")
				is.True(strings.HasPrefix(s.LogCursor, s.BootID+":"), "log_cursor %q for boot %q", s.LogCursor, s.BootID)
			}},
			{"following the log delivers a line written after the request", func(t *testing.T) {
				resp, err := ops.Get(lab.OpsURL + "logs?follow&cursor=now")
				require.NoError(t, err)
				defer resp.Body.Close()
				// A refused ops request is logged with its path.
				marker := rand.Text()
				lab.Get(vm.Client(t, caFile, node1Crt, node1Key), lab.OpsURL+marker)
				sc := bufio.NewScanner(resp.Body)
				for sc.Scan() {
					if strings.Contains(sc.Text(), marker) {
						return
					}
				}
				t.Fatalf("no line with %s before the stream ended: %v", marker, sc.Err())
			}},
			{"a cursor past the end of this boot's log returns no lines", func(t *testing.T) {
				is := assert.New(t)
				boot := lab.BootID(t, ops)
				resp, body, err := lab.Get(ops, lab.OpsURL+"logs?cursor="+boot+":999999999")
				require.NoError(t, err)
				is.Equal(http.StatusOK, resp.StatusCode)
				is.Empty(body)
				is.Empty(resp.Header.Get("X-Log-Gap"))
				is.NotEqual(boot+":999999999", resp.Header.Get("X-Log-Cursor"), "the next cursor is the real end")
			}},
			{"a log reader reads logs, status, and the policy, and cannot change it", func(t *testing.T) {
				logs := vm.Client(t, caFile, logsCrt, logsKey)
				lab.BootID(t, logs)
				for _, path := range []string{"logs", "policy"} {
					resp, _, err := lab.Get(logs, lab.OpsURL+path)
					require.NoError(t, err)
					assert.Equal(t, http.StatusOK, resp.StatusCode, path)
				}
				resp, _, err := put(logs, "block: [192.0.2.9]\n")
				require.NoError(t, err)
				assert.Equal(t, http.StatusForbidden, resp.StatusCode, "policy")
			}},
			{"the edge offers no certificate signing, and no config bundles", func(t *testing.T) {
				for _, path := range []string{"certs", "config"} {
					req, err := http.NewRequest(http.MethodPost, lab.OpsURL+path, strings.NewReader("name=node9"))
					require.NoError(t, err)
					resp, _, err := lab.Do(ops, req)
					require.NoError(t, err)
					assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
				}
			}},
			{"a malformed cursor is rejected", func(t *testing.T) {
				resp, _, err := lab.Get(ops, lab.OpsURL+"logs?cursor=abc")
				require.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			}},
			{"each JSON log line is one object with a line field", func(t *testing.T) {
				is := assert.New(t)
				_, body, err := lab.Get(ops, lab.OpsURL+"logs?format=ndjson")
				require.NoError(t, err)
				is.NotEmpty(body)
				for line := range strings.Lines(body) {
					var v struct {
						Line *string `json:"line"`
					}
					if is.NoError(json.Unmarshal([]byte(line), &v), line) {
						is.NotNil(v.Line, line)
					}
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				tc.check(t)
			})
		}
	})

	const limits = "limits:\n  requests_per_second: 2\n  request_burst: 2\n  ban: 0\n  new_connections_per_second: 500\n"

	var boot string
	step(t, "an edge nobody applied a policy to runs the defaults, and diff says so", func(t *testing.T) {
		boot = lab.BootID(t, ops)
		out, same := e.Diff(t, limits)
		assert.False(t, same)
		assert.Contains(t, out, "has no policy yet")
		assert.Contains(t, out, "+  requests_per_second: 2")
		assert.EqualValues(t, 150, statusLimits(t, ops)["requests_per_second"])
	})

	step(t, "a policy the edge cannot parse is refused and changes nothing", func(t *testing.T) {
		// fortressctl apply checks the file first; this is what an older
		// or careless client could send.
		for _, bad := range []string{"block: [not-an-address]\n", "quic: false\n", "limits: [\n"} {
			resp, body, err := put(ops, bad)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, body)
		}
		assert.Equal(t, boot, lab.BootID(t, ops), "same boot")
		_, same := e.Diff(t, "")
		assert.True(t, same, "still no policy")
	})

	step(t, "limits change without a reboot, and applying the same file again changes nothing", func(t *testing.T) {
		must := require.New(t)
		must.Contains(e.Apply(t, limits), "policy applied")
		must.Equal(boot, lab.BootID(t, ops), "same boot")
		st := statusLimits(t, ops)
		assert.EqualValues(t, 2, st["requests_per_second"])
		assert.EqualValues(t, 500, st["new_connections_per_second"])
		must.Contains(e.Apply(t, limits), "policy unchanged")
		out, same := e.Diff(t, limits)
		assert.True(t, same, out)

		// Port 80 answers the tunnel name with a redirect, under the same limits.
		codes := map[int]int{}
		for range 10 {
			resp, _, err := lab.Get(web, "http://"+lab.Tunnel+"/x")
			must.NoError(err)
			codes[resp.StatusCode]++
		}
		assert.Positive(t, codes[http.StatusTooManyRequests], "codes %v", codes)
		// The ops API, with its client certificate, is never rate limited.
		for range 5 {
			lab.BootID(t, ops)
		}
	})

	step(t, "the access log turns on, and off for one site, without a reboot", func(t *testing.T) {
		must := require.New(t)
		vm.Tunnel(t, web, "wss", "acc.example.com", caFile, node1Crt, node1Key)
		// A site request under limits of 2 a second: tried until it passes.
		visit := func() string {
			var id string
			must.EventuallyWithT(func(c *assert.CollectT) {
				resp, _, err := lab.Get(web, "https://acc.example.com/")
				require.NoError(c, err)
				require.Equal(c, http.StatusOK, resp.StatusCode)
				id = resp.Header.Get("Fortress-Request-Id")
			}, lab.Until(t), lab.Tick)
			return id
		}
		access := func() string {
			_, body, err := lab.Get(ops, lab.OpsURL+"access")
			must.NoError(err)
			return body
		}
		must.Contains(e.Apply(t, limits+"access_log: true\n"), "policy applied")
		must.Equal(boot, lab.BootID(t, ops), "same boot")
		logged := visit()
		must.EventuallyWithT(func(c *assert.CollectT) { assert.Contains(c, access(), logged) }, lab.Until(t), lab.Tick)

		must.Contains(e.Apply(t, limits+"access_log: true\nsites:\n  acc.example.com:\n    access_log: false\n"), "policy applied")
		quiet := visit()
		must.Contains(e.Apply(t, limits+"access_log: true\n"), "policy applied")
		logged = visit()
		must.EventuallyWithT(func(c *assert.CollectT) { assert.Contains(c, access(), logged) }, lab.Until(t), lab.Tick)
		assert.NotContains(t, access(), quiet, "logged while the site had it off")
		must.Contains(e.Apply(t, limits), "policy applied")
		must.Equal(boot, lab.BootID(t, ops), "same boot")
	})

	var firstBoot string
	step(t, "the power button shuts the machine down", func(t *testing.T) {
		resp, _, err := lab.Get(ops, lab.OpsURL+"logs")
		require.NoError(t, err)
		firstBoot = resp.Header.Get("X-Log-Cursor")
		vm.PowerDown(t)
	})

	step(t, "booting again keeps the policy, and the saved cursor reads the previous boot", func(t *testing.T) {
		must := require.New(t)
		is := assert.New(t)
		vm.Restart(t)
		must.EventuallyWithT(func(c *assert.CollectT) { lab.BootID(c, ops) }, lab.Until(t), lab.Tick)
		boot = lab.BootID(t, ops)
		is.EqualValues(2, statusLimits(t, ops)["requests_per_second"], "the policy from the disk")
		_, same := e.Diff(t, limits)
		is.True(same)
		resp, body, err := lab.Get(ops, lab.OpsURL+"logs?cursor="+firstBoot)
		must.NoError(err)
		is.Equal(http.StatusOK, resp.StatusCode)
		is.Empty(resp.Header.Get("X-Log-Gap"))
		is.NotEmpty(body, "previous boot's lines after the saved cursor")
		is.Equal(boot+":0", resp.Header.Get("X-Log-Cursor"), "next read continues at this boot's start")
	})

	step(t, "a limit the servers fix when they start reboots the edge into it", func(t *testing.T) {
		out := e.Apply(t, limits+"  max_http2_streams: 50\n")
		require.Contains(t, out, "rebooting")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.NotEqual(c, boot, lab.BootID(c, ops))
		}, lab.Until(t), lab.Tick)
		assert.EqualValues(t, 50, statusLimits(t, ops)["max_http2_streams"])
	})

	// A stored block list longer than a PUT may send: one an older edge
	// stored, or a damaged disk holds. These write it to the data disk
	// while the edge is off.
	blockList := func(second, n int) string {
		var b strings.Builder
		b.WriteString("exempt: [192.0.2.7]\nblock:\n")
		for i := range n {
			fmt.Fprintf(&b, "  - 100.%d.%d.%d\n", second, i>>8, i&255)
		}
		return b.String()
	}
	bootWith := func(t *testing.T, stored string) {
		t.Helper()
		vm.PowerDown(t)
		if stored != "" {
			storePolicy(t, filepath.Join(e.Dir, "data.img"), stored)
		}
		vm.Restart(t)
		e.WaitUp(t)
		boot = lab.BootID(t, ops)
	}

	step(t, "a policy XDP cannot swap in is refused and stays off the disk, one that reboots too", func(t *testing.T) {
		must := require.New(t)
		stored := limits + blockList(64, 12000)
		bootWith(t, stored)
		must.EqualValues(12000, opsStatus(t, ops)["blocked"])
		// 12000 in force and 8000 new are more than the 16384 XDP holds
		// while it swaps one list for the other.
		next := blockList(96, 8000)
		for _, body := range []string{limits + next, limits + "  max_http2_streams: 60\n" + next} {
			resp, msg, err := put(ops, body)
			must.NoError(err)
			assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, msg)
			assert.Contains(t, msg, "xdp block list", msg)
		}
		assert.Equal(t, boot, lab.BootID(t, ops), "same boot")
		assert.EqualValues(t, 12000, opsStatus(t, ops)["blocked"])
		bootWith(t, "")
		_, got, err := lab.Get(ops, lab.OpsURL+"policy")
		must.NoError(err)
		assert.Equal(t, stored, got, "the disk kept the policy in force")
		assert.EqualValues(t, 12000, opsStatus(t, ops)["blocked"])
	})

	step(t, "a stored block list XDP cannot hold boots the edge without it, keeping the rest, until the next apply", func(t *testing.T) {
		must := require.New(t)
		bootWith(t, limits+blockList(64, 20000))
		st := opsStatus(t, ops)
		must.EqualValues(0, st["blocked"])
		must.Len(st["policy_degraded"], 1, st["policy_degraded"])
		assert.Contains(t, st["policy_degraded"].([]any)[0], "running with no block list")
		assert.EqualValues(t, 2, st["limits"].(map[string]any)["requests_per_second"], "the stored limits")
		assert.EqualValues(t, 1, st["limits"].(map[string]any)["exempt"], "the stored exempt")
		assert.Contains(t, opsMetrics(t, ops), "\nfortressedge_policy_degraded 1\n")
		must.Contains(e.Apply(t, limits), "policy applied")
		assert.Empty(t, opsStatus(t, ops)["policy_degraded"])
		assert.Contains(t, opsMetrics(t, ops), "\nfortressedge_policy_degraded 0\n")
		assert.Equal(t, boot, lab.BootID(t, ops), "same boot")
	})

	step(t, "after the host address is blocked, the host can no longer connect", func(t *testing.T) {
		must := require.New(t)
		// XDP drops the host's ACKs from here on, so the response may not arrive.
		put(ops, limits+"block: [10.0.2.2]\n")
		// A blocked request hangs rather than failing, so give up soon: an
		// unblocked edge answers the ops API well within a second.
		quick := &http.Client{Transport: ops.Transport, Timeout: 2 * time.Second}
		must.EventuallyWithT(func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, _, err := lab.Get(quick, lab.OpsURL+"status")
			assert.Error(c, err, "slirp sends every host connection from 10.0.2.2")
		}, lab.Until(t), lab.Tick)
	})
}

// An edge that cannot start says why on the console, and powers off when
// told to: there is nothing to provision it with but a new ISO or drive.
func TestEdgeThatCannotStart(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		opts    lab.EdgeOptions
		release bool // boot the release ISO as it ships, not the baked copy
		want    []string
	}{
		{"a VM without a DNS domain: Proxmox writes its bare name as fqdn",
			lab.EdgeOptions{FQDN: "tunnel"}, false, []string{`fqdn "tunnel"`, "not a DNS name with a domain", "Proxmox"}},
		{"a VM without its NoCloud drive",
			lab.EdgeOptions{NoDrive: true}, false, []string{"no NoCloud drive"}},
		{"the release ISO as it ships",
			lab.EdgeOptions{}, true, []string{"this is the release ISO"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := lab.NewEdge(t, tc.opts)
			if tc.release {
				e.VM.ISO = lab.ReleaseISO()
			}
			e.VM.Restart(t)
			e.VM.Console(t, "cannot start")
			// Each in full: the console can be read halfway through a line.
			for _, w := range tc.want {
				e.VM.Console(t, w)
			}
			e.VM.PowerDown(t)
		})
	}
}

// put sends body as the policy, as c, without fortressctl's own checks.
func put(c *http.Client, body string) (*http.Response, string, error) {
	req, err := http.NewRequest(http.MethodPut, lab.OpsURL+"policy", strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	return lab.Do(c, req)
}

// statusLimits is /status's limits.
func statusLimits(t *testing.T, ops *http.Client) map[string]any {
	t.Helper()
	_, body, err := lab.Get(ops, lab.OpsURL+"status")
	require.NoError(t, err)
	var st struct {
		Limits map[string]any `json:"limits"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &st), body)
	return st.Limits
}

// opsStatus is /status, decoded.
func opsStatus(t *testing.T, ops *http.Client) map[string]any {
	t.Helper()
	_, body, err := lab.Get(ops, lab.OpsURL+"status")
	require.NoError(t, err)
	var st map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &st), body)
	return st
}

func opsMetrics(t *testing.T, ops *http.Client) string {
	t.Helper()
	_, body, err := lab.Get(ops, lab.OpsURL+"metrics")
	require.NoError(t, err)
	return body
}

// storePolicy writes body as the stored policy on the data disk of an
// edge that is off, with e2fsprogs' debugfs: no root, no mount.
func storePolicy(t *testing.T, disk, body string) {
	t.Helper()
	dir := t.TempDir()
	src, script := filepath.Join(dir, "policy.yml"), filepath.Join(dir, "debugfs")
	require.NoError(t, os.WriteFile(src, []byte(body), 0o600))
	require.NoError(t, os.WriteFile(script, []byte("rm fortressedge/policy.yml\nwrite "+src+" fortressedge/policy.yml\n"), 0o600))
	out, err := exec.Command("debugfs", "-w", "-f", script, disk).CombinedOutput()
	require.NoError(t, err, "%s", out)
	got, err := exec.Command("debugfs", "-R", "cat fortressedge/policy.yml", disk).Output()
	require.NoError(t, err)
	require.Equal(t, body, string(got), "debugfs: %s", out)
}
