# Development

## Layout

| Path | What |
| --- | --- |
| `cmd/fortressedge` | the edge, PID 1 of the ISO |
| `cmd/fortressctl` | the operator tool, and the ISO builder |
| `cmd/fortresskube` | frpc for Kubernetes; its own Go module |
| `bake/` | the one public package: checking and baking `fortress.yml`, for the [Terraform provider](https://github.com/Sebiee/terraform-provider-fortressedge) |
| `internal/` | the edge's packages |
| `bpf/` | the XDP filter; the compiled objects in `internal/flod` are committed |
| `os/` | the Alpine kernel fetch and the QEMU launcher |
| `test/e2e` | system tests that boot the ISO; their own Go module |
| `test/perf` | a three-VM load lab, run by hand |

The repository has three Go modules: the edge and `fortressctl` at the
root (`github.com/Sebiee/fortressedge`), `test/e2e`, and
`cmd/fortresskube`. Test tools (Pebble, QEMU control, gotestsum) and
Kubernetes' client-go never enter the edge's `go.mod`, so they cannot
change a library version the edge links. All three pin the same frp fork
with a `replace`. The Terraform provider is a repository of its own that
requires this module for `bake`: a change there that alters the bytes of
a bake needs a provider release of the same version. `make tidy` tidies all of
them, and CI fails when one is untidy or the pins differ. Dependabot opens
one grouped PR per module for minor and patch updates; the frp fork is
updated by hand. There is no committed `go.work`, so each module builds
exactly as it is released.

## Build and test

You need Go, gcc (the race detector needs cgo), `qemu-system-x86_64`,
`isolinux` and `syslinux-common` (the ISO boot loader), and `e2fsprogs`.
Docker is needed once, for `os/alpine.sh`, which fetches the kernel into
`out/alpine`. `./dev <command>` runs a command in a container with all of
these.

| Target | Does |
| --- | --- |
| `make build` | `fortressedge`, `fortressctl`, and `out/kube/fortresskube` |
| `make iso` | `out/fortressedge.iso`, dated the last commit's time (`SOURCE_DATE_EPOCH`), so the same commit builds the same bytes |
| `make test` | unit tests, with `-race`, in both code modules |
| `make e2e` | the system tests, with `-race` on what runs in-process (the frp fork's client, Pebble); `RUN=TestCertificates` picks some |
| `make load` | what one edge VM serves through each tunnel (see [Load tests](#load-tests)); not part of `ci` |
| `make waf-bench` | replay open-appsec's WAF datasets and run GoTestWAF through a larger edge VM, with throughput and latency (see [WAF bench](#waf-bench)); not part of `ci` |
| `make perf-guard BASE=<ref>` | what a request costs the edge in CPU and allocations, against `BASE` (see [Perf guard](#perf-guard)); CI runs it on every pull request |
| `make ci` | `tidy-check`, `test`, `e2e`, as CI runs them |
| `make tidy` | `go mod tidy` in every module |
| `make generate` | rebuild the BPF objects (needs clang and llvm) |

Output is short by default: one line per package, and the full output of
failed tests only. `V=1` shows every command and all test output. Binaries
are built with `-trimpath -ldflags='-s -w'`.

## System tests

Each file in `test/e2e` is a scenario that boots the real ISO in QEMU,
and they run in parallel: a provisioned edge and its policy, edges that
cannot start, proxying to dark nodes, ACME, certificate renewal, and
hostile requests. They check what users see: status codes, certificate
chains, a dark node's site answering, closed ports, the console, and
silence for unknown names. `test/e2e/lab` holds the helpers:

- **Edges** as an operator deploys them (`lab.BootEdge`): the release ISO
  baked with `fortressctl bake`, a NoCloud drive written the way Proxmox
  writes one, a blank data disk, and the test's policy applied with
  `fortressctl apply`. Each edge has its own client CA and Pebble.
- **QEMU** through `os/qemu.sh`, with host ports forwarded to the guest.
- **NTP**: the lab answers the guests' clock queries, so no test needs
  `pool.ntp.org`.
- **Pebble**, Let's Encrypt's test ACME server, in-process, one per
  edge: every certificate the edge serves comes from it. The edge trusts
  it through `acme_ca`, and its challenge checks resolve every name to the
  VM, on QEMU's user-mode network or the tap. `RenewNow` moves a certificate's ARI window into the past;
  `PebbleOptions` issues short-lived certificates without ARI, so renewal
  at the end of a lifetime runs in seconds (12-second certificates, checked
  every 250ms, as Traefik's suite does with 120-second ones).
- **frpc** in-process, as dark nodes.

Once `out/alpine` exists the suite needs no internet. It has a 3-minute
budget with KVM; without KVM, QEMU emulates the CPU and is much slower:

```sh
make ci E2E_TIMEOUT=15m
make e2e RUN=TestProxyingToDarkNodes
```

`make e2e` writes `out/e2e/junit.xml`, each VM's `serial.log`, and the
in-process frpc log `frpc.log` under `out/e2e/`; a failing test prints the
tail of its VM's log. PRs and `main` run
the unit and system tests as two parallel jobs.

### Hostile requests

`TestHostileRequests` sends what attackers and broken clients send, and
its site reads each request off the socket (`wireOrigin`), so the test
sees the bytes a gateway would get after the edge, frps and frpc. For
every request, whatever the edge does with it:

- what reaches the site is one clean HTTP/1.1 request per request the
  edge accepted (strict RFC 9112 framing and headers, the visitor's
  address in `X-Forwarded-For` and `X-Real-IP`, no `Forwarded`, no path a
  gateway could resolve another way), or a request cut short when the
  edge gave up on it partway;
- a request the edge refuses reaches nothing;
- the canary, a plain request sent next on the edge's pooled connection,
  arrives intact, so nothing was left behind for the next visitor.

The HTTP/1.1 vectors cover request smuggling (CL.TE, TE.CL, duplicate and
malformed `Content-Length`, `Transfer-Encoding` variants, broken chunks),
header syntax, the request line, `Host`, ambiguous paths, and plain HTTP
on port 80; the HTTP/2 vectors cover H2.CL, H2.TE, CRLF in fields and
pseudo-headers, and fields HTTP/2 forbids. Each pins what the visitor
gets back, so a change in the edge or in Go's parsers shows up.

## WAF bench

`make waf-bench` sends real and attack traffic through an edge VM larger
than the system tests use (`WAF_CPUS=2`, `WAF_MEM=2048` MiB by default),
to a site like `TestHostileRequests`'s that checks every request it
gets. It serves two purposes: a baseline for the WAF on the
[roadmap](roadmap.md), and a performance benchmark. It runs without
`-race`, on its own, and writes its reports to `out/waf-bench/`. The
`waf-bench` workflow runs it weekly and on demand for any branch (with
the VM's size and the connections as inputs); each run's reports are the
artifact `waf-bench-<sha>`, and the tables are on the run's summary page.
There, the outcomes are held to the baselines, but the throughput is
information only: on a 2-core runner the load generator is the limit.
What keeps the edge from getting slower is the [perf guard](#perf-guard).

- **`TestOpenAppSec`** replays open-appsec's
  [WAF comparison datasets](https://github.com/openappsec/waf-comparison-project)
  (Apache-2.0; the attacks MIT): 1,040,242 legitimate requests recorded
  from 185 real websites, and 73,924 attacks in seven categories (command
  execution, Log4Shell, Shellshock, SQL injection, path traversal, XSS,
  XXE), over `WAF_WORKERS=32` kept-open connections. `make openappsec`
  fetches the two zips (1.2 GB) into `out/openappsec` and checks them
  against `test/e2e/testdata/openappsec.sha256`, since their URLs are not
  versioned. What became of each class (the legitimate set, and each
  attack category) is pinned in `testdata/openappsec-baseline.json`; a WAF
  should move the attack numbers and leave the legitimate ones be.
  `openappsec-outcomes.jsonl` lists every request not forwarded as sent,
  which for the legitimate set are false positives.
- **`TestGoTestWAF`** runs [GoTestWAF](https://github.com/wallarm/gotestwaf)
  (MIT, pinned in the Makefile, built from its module) through an
  in-process CONNECT proxy to the edge: its OWASP, OWASP API and community
  payloads in every encoding and place in a request it knows, and its
  false-positive set. It counts a `403` as blocked, so today its score is
  0%: it will be the WAF's certification. Its JSON, HTML and CSV reports
  are kept, and its summary is pinned in `testdata/gotestwaf-baseline.json`.

The VM sits on a tap device with vhost-net (`WAF_NET=tap`, the default),
so packets between it and the host stay in the kernel. `os/netns.sh` makes
the tap in a network namespace of the bench's own, from an unprivileged
user namespace: no root, nothing on the host's network, and nothing
outside reachable from inside, so the Makefile builds the test binary
first and runs only it there. Ubuntu 24.04 allows such namespaces only
with `sysctl kernel.apparmor_restrict_unprivileged_userns=0`, which the
workflow sets; `/dev/vhost-net` must be writable (group `kvm`), or the tap
runs without vhost. `WAF_NET=user` uses QEMU's user-mode network instead,
which caps the bench near 1,500 requests a second whatever the VM's size:
it carries every byte through QEMU's own TCP stack, twice (visitor to
edge, edge to the in-process dark node).

For each set, `openappsec-bench.json` records requests per second, bytes
sent and received, latency percentiles, the VM's size and network, the
host's CPUs, the commit, and the edge's `/~!ops/status` at the end.
Compare it across workflow runs with the same VM size, network, and
runner. The load generator, the dark node, and the site share the host's
CPUs, so a bigger VM needs a bigger runner to show.

A run on tap takes about 4 minutes with KVM. On a 22-CPU laptop the
legitimate set runs at about 6,300 requests a second over 32 connections
(p50 4.4 ms, p99 15 ms), about 7,200 over 64, with the VM's 2 vCPUs close
to saturated. `host CPUs busy` in the summary is how many of the host's
CPUs the test process (load generator, dark node, and site) kept busy:
near the host's count, as on a 2-core CI runner, the host set the
number, not the edge, so compare such runs only with each other. A new
connection reset before any answer is sent again once and counted under
`retries`. What the first runs found is under
[Edge WAF](roadmap.md#edge-waf).

The bench boots `out/bench/fortressedge.iso` (`make bench-iso`): the
release build with `-tags pprof`, whose ops API serves `net/http/pprof`
to an operator. 10 seconds into the legitimate set it takes a 2-second
execution trace of the edge, a 20-second CPU profile, and a heap profile,
into `edge.trace`, `edge-cpu.pprof`, and `edge-heap.pprof`. The trace shows
where requests wait rather than run (`go tool trace -pprof=sched`). For a
quicker measurement while optimizing, replay the first files of each set,
the same ones each run (130 are about 230,000 requests); the outcomes are
then not held to the baseline. Runs of the same code differ by about 3%.

```sh
make waf-bench WAF_RUN='^TestOpenAppSec$$' WAF_WORKERS=64 E2E_ARGS=-oas-files=130
go tool pprof -top out/waf-bench/edge-cpu.pprof
```

`-tunnel=quic` puts the bench's dark node on QUIC instead of a WebSocket.
`TestCeiling` is the reference for all of this: how many requests a
second the same VM answers when it proxies nothing (an ops route of the
bench ISO), about 24,000 over HTTP/1.1 on that laptop:

```sh
make waf-bench WAF_RUN='^TestCeiling$$' WAF_WORKERS=64 E2E_ARGS=-ceiling=20s
```

After a deliberate change to what the edge forwards or refuses:

```sh
make waf-bench E2E_ARGS=-update-baselines
```

### Perf guard

Requests a second on a shared, 2-core CI runner measure the runner, so
the perf guard measures work instead. `TestPerfGuard` replays the first
10 files of open-appsec's legitimate set (18,277 requests) at 1,000
requests a second, which such a runner sustains, and reads what the edge
process spent meanwhile: CPU time and allocations per request (the bench
ISO's `/~!ops/pprof/metrics`), with the visitors' p50 and p99 for
information. `make perf-guard BASE=<ref>` builds `<ref>`'s bench ISO in a
worktree under `out/` and boots it and this tree's in turn, 5 rounds each,
back to back. It fails when a request costs more than 20% more CPU than
on the base, taken as the median of each round's ratio, since noise drifts
but hits a round's two builds alike, or more than 10% more allocations or
bytes allocated, or when the edge's peak RSS (`VmHWM`, the most memory
it held) is more than 15% above the base's. Allocations and peak RSS
barely move between runs or machines, so they are also held to
`test/e2e/testdata/perf-baseline.json`; a base from before the perf guard,
or one provisioned otherwise than the lab boots edges (before the policy
API), is compared with that file only. The live heap after the last GC is in
the table too, but only for information: it depends on the requests in
flight when that GC ran, and moved about 20% between rounds of the same
code, where peak RSS moved about 8%.

On a laptop confined to 2 CPUs (`taskset -c 0,1`), the same code against
itself came out at −6% CPU and ±0% allocations, with single rounds
between −19% and +8%; a request made about 35% dearer by hashing 192 KiB
failed at +36.5%; 32 MiB held from boot failed at +209% peak RSS, since
the edge collects garbage at five times the live heap. CI runs it on
every pull request against its base, and
on `main` against the commit before, and posts the table on the run's
summary page. After a change that allocates more on purpose:

```sh
make perf-guard BASE=main E2E_ARGS=-update-baselines
```

## Load tests

### One VM: `make load`

`make load` boots the ISO in QEMU as the system tests do (1 vCPU,
512 MB, KVM), publishes a small and a 1 MiB site through a `wss` and a
QUIC dark node, and loads each from this host with the limits off:
requests per second and latency for small responses over HTTP/2 and
HTTP/1.1 at 10 and 50 concurrent requests, then download throughput.
`LOAD_FOR=30s` makes each run longer (default 10s). It prints a table and
fails only when nothing gets through; errors are grouped by message.

The load crosses QEMU's user-mode network, which costs something too, so
the numbers are a floor and are best compared with each other: run it
before and after a change on the same machine. Reference, 2026-09-24 on
a 22-thread workstation:

| Tunnel | Small requests | p50 / p99 at 50 concurrent | 1 MiB downloads |
| --- | --- | --- | --- |
| `wss` | 1,450–1,660 req/s | 31–33 ms / 54–59 ms | 59 MB/s |
| QUIC | 1,470–1,730 req/s | 28–30 ms / 56–58 ms | 27 MB/s |

Before XDP stopped counting QUIC data packets, QUIC downloads were capped
at 5 MB/s.

At 50 concurrent requests, a few in 15,000 fail with `connection reset by
peer`, all on new connections in the first second of a run, when 50 open
at once. They are the lab's, not the edge's: QEMU forwards the ports from
a listening socket on the host, whose accept queue overflows (the host's
`ListenOverflows` rises), while the edge's kernel counters in
`/~!ops/status` (`kernel_tcp`: accept queue overflows and drops, SYN
cookies) stay at zero and its TLS server sees no failed handshake. The
test prints both. The same overflow can reset a connection when a system
test's parallel steps open many at once.

### Three VMs: `test/perf`

Three VMs: the edge, a dark node running `test/perf/compose.yaml` (frpc
and three origins), and a load generator. The edge's certificates come
from an ACME server of the lab's own (step-ca, or Pebble with
`PEBBLE_VA_ALWAYS_VALID=1`), which issues for `tunnel.example.com` and
`a`, `b`, `c.example.com`:

```sh
./fortressctl ca init out/tls
./fortressctl ca client out/tls spiffe://tunnel.example.com/node/node1
```

`test/perf/vms.sh` configures the dark node and the load generator from a
workstation that can ssh to both, and writes what the edge boots from: a
baked ISO, the files of its NoCloud drive, and `policy.yml`. The edge has
no shell. All load comes from one address, so the policy lists the load
generator under `exempt`; without it, the per-source limits would be what
you measure.

```sh
EDGE=192.0.2.10 DARK=root@192.0.2.20 LOAD=root@192.0.2.30 TLS=out/tls \
  ACME=https://ca.lab:9000/acme/acme/directory ROOTS=root.crt ISO=out/fortressedge.iso test/perf/vms.sh
EDGE=192.0.2.10 CA=root.crt test/perf/loadgen.sh
RATE=0 WORKERS=50 DURATION=30s EDGE=192.0.2.10 CA=root.crt test/perf/loadgen.sh
```

`loadgen.sh` checks the 308 redirect and that each hostname returns its
own origin, then runs [vegeta](https://github.com/tsenart/vegeta) over
HTTP/2. `RATE=0` is unbounded.

## Releases

Push an annotated `v*.*.*` tag; a lightweight one fails
`gh release create --verify-tag`. The release job runs `make ci`, then
attaches the ISO it just tested, `fortressctl`, `fortresskube`, and
`SHA256SUMS`, and pushes the `fortresskube` image.

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
sha256sum -c SHA256SUMS
```
