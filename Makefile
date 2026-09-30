.PHONY: generate test build kube iso e2e load clock-soak openappsec gotestwaf bench-iso waf-bench perf-guard ci tidy tidy-check

# Three Go modules: the edge and fortressctl (root), the system tests
# (test/e2e), and fortresskube (cmd/fortresskube). Test and Kubernetes
# dependencies stay out of the edge's go.mod.
MODULES := . test/e2e cmd/fortresskube
# Reproducible and smaller: no local paths, no symbol table.
BUILDFLAGS := -trimpath -ldflags='-s -w'
# Every date in an ISO is the last commit's, so a build is reproducible
# (fortressctl iso reads it; bake dates its copy the same as its source).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null)
export SOURCE_DATE_EPOCH
E2E_TIMEOUT ?= 3m
# RUN picks system tests by name: make e2e RUN=TestCertificates
RUN ?= .
# E2E_ARGS go to the test binary: make waf-bench E2E_ARGS=-update-baselines
E2E_ARGS ?=

# V=1 shows every command and all test output. By default a run prints
# one line per package and the full output of failed tests only.
V ?= 0
ifeq ($(V),1)
Q :=
GOTESTFLAGS := -v
GOTESTSUM_FORMAT ?= standard-verbose
else
Q := @
GOTESTFLAGS :=
GOTESTSUM_FORMAT ?= pkgname-and-test-fails
endif

generate:
	$(Q)go generate ./...

test:
	$(Q)go test -race $(GOTESTFLAGS) ./...
	$(Q)go -C cmd/fortresskube test -race $(GOTESTFLAGS) ./...

build: kube
	$(Q)CGO_ENABLED=0 go build $(BUILDFLAGS) -o fortressedge ./cmd/fortressedge
	$(Q)go build $(BUILDFLAGS) -o fortressctl ./cmd/fortressctl

kube:
	$(Q)CGO_ENABLED=0 go -C cmd/fortresskube build $(BUILDFLAGS) -o $(CURDIR)/out/kube/fortresskube .

iso:
	@# /init in the initramfs has no dynamic linker; match Dockerfile ENV CGO_ENABLED=0.
	$(Q)CGO_ENABLED=0 go build $(BUILDFLAGS) -o out/fortressedge ./cmd/fortressedge
	$(Q)go build $(BUILDFLAGS) -o out/fortressctl ./cmd/fortressctl
	$(Q)os/alpine.sh out/alpine >/dev/null
	$(Q)out/fortressctl initramfs -o out/initramfs.cpio.gz --bin out/fortressedge --ca-bundle out/alpine/ca-certificates.crt --modules out/alpine/modules
	$(Q)out/fortressctl iso -o out/fortressedge.iso --kernel out/alpine/vmlinuz-virt --initramfs out/initramfs.cpio.gz

# -race covers what runs in-process: the frp fork's client, Pebble, and
# the harness. It found the fork's reconnect race.
e2e: iso
	$(Q)mkdir -p out/e2e
	$(Q)go -C test/e2e tool gotestsum --format $(GOTESTSUM_FORMAT) --junitfile $(CURDIR)/out/e2e/junit.xml -- \
		-race -tags e2e -timeout $(E2E_TIMEOUT) -run '$(RUN)' -artifacts -outputdir $(CURDIR)/out/e2e . \
		-args -iso=$(CURDIR)/out/fortressedge.iso -fortressctl=$(CURDIR)/out/fortressctl -frplog=$(CURDIR)/out/e2e/frpc.log \
		$(E2E_ARGS)

# The WAF bench: open-appsec's WAF comparison datasets (1.2 GB, about
# 1.1 million requests) and GoTestWAF, through an edge VM of WAF_CPUS and
# WAF_MEM MiB, WAF_WORKERS connections at a time. Reports, throughput and
# latency among them, go to out/waf-bench. No -race, which would slow the
# load generator; not part of ci, a workflow of its own runs it.
OPENAPPSEC_DIR := $(CURDIR)/out/openappsec
OPENAPPSEC_URL := https://downloads.openappsec.io/waf-comparison-project
GOTESTWAF_VERSION := v0.5.8
WAF_CPUS ?= 2
WAF_MEM ?= 2048
WAF_WORKERS ?= 32
WAF_TIMEOUT ?= 60m
WAF_RUN ?= ^(TestOpenAppSec|TestGoTestWAF)$$
BENCH_DIR := $(CURDIR)/out/waf-bench
# tap: the VM sits on a tap device with vhost-net in a network namespace of
# the bench's own (os/netns.sh, no root). user: QEMU's user-mode network,
# which caps the bench near 1,500 requests a second.
WAF_NET ?= tap
WAF_WRAP := $(if $(filter tap,$(WAF_NET)),$(CURDIR)/os/netns.sh)
WAF_TAP := $(if $(filter tap,$(WAF_NET)),fortress0)

# The datasets' URLs are not versioned; the pinned sums catch a new edition.
openappsec:
	$(Q)mkdir -p $(OPENAPPSEC_DIR)
	$(Q)for f in legitimate.zip malicious.zip; do \
		[ -f $(OPENAPPSEC_DIR)/$$f ] || curl -fsSL -o $(OPENAPPSEC_DIR)/$$f $(OPENAPPSEC_URL)/$$f || exit 1; \
	done
	$(Q)cd $(OPENAPPSEC_DIR) && sha256sum --quiet -c $(CURDIR)/test/e2e/testdata/openappsec.sha256

# The bench's ISO: the release build plus -tags pprof, so the bench can
# take CPU and heap profiles of the edge through the ops API.
bench-iso:
	$(Q)mkdir -p out/bench
	$(Q)CGO_ENABLED=0 go build $(BUILDFLAGS) -tags pprof -o out/bench/fortressedge ./cmd/fortressedge
	$(Q)go build $(BUILDFLAGS) -o out/fortressctl ./cmd/fortressctl
	$(Q)os/alpine.sh out/alpine >/dev/null
	$(Q)out/fortressctl initramfs -o out/bench/initramfs.cpio.gz --bin out/bench/fortressedge --ca-bundle out/alpine/ca-certificates.crt --modules out/alpine/modules
	$(Q)out/fortressctl iso -o out/bench/fortressedge.iso --kernel out/alpine/vmlinuz-virt --initramfs out/bench/initramfs.cpio.gz

# The perf guard (TestPerfGuard): what a request costs the edge in CPU and
# allocations, at a rate a 2-core CI runner sustains, against BASE (a git
# ref) when given. BASE's bench ISO is built in a worktree under out/ and
# kept in out/base-iso/<commit>.iso, which CI caches; a BASE from before
# bench-iso, or provisioned otherwise than this lab boots edges (before the
# policy API), leaves the committed baseline.
PERF_FILES ?= 5
BASE ?=
perf-guard: bench-iso
	$(Q)base_iso=; \
	if [ -n "$(BASE)" ]; then \
		sha=$$(git rev-parse --verify "$(BASE)^{commit}") || exit 1; \
		if [ -f "out/base-iso/$$sha.iso" ]; then \
			base_iso=$(CURDIR)/out/base-iso/$$sha.iso; \
			echo "perf-guard: $(BASE)'s bench ISO from out/base-iso"; \
		else \
			git worktree remove --force out/base-src 2>/dev/null; rm -rf out/base-src; \
			git worktree add --detach out/base-src "$$sha" >/dev/null || exit 1; \
			mkdir -p out/base-src/out && cp -r out/alpine out/base-src/out/ 2>/dev/null; \
			if ! grep -q OpsPolicyPath out/base-src/internal/config/config.go; then \
				echo "perf-guard: $(BASE) is provisioned otherwise than this lab boots edges; the committed baseline only"; \
			elif $(MAKE) --no-print-directory -C out/base-src bench-iso >out/base-src.log 2>&1; then \
				mkdir -p out/base-iso && cp out/base-src/out/bench/fortressedge.iso "out/base-iso/$$sha.iso"; \
				base_iso=$(CURDIR)/out/base-iso/$$sha.iso; \
			else echo "perf-guard: $(BASE) has no bench-iso (out/base-src.log); the committed baseline only"; fi; \
			git worktree remove --force out/base-src 2>/dev/null; \
		fi; \
	fi; \
	$(MAKE) --no-print-directory waf-bench WAF_RUN='^TestPerfGuard$$' \
		E2E_ARGS="-perf-files=$(PERF_FILES) -base-iso=$$base_iso $(E2E_ARGS)"

# Built from its module, which the Go checksum database vouches for; the
# module also carries the testcases and config.yaml GoTestWAF reads.
gotestwaf:
	$(Q)GOBIN=$(CURDIR)/out/tools go install github.com/wallarm/gotestwaf/cmd/gotestwaf@$(GOTESTWAF_VERSION)

waf-bench: bench-iso openappsec gotestwaf
	$(Q)rm -rf $(BENCH_DIR) && mkdir -p $(BENCH_DIR)
	@# Only the test binary runs in the network namespace, which reaches
	@# nothing outside (and where a snap-installed go refuses to run).
	$(Q)go -C test/e2e test -c -tags e2e -o $(BENCH_DIR)/e2e.test .
	$(Q)go -C test/e2e build -o $(CURDIR)/out/tools/gotestsum gotest.tools/gotestsum
	$(Q)go build -o $(CURDIR)/out/tools/test2json cmd/test2json
	$(Q)src=$$(go -C test/e2e mod download -json github.com/wallarm/gotestwaf@$(GOTESTWAF_VERSION) | sed -n 's/^\t"Dir": "\(.*\)",$$/\1/p'); \
	cd test/e2e && $(CURDIR)/out/tools/gotestsum --format standard-verbose --junitfile $(BENCH_DIR)/junit.xml --raw-command -- \
		$(WAF_WRAP) $(CURDIR)/out/tools/test2json -t -p github.com/Sebiee/fortressedge/test/e2e $(BENCH_DIR)/e2e.test -test.v=test2json \
		-test.count=1 -test.timeout=$(WAF_TIMEOUT) -test.run='$(WAF_RUN)' -test.artifacts -test.outputdir=$(BENCH_DIR) \
		-iso=$(CURDIR)/out/bench/fortressedge.iso -fortressctl=$(CURDIR)/out/fortressctl -frplog=$(BENCH_DIR)/frpc.log \
		-openappsec=$(OPENAPPSEC_DIR) -gotestwaf=$(CURDIR)/out/tools/gotestwaf -gotestwaf-src=$$src \
		-bench=$(BENCH_DIR) -vm-cpus=$(WAF_CPUS) -vm-mem=$(WAF_MEM) -workers=$(WAF_WORKERS) -tap=$(WAF_TAP) \
		-commit=$$(git rev-parse --short HEAD) $(E2E_ARGS)

# What one edge VM serves through each tunnel: requests per second,
# latency, and download throughput, with the limits off. Not part of ci;
# no -race, which would slow the load generator. LOAD_FOR is each run's length.
LOAD_FOR ?= 10s
load: iso
	$(Q)go -C test/e2e test -tags e2e -count=1 -timeout 15m -run '^TestLoad$$' -v . \
		-args -iso=$(CURDIR)/out/fortressedge.iso -fortressctl=$(CURDIR)/out/fortressctl -load=$(LOAD_FOR) 2>&1 \
		| grep -E '^(---|ok|FAIL|PASS)|load_test.go'

# An edge kept to real NTP servers (CLOCK_NTP, comma-separated; METAS's by
# default) for CLOCK_FOR, printing its offset each minute. Needs the
# internet; not part of ci.
CLOCK_FOR ?= 60m
CLOCK_NTP ?= ntp11.metas.ch,ntp12.metas.ch,ntp13.metas.ch
clock-soak: iso
	$(Q)go -C test/e2e test -tags e2e -count=1 -timeout 0 -run '^TestClockSoak$$' -v . \
		-args -iso=$(CURDIR)/out/fortressedge.iso -fortressctl=$(CURDIR)/out/fortressctl -clock=$(CLOCK_FOR) -clock-ntp=$(CLOCK_NTP) 2>&1 \
		| grep -E '^(---|ok|FAIL|PASS)|clock_test.go'

ci: tidy-check test e2e

tidy:
	$(Q)for m in $(MODULES); do go -C $$m mod tidy || exit 1; done
	$(Q)$(MAKE) --no-print-directory tidy-check

# Every go.mod is tidy, and all pin the same frp fork and yamux.
tidy-check:
	$(Q)for m in $(MODULES); do go -C $$m mod tidy -diff || exit 1; done
	$(Q)for m in $(MODULES); do grep -E '^replace github.com/(hashicorp/yamux|fatedier/frp) ' $$m/go.mod | sort | sha256sum; done | uniq | wc -l | grep -qx 1 \
		|| { echo "tidy-check: the frp and yamux replaces differ between modules"; exit 1; }
