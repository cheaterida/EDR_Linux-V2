# EDR v2 — M0 build gate
#
# Reproducible-by-default: the Go toolchain is resolved from PATH, with a
# project-local fallback so `make gate` works on this workstation.

GO      ?= $(shell command -v go 2>/dev/null || echo /home/cheater/go/bin/go)
GOFMT   ?= $(shell command -v gofmt 2>/dev/null || echo /home/cheater/go/bin/gofmt)

.PHONY: all gate fmt vet test test-race build dist capability preflight vmlinux bpf-gen datapath-build package-lab clean

DIST ?= dist
BINARIES := edr-agent edrctl edr-center edr-orchestrator edr-preflight

all: gate

# gate = the mandatory, offline, root-free checks. Must be green on a clean
# checkout. Capability tests are NOT part of gate (they may need a kernel).
gate: fmt vet test build
	@echo "gate: ✅ green"

fmt:
	@out=$$($(GOFMT) -l . 2>/dev/null); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@echo "fmt: clean"

vet:
	$(GO) vet ./...
	@echo "vet: clean"

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test -race ./... -count=1

build:
	$(GO) build ./...
	@echo "build: ok"

# dist builds every user-facing binary into DIST/.
dist:
	@mkdir -p $(DIST)
	@for b in $(BINARIES); do $(GO) build -o $(DIST)/$$b ./cmd/$$b; done
	@echo "dist: $(DIST)/{$(BINARIES)}"

# package-lab assembles a deployable tarball (bin + configs + systemd + installer).
package-lab:
	@bash scripts/package_lab.sh

# capability regenerates docs/capability-matrix.md from real code paths.
# Run in CI/VM; on a dev box it is still safe (pure Go, no privileges).
capability:
	$(GO) test ./test/capability/ -run TestCapabilityMatrix -count=1 -v

# vmlinux.h is generated from the running kernel's BTF (host-specific, not
# committed). Regenerate then recompile the probes with `make bpf-gen`.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/bpf/probes/vmlinux.h
	@echo "vmlinux: internal/bpf/probes/vmlinux.h"

bpf-gen: vmlinux
	$(GO) generate ./internal/bpf/
	@echo "bpf-gen: internal/bpf/bpf_bpfel.{go,o} regenerated"

# datapath builds the Rust data-plane helper (fanotify + response primitives).
datapath-build:
	cd datapath && cargo build --release
	@echo "datapath: datapath/target/release/edr-datapath"

# preflight builds the read-only host probe for the target architecture.
preflight:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(DIST)/edr-preflight ./cmd/edr-preflight
	@echo "preflight: $(DIST)/edr-preflight"

clean:
	$(GO) clean
	rm -f docs/capability-matrix.md
