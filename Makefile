# veepin — Makefile
#
# A pure-Go userspace IKEv2 VPN (server + client). This Makefile drives the
# common build, test, benchmark, quality and packaging workflows.
#
#   make            # list available targets (same as `make help`)
#   make build      # build all three binaries into ./bin
#   make test       # run the test suite with the race detector
#   make setcap     # grant the built binaries CAP_NET_ADMIN (needs sudo)
#
# Run `make help` for the full, self-documenting target list.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Toolchain. Override to test against a specific Go, e.g. `make GO=go1.26 build`.
GO      ?= go
GOFLAGS ?=

# Output layout.
BIN_DIR    ?= bin
COVER_DIR  ?= coverage
DIST_DIR   ?= dist

# Install location for `make install` / `make uninstall`.
PREFIX     ?= /usr/local
INSTALL_BIN := $(DESTDIR)$(PREFIX)/bin

# The commands this module ships (cmd/<name> -> bin/<name>). One binary with
# connect/serve/probe subcommands, so protocols do not multiply binaries.
CMDS    := veepin
BINS    := $(addprefix $(BIN_DIR)/,$(CMDS))

# `veepin connect` and `veepin serve` open a TUN device (and connect edits the
# routing table), which needs CAP_NET_ADMIN. `veepin probe` is userspace-only and
# needs no capability, but they are one binary now, so the capability is granted
# once.
CAP_BINS := veepin

# Version stamping. Derived from git; overridable (`make VERSION=1.2.3 build`).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Inject build metadata into main.version/main.commit/main.date when those
# variables exist. `-X` on an absent symbol is silently ignored, so this stays
# harmless if a main package doesn't declare them.
#
# The linker symbol for a main package's variable is main.<name>, not
# <importpath>.<name>; the latter matches nothing and, because -X on an unknown
# symbol is ignored, fails silently. .goreleaser.yaml uses the same form, so
# `make build` and released binaries stamp identically.
define stamp
-X 'main.version=$(VERSION)' \
-X 'main.commit=$(COMMIT)' \
-X 'main.date=$(DATE)'
endef

# Release builds strip the symbol table and DWARF for smaller binaries.
LDFLAGS        ?=
RELEASE_LDFLAGS := -s -w

# Optional external tools (used if installed; targets explain how to get them).
GOLANGCI_LINT ?= golangci-lint
STATICCHECK   ?= staticcheck
GOVULNCHECK   ?= govulncheck

# Cross-compilation pass-through. NOTE: the TUN data path and route
# installation are Linux-only; other platforms compile but OpenTUN/route setup
# return errors at runtime. The IKE/handshake code itself is portable.
GOOS   ?=
GOARCH ?=
export GOOS GOARCH

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

## build: compile all binaries into ./bin
.PHONY: build
build: $(BINS)

# Per-binary rule. Rebuilds when any Go source changes.
GO_SOURCES := $(shell find . -type f -name '*.go' -not -name '*_test.go')
$(BIN_DIR)/%: $(GO_SOURCES) go.mod
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS) $(call stamp,$*)" -o $@ ./cmd/$*

## release: build all binaries with stripped, optimized flags
.PHONY: release
release: LDFLAGS := $(RELEASE_LDFLAGS)
release: clean-bin build
	@echo "Release binaries ($(VERSION)) in $(BIN_DIR)/"

## install: install binaries to $(PREFIX)/bin (override PREFIX/DESTDIR)
.PHONY: install
install: build
	@mkdir -p $(INSTALL_BIN)
	@for c in $(CMDS); do \
		echo "install $(BIN_DIR)/$$c -> $(INSTALL_BIN)/$$c"; \
		install -m 0755 $(BIN_DIR)/$$c $(INSTALL_BIN)/$$c; \
	done

## uninstall: remove installed binaries from $(PREFIX)/bin
.PHONY: uninstall
uninstall:
	@for c in $(CMDS); do \
		echo "rm $(INSTALL_BIN)/$$c"; \
		rm -f $(INSTALL_BIN)/$$c; \
	done

## setcap: grant CAP_NET_ADMIN to the veepin binary (needs sudo)
.PHONY: setcap
setcap: build
	@for c in $(CAP_BINS); do \
		echo "setcap cap_net_admin+ep $(BIN_DIR)/$$c"; \
		sudo setcap cap_net_admin+ep $(BIN_DIR)/$$c; \
	done
	@echo "Done. $(CAP_BINS) can now open a TUN device without root."

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

## test: run all tests with the race detector
.PHONY: test
test:
	$(GO) test -race $(GOFLAGS) ./...

## test-short: run the fast subset (-short, no race detector)
.PHONY: test-short
test-short:
	$(GO) test -short $(GOFLAGS) ./...

## interop: Docker-based interop tests vs strongSwan + wireguard-go (needs Docker; not in `test`)
.PHONY: interop
interop:
	$(GO) test -tags interop -count=1 -timeout 20m ./tests/interop/...

## test-v: run all tests verbosely with the race detector
.PHONY: test-v
test-v:
	$(GO) test -race -v $(GOFLAGS) ./...

## cover: run tests with coverage and write an HTML report
.PHONY: cover
cover:
	@mkdir -p $(COVER_DIR)
	$(GO) test $(GOFLAGS) -covermode=atomic -coverprofile=$(COVER_DIR)/cover.out ./...
	$(GO) tool cover -html=$(COVER_DIR)/cover.out -o $(COVER_DIR)/cover.html
	@$(GO) tool cover -func=$(COVER_DIR)/cover.out | tail -n 1
	@echo "HTML report: $(COVER_DIR)/cover.html"

# ---------------------------------------------------------------------------
# Benchmarks (delegate to the project's bench.sh so behaviour stays consistent)
# ---------------------------------------------------------------------------

## bench: run the full benchmark suite (via bench.sh)
.PHONY: bench
bench:
	./bench.sh

## bench-esp: run only the ESP data-plane benchmarks
.PHONY: bench-esp
bench-esp:
	BENCH=ESP ./bench.sh

## bench-long: run benchmarks with a longer benchtime for stable numbers
.PHONY: bench-long
bench-long:
	./bench.sh -benchtime 3s

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

## fmt: format all Go source with gofmt
.PHONY: fmt
fmt:
	$(GO) fmt ./...

## fmt-check: fail if any file is not gofmt-clean (for CI)
.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi; \
	echo "gofmt: clean"

## vet: run go vet
.PHONY: vet
vet:
	$(GO) vet ./...

## lint: run golangci-lint if installed
.PHONY: lint
lint:
	@if command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		$(GOLANGCI_LINT) run ./...; \
	else \
		echo "$(GOLANGCI_LINT) not found; install: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi

## staticcheck: run staticcheck if installed
.PHONY: staticcheck
staticcheck:
	@if command -v $(STATICCHECK) >/dev/null 2>&1; then \
		$(STATICCHECK) ./...; \
	else \
		echo "$(STATICCHECK) not found; install: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
		exit 1; \
	fi

## vulncheck: scan for known vulnerabilities with govulncheck
.PHONY: vulncheck
vulncheck:
	@if command -v $(GOVULNCHECK) >/dev/null 2>&1; then \
		$(GOVULNCHECK) ./...; \
	else \
		echo "$(GOVULNCHECK) not found; install: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
		exit 1; \
	fi

## tidy: sync go.mod/go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## tidy-check: fail if `go mod tidy` would change anything (for CI)
.PHONY: tidy-check
tidy-check:
	@cp go.mod go.mod.bak; [ -f go.sum ] && cp go.sum go.sum.bak || true; \
	$(GO) mod tidy; \
	rc=0; \
	cmp -s go.mod go.mod.bak || rc=1; \
	{ [ -f go.sum ] && [ -f go.sum.bak ] && ! cmp -s go.sum go.sum.bak && rc=1; } || true; \
	mv go.mod.bak go.mod; [ -f go.sum.bak ] && mv go.sum.bak go.sum || true; \
	if [ $$rc -ne 0 ]; then echo "go.mod/go.sum are not tidy; run 'make tidy'"; exit 1; fi; \
	echo "go.mod/go.sum: tidy"

## check: fmt-check + vet + test (the standard pre-commit gate)
.PHONY: check
check: fmt-check vet test

## ci: the full gate run in CI (tidy + format + vet + build + test)
.PHONY: ci
ci: tidy-check fmt-check vet build test

# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

## dist: build a stripped tarball of the binaries under ./dist
.PHONY: dist
dist: release
	@mkdir -p $(DIST_DIR)
	@os=$${GOOS:-$$($(GO) env GOOS)}; arch=$${GOARCH:-$$($(GO) env GOARCH)}; \
	name=veepin-$(VERSION)-$$os-$$arch; \
	tar -C $(BIN_DIR) -czf $(DIST_DIR)/$$name.tar.gz $(CMDS); \
	echo "Wrote $(DIST_DIR)/$$name.tar.gz"

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

## clean: remove build, coverage and dist artifacts
.PHONY: clean
clean: clean-bin
	rm -rf $(COVER_DIR) $(DIST_DIR)
	$(GO) clean -cache -testcache >/dev/null 2>&1 || true

.PHONY: clean-bin
clean-bin:
	rm -rf $(BIN_DIR)

## tools: install the optional lint/security tooling
.PHONY: tools
tools:
	$(GO) install honnef.co/go/tools/cmd/staticcheck@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "For golangci-lint see https://golangci-lint.run/usage/install/"

## help: list available targets
.PHONY: help
help:
	@echo "veepin — make targets (version $(VERSION)):"
	@echo
	@grep -hE '^## [a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) \
		| sed -E 's/^## ([a-zA-Z0-9_-]+): (.*)/  \1|\2/' \
		| awk -F'|' '{ printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }'
	@echo
	@echo "Common overrides: GO=, VERSION=, PREFIX=, GOOS=, GOARCH=, GOFLAGS="
