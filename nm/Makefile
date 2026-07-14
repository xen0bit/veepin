# ikennkt — NetworkManager plugin (nested module)
#
# This module is intentionally separate from the root module so the core
# binaries (ikev2d/ikev2/testclient) stay CGO-free and dependency-free: the root
# `go build ./...` never descends here, and only this module depends on godbus.
#
#   make build      # build the D-Bus VPN service
#   make test       # test the nested module
#   sudo make install
#
# Phase 2 (the C libnm editor .so) is not built here yet; see
# ../doc/networkmanager-plugin.md.

GO      ?= go
GOFLAGS ?=

BIN_DIR ?= bin
SERVICE := $(BIN_DIR)/nm-ikennkt-service

# Install locations (Debian/Pop!_OS layout; override on other distros).
DESTDIR      ?=
NM_LIBDIR    ?= /usr/lib/NetworkManager
VPN_DIR      ?= /usr/lib/NetworkManager/VPN
DBUS_POLICY  ?= /usr/share/dbus-1/system.d

LDFLAGS ?= -s -w

.DEFAULT_GOAL := help

## build: compile the D-Bus VPN service (CGO-free, godbus)
.PHONY: build
build: $(SERVICE)

$(SERVICE): $(shell find . -name '*.go') go.mod
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $@ ./cmd/nm-ikennkt-service

## test: run the nested module's tests (needs dbus-daemon for the integration test)
.PHONY: test
test:
	$(GO) test -race ./...

## vet: run go vet on the nested module
.PHONY: vet
vet:
	$(GO) vet ./...

## fmt: gofmt the nested module
.PHONY: fmt
fmt:
	$(GO) fmt ./...

## tidy: sync this module's go.mod/go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## install: install service + .name descriptor + D-Bus policy (needs root)
.PHONY: install
install: build
	install -d $(DESTDIR)$(NM_LIBDIR) $(DESTDIR)$(VPN_DIR) $(DESTDIR)$(DBUS_POLICY)
	install -m 0755 $(SERVICE) $(DESTDIR)$(NM_LIBDIR)/nm-ikennkt-service
	install -m 0644 data/nm-ikennkt-service.name $(DESTDIR)$(VPN_DIR)/nm-ikennkt-service.name
	install -m 0644 data/nm-ikennkt-service.conf $(DESTDIR)$(DBUS_POLICY)/nm-ikennkt-service.conf
	@echo "Installed. Reload NetworkManager:  sudo systemctl reload NetworkManager"

## uninstall: remove installed files (needs root)
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(NM_LIBDIR)/nm-ikennkt-service
	rm -f $(DESTDIR)$(VPN_DIR)/nm-ikennkt-service.name
	rm -f $(DESTDIR)$(DBUS_POLICY)/nm-ikennkt-service.conf
	@echo "Removed. Reload NetworkManager:  sudo systemctl reload NetworkManager"

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

## help: list targets
.PHONY: help
help:
	@echo "ikennkt NetworkManager plugin — make targets:"
	@grep -hE '^## [a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) \
		| sed -E 's/^## ([a-zA-Z0-9_-]+): (.*)/  \1|\2/' \
		| awk -F'|' '{ printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }'
