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
CC      ?= cc
PKG_CONFIG ?= pkg-config
NFPM    ?= nfpm

# Package metadata (overridable). VERSION defaults to a git describe.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo 0.0.0)
PKG_ARCH ?= amd64

BIN_DIR ?= bin
SERVICE := $(BIN_DIR)/nm-ikennkt-service
EDITOR_SO := $(BIN_DIR)/libnm-vpn-plugin-ikennkt.so
AUTHDIALOG := $(BIN_DIR)/nm-ikennkt-auth-dialog

# Install locations (Debian/Pop!_OS layout; override on other distros).
DESTDIR      ?=
NM_LIBDIR    ?= /usr/lib/NetworkManager
VPN_DIR      ?= /usr/lib/NetworkManager/VPN
DBUS_POLICY  ?= /usr/share/dbus-1/system.d
# The editor .so goes in NM's (multiarch) plugin dir.
MULTIARCH    ?= $(shell $(CC) -print-multiarch 2>/dev/null)
NM_PLUGIN_DIR ?= $(if $(MULTIARCH),/usr/lib/$(MULTIARCH)/NetworkManager,/usr/lib/NetworkManager)

# The editor plugin and auth-dialog are C/libnm/GTK/libnma; built only when the
# dev packages are present (never linked into any Go binary, so the core stays
# CGO-free).
EDITOR_PKGS := libnm gtk+-3.0 gmodule-2.0
HAVE_EDITOR := $(shell $(PKG_CONFIG) --exists $(EDITOR_PKGS) 2>/dev/null && echo yes)
EDITOR_CFLAGS := -Wall -Wextra -fPIC $(shell $(PKG_CONFIG) --cflags $(EDITOR_PKGS) 2>/dev/null)
EDITOR_LIBS := $(shell $(PKG_CONFIG) --libs $(EDITOR_PKGS) 2>/dev/null)

AUTH_PKGS := libnm libnma gtk+-3.0
HAVE_AUTHDIALOG := $(shell $(PKG_CONFIG) --exists $(AUTH_PKGS) 2>/dev/null && echo yes)
AUTH_CFLAGS := -Wall -Wextra $(shell $(PKG_CONFIG) --cflags $(AUTH_PKGS) 2>/dev/null)
AUTH_LIBS := $(shell $(PKG_CONFIG) --libs $(AUTH_PKGS) 2>/dev/null)

LDFLAGS ?= -s -w

.DEFAULT_GOAL := help

## build: compile the D-Bus VPN service (CGO-free, godbus)
.PHONY: build
build: $(SERVICE)

$(SERVICE): $(shell find . -name '*.go') go.mod
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $@ ./cmd/nm-ikennkt-service

## editor: build the C/libnm GUI editor plugin (.so) if dev packages are present
.PHONY: editor
editor: $(EDITOR_SO)

$(EDITOR_SO): editor/ikennkt-editor.c
ifeq ($(HAVE_EDITOR),yes)
	@mkdir -p $(BIN_DIR)
	$(CC) -shared $(EDITOR_CFLAGS) -o $@ $< $(EDITOR_LIBS)
	@echo "Built $@"
else
	@echo "SKIP editor: install dev packages ($(EDITOR_PKGS)) — e.g. libnm-dev libgtk-3-dev"
endif

## editor-test: build + run the editor dlopen smoke test (needs a display)
.PHONY: editor-test
editor-test: $(EDITOR_SO)
ifeq ($(HAVE_EDITOR),yes)
	$(CC) -Wall $(EDITOR_CFLAGS) -o $(BIN_DIR)/editor_smoketest editor/editor_smoketest.c $(EDITOR_LIBS)
	$(BIN_DIR)/editor_smoketest $(EDITOR_SO)
else
	@echo "SKIP editor-test: editor dev packages not present"
endif

## authdialog: build the C/libnma interactive secret prompt (if deps present)
.PHONY: authdialog
authdialog: $(AUTHDIALOG)

$(AUTHDIALOG): authdialog/ikennkt-auth-dialog.c
ifeq ($(HAVE_AUTHDIALOG),yes)
	@mkdir -p $(BIN_DIR)
	$(CC) $(AUTH_CFLAGS) -o $@ $< $(AUTH_LIBS)
	@echo "Built $@"
else
	@echo "SKIP authdialog: install dev packages ($(AUTH_PKGS)) — e.g. libnm-dev libnma-dev libgtk-3-dev"
endif

## authdialog-test: build + run the auth-dialog non-interactive tests
.PHONY: authdialog-test
authdialog-test: $(AUTHDIALOG)
ifeq ($(HAVE_AUTHDIALOG),yes)
	./authdialog/authdialog_test.sh $(AUTHDIALOG)
else
	@echo "SKIP authdialog-test: dev packages not present"
endif

## all: build the service and (if possible) the editor + auth-dialog
.PHONY: all
all: build editor authdialog

## packages: build the ikennkt-nm .deb and .rpm (needs nfpm + editor/auth deps)
.PHONY: packages
packages: build editor authdialog
	@command -v $(NFPM) >/dev/null 2>&1 || { \
		echo "nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
ifneq ($(HAVE_EDITOR),yes)
	@echo "Refusing to package without the editor .so (install libnm-dev libgtk-3-dev)"; exit 1
endif
ifneq ($(HAVE_AUTHDIALOG),yes)
	@echo "Refusing to package without the auth-dialog (install libnma-dev)"; exit 1
endif
	@mkdir -p $(BIN_DIR)/pkg
	@# nfpm does not expand env vars in contents paths, so template with sed.
	sed -e 's/@VERSION@/$(VERSION)/g' -e 's/@PKG_ARCH@/$(PKG_ARCH)/g' \
	    -e 's/@MULTIARCH@/$(MULTIARCH)/g' nfpm.yaml.in > $(BIN_DIR)/nfpm.yaml
	$(NFPM) package -f $(BIN_DIR)/nfpm.yaml -p deb -t $(BIN_DIR)/pkg
	$(NFPM) package -f $(BIN_DIR)/nfpm.yaml -p rpm -t $(BIN_DIR)/pkg
	@echo "Packages in $(BIN_DIR)/pkg/:"; ls -1 $(BIN_DIR)/pkg

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

## install: install service + .name + D-Bus policy + editor .so (needs root)
.PHONY: install
install: build
	install -d $(DESTDIR)$(NM_LIBDIR) $(DESTDIR)$(VPN_DIR) $(DESTDIR)$(DBUS_POLICY)
	install -m 0755 $(SERVICE) $(DESTDIR)$(NM_LIBDIR)/nm-ikennkt-service
	install -m 0644 data/nm-ikennkt-service.name $(DESTDIR)$(VPN_DIR)/nm-ikennkt-service.name
	install -m 0644 data/nm-ikennkt-service.conf $(DESTDIR)$(DBUS_POLICY)/nm-ikennkt-service.conf
ifeq ($(HAVE_EDITOR),yes)
	@$(MAKE) editor
	install -d $(DESTDIR)$(NM_PLUGIN_DIR)
	install -m 0644 $(EDITOR_SO) $(DESTDIR)$(NM_PLUGIN_DIR)/libnm-vpn-plugin-ikennkt.so
endif
ifeq ($(HAVE_AUTHDIALOG),yes)
	@$(MAKE) authdialog
	install -m 0755 $(AUTHDIALOG) $(DESTDIR)$(NM_LIBDIR)/nm-ikennkt-auth-dialog
endif
	@echo "Installed. Reload NetworkManager:  sudo systemctl reload NetworkManager"

## uninstall: remove installed files (needs root)
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(NM_LIBDIR)/nm-ikennkt-service
	rm -f $(DESTDIR)$(NM_LIBDIR)/nm-ikennkt-auth-dialog
	rm -f $(DESTDIR)$(VPN_DIR)/nm-ikennkt-service.name
	rm -f $(DESTDIR)$(DBUS_POLICY)/nm-ikennkt-service.conf
	rm -f $(DESTDIR)$(NM_PLUGIN_DIR)/libnm-vpn-plugin-ikennkt.so
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
