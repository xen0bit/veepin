# veepin — NetworkManager plugin (nested module)
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
SERVICE := $(BIN_DIR)/nm-veepin-service
AUTHDIALOG := $(BIN_DIR)/nm-veepin-auth-dialog

# THE protocol list. Every veepin protocol is a separate VPN type in the OS's
# "Add VPN" list, which means one .name descriptor and one editor .so each — both
# generated from this list, so adding a protocol is a line here plus its field
# table in editor/veepin-editor.c. (One .so per protocol is forced by libnm: it
# refuses a plugin whose reported service differs from the descriptor's, and the
# factory entry point takes no service argument.)
VEEPIN_PROTOCOLS := ikev2 wireguard openvpn sstp ssh anyconnect nebula masque fortinet gp cisco l2tp

# Display names, used for the descriptor's name= and the plugin's own name
# property — kept identical to each other on purpose; see the descriptor
# template. Must match editor/veepin-editor.c's labels.
LABEL_ikev2      := IKEv2
LABEL_wireguard  := WireGuard
LABEL_openvpn    := OpenVPN
LABEL_sstp       := SSTP
LABEL_ssh        := SSH
LABEL_anyconnect := AnyConnect
LABEL_nebula     := Nebula
LABEL_masque     := MASQUE
LABEL_fortinet   := Fortinet
LABEL_gp         := GlobalProtect
LABEL_cisco      := Cisco IPsec
LABEL_l2tp       := L2TP/IPsec

EDITOR_SOS  := $(foreach p,$(VEEPIN_PROTOCOLS),$(BIN_DIR)/libnm-vpn-plugin-veepin-$(p).so)
NAME_FILES  := $(foreach p,$(VEEPIN_PROTOCOLS),$(BIN_DIR)/VPN/nm-veepin-$(p)-service.name)

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
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $@ ./cmd/nm-veepin-service

## names: generate the per-protocol NetworkManager .name descriptors
.PHONY: names
names: $(NAME_FILES)

# The label may contain a slash (L2TP/IPsec), so sed is delimited with |.
$(BIN_DIR)/VPN/nm-veepin-%-service.name: data/nm-veepin-service.name.in
	@mkdir -p $(dir $@)
	@sed -e 's|@PROTOCOL@|$*|g' -e 's|@LABEL@|$(LABEL_$*)|g' $< > $@

## editor: build one GUI editor plugin (.so) per protocol, if dev packages are present
.PHONY: editor
editor: $(if $(HAVE_EDITOR),$(EDITOR_SOS))
ifneq ($(HAVE_EDITOR),yes)
	@echo "SKIP editor: install dev packages ($(EDITOR_PKGS)) — e.g. libnm-dev libgtk-3-dev"
endif

$(BIN_DIR)/libnm-vpn-plugin-veepin-%.so: editor/veepin-editor.c
	@mkdir -p $(BIN_DIR)
	$(CC) -shared $(EDITOR_CFLAGS) -DVEEPIN_PROTOCOL='"$*"' -o $@ $< $(EDITOR_LIBS)
	@echo "Built $@"

## editor-test: build + run the editor dlopen smoke test, once per protocol (needs a display)
.PHONY: editor-test
editor-test: editor names
ifeq ($(HAVE_EDITOR),yes)
	$(CC) -Wall $(EDITOR_CFLAGS) -o $(BIN_DIR)/editor_smoketest editor/editor_smoketest.c $(EDITOR_LIBS)
	@for p in $(VEEPIN_PROTOCOLS); do \
	    rc=0; \
	    $(BIN_DIR)/editor_smoketest \
	        $(BIN_DIR)/libnm-vpn-plugin-veepin-$$p.so $$p \
	        $(BIN_DIR)/VPN/nm-veepin-$$p-service.name || rc=$$?; \
	    [ $$rc -eq 0 ] || [ $$rc -eq 77 ] || exit 1; \
	done
	@echo "All $(words $(VEEPIN_PROTOCOLS)) editor plugins OK"
else
	@echo "SKIP editor-test: editor dev packages not present"
endif

## authdialog: build the C/libnma interactive secret prompt (if deps present)
.PHONY: authdialog
authdialog: $(AUTHDIALOG)

$(AUTHDIALOG): authdialog/veepin-auth-dialog.c
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

## all: build the service, descriptors and (if possible) the editors + auth-dialog
.PHONY: all
all: build names editor authdialog

## packages: build the veepin-nm .deb and .rpm (needs nfpm + editor/auth deps)
.PHONY: packages
packages: build names editor authdialog
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
	@# The per-protocol editor .so and .name descriptor pairs. nfpm has no loop,
	@# and contents: is the last key in the template, so they are appended here
	@# from the same VEEPIN_PROTOCOLS list everything else is generated from.
	@for p in $(VEEPIN_PROTOCOLS); do \
	    printf '  - src: %s/libnm-vpn-plugin-veepin-%s.so\n    dst: /usr/lib/%s/NetworkManager/libnm-vpn-plugin-veepin-%s.so\n    file_info:\n      mode: 0644\n' \
	        "$(BIN_DIR)" "$$p" "$(MULTIARCH)" "$$p" >> $(BIN_DIR)/nfpm.yaml; \
	    printf '  - src: %s/VPN/nm-veepin-%s-service.name\n    dst: /usr/lib/NetworkManager/VPN/nm-veepin-%s-service.name\n    file_info:\n      mode: 0644\n' \
	        "$(BIN_DIR)" "$$p" "$$p" >> $(BIN_DIR)/nfpm.yaml; \
	done
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

## install: install service + .name descriptors + D-Bus policy + editor .so files (needs root)
.PHONY: install
install: build names
	install -d $(DESTDIR)$(NM_LIBDIR) $(DESTDIR)$(VPN_DIR) $(DESTDIR)$(DBUS_POLICY)
	install -m 0755 $(SERVICE) $(DESTDIR)$(NM_LIBDIR)/nm-veepin-service
	install -m 0644 $(NAME_FILES) $(DESTDIR)$(VPN_DIR)/
	install -m 0644 data/nm-veepin-service.conf $(DESTDIR)$(DBUS_POLICY)/nm-veepin-service.conf
	@# The single umbrella descriptor this replaced. Left behind it would keep
	@# offering a "veepin" VPN type whose service nothing owns any more.
	rm -f $(DESTDIR)$(VPN_DIR)/nm-veepin-service.name
	rm -f $(DESTDIR)$(NM_PLUGIN_DIR)/libnm-vpn-plugin-veepin.so
ifeq ($(HAVE_EDITOR),yes)
	@$(MAKE) editor
	install -d $(DESTDIR)$(NM_PLUGIN_DIR)
	install -m 0644 $(EDITOR_SOS) $(DESTDIR)$(NM_PLUGIN_DIR)/
endif
ifeq ($(HAVE_AUTHDIALOG),yes)
	@$(MAKE) authdialog
	install -m 0755 $(AUTHDIALOG) $(DESTDIR)$(NM_LIBDIR)/nm-veepin-auth-dialog
endif
	@echo "Installed. Reload NetworkManager:  sudo systemctl reload NetworkManager"

## uninstall: remove installed files (needs root)
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(NM_LIBDIR)/nm-veepin-service
	rm -f $(DESTDIR)$(NM_LIBDIR)/nm-veepin-auth-dialog
	rm -f $(DESTDIR)$(DBUS_POLICY)/nm-veepin-service.conf
	$(foreach p,$(VEEPIN_PROTOCOLS),\
	    rm -f $(DESTDIR)$(VPN_DIR)/nm-veepin-$(p)-service.name; \
	    rm -f $(DESTDIR)$(NM_PLUGIN_DIR)/libnm-vpn-plugin-veepin-$(p).so;)
	@# The pre-split umbrella pair, if this is upgrading over it.
	rm -f $(DESTDIR)$(VPN_DIR)/nm-veepin-service.name
	rm -f $(DESTDIR)$(NM_PLUGIN_DIR)/libnm-vpn-plugin-veepin.so
	@echo "Removed. Reload NetworkManager:  sudo systemctl reload NetworkManager"

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

## help: list targets
.PHONY: help
help:
	@echo "veepin NetworkManager plugin — make targets:"
	@grep -hE '^## [a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) \
		| sed -E 's/^## ([a-zA-Z0-9_-]+): (.*)/  \1|\2/' \
		| awk -F'|' '{ printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }'
