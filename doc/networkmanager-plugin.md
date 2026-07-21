# NetworkManager plugin for veepin

Design document and implementation plan for integrating the veepin VPN client
(`./ikev2`) into NetworkManager, so a Linux desktop (GNOME / Pop!\_OS) can bring
the tunnel up and down from its native VPN UI — **without** depending on
strongSwan or the `network-manager-strongswan` packages.

Status: **complete — all phases implemented.** The public `client` facade, a
hardened D-Bus VPN service, the C/libnm **graphical Add-VPN form** (with
saved-secret support), the interactive **auth-dialog** (for "ask every time"
secrets), and **`.deb`/`.rpm` packaging** all exist and are tested. See
[§13 Implementation status](#13-implementation-status--runbook) for what is built
and how to run it.

---

## 1. Goals and constraints

**Goal.** A NetworkManager VPN type, "IKEv2 (veepin)", that:

- appears alongside OpenVPN / WireGuard / PPTP in the desktop VPN UI (eventually)
  and, at minimum, is toggleable from the GNOME quick-settings VPN menu;
- reuses the existing `internal/ike` client to perform the RFC 7296 handshake
  and run the ESP data path;
- lets **NetworkManager** own addressing, routing and DNS (rather than the
  client installing routes itself, as `cmd/ikev2` does today);
- carries no dependency on strongSwan or any untrusted VPN package.

**Hard constraints.**

1. **The shipped binaries `ikev2d`, `ikev2`, `testclient` remain CGO-free.** This
   is non-negotiable: it is what lets GoReleaser build fully static, dependency-
   light binaries for `linux/{amd64,arm64,arm}` (see `.goreleaser.yaml`, which
   pins `CGO_ENABLED=0`).
2. **The root Go module stays dependency-free** (stdlib only). The README's
   "no external dependencies" claim must remain true for the core.
3. The NM plugin **may** use CGO, C, a C toolchain, and third-party Go modules —
   but only in code that the three core binaries never import and that the root
   build never compiles.

The rest of this document is largely about **how constraints 1–2 are guaranteed
structurally**, not merely by convention.

---

## 2. Background: how a NetworkManager VPN plugin is built

NetworkManager does not run "any VPN binary". A VPN *type* is a **D-Bus service**
implementing `org.freedesktop.NetworkManager.VPN.Plugin`. A complete plugin is up
to four artifacts:

| Artifact | Role | Required? |
|----------|------|-----------|
| **`.name` descriptor** | keyfile in `/usr/lib/NetworkManager/VPN/` telling NM the service name, the daemon to spawn, and where the GUI pieces live | **yes** |
| **VPN service daemon** | the binary NM spawns (as **root**) and drives over D-Bus; actually establishes the tunnel | **yes** |
| **GUI editor plugin** (`.so`) | a GObject/`libnm` shared library `dlopen`-ed by the connection editor to draw the config form | no (for the graphical *Add VPN* form) |
| **auth-dialog** | small helper NM runs to prompt for secrets interactively | no (secrets can be provisioned non-interactively) |

The two mandatory artifacts get a *working, NM-managed* connection. The two
optional ones add the polished graphical *configuration* experience.

### 2.1 The D-Bus contract

The daemon exports object `/org/freedesktop/NetworkManager/VPN/Plugin`,
interface `org.freedesktop.NetworkManager.VPN.Plugin`:

- **Methods NM calls on the daemon:**
  - `Connect(a{sa{sv}} connection)` — start, given the full connection settings.
  - `ConnectInteractive(a{sa{sv}} connection, a{sv} details)` — start, interactive
    secrets allowed.
  - `NeedSecrets(a{sa{sv}} connection) → s` — return the name of the setting whose
    secrets are still needed, or `""`.
  - `NewSecrets(a{sa{sv}} connection)` — secrets supplied after `SecretsRequired`.
  - `Disconnect()` — tear down.
- **Signals the daemon emits to NM:**
  - `StateChanged(u state)` — lifecycle (see enum below).
  - `Config(a{sv})` — generic tunnel config (`tundev`, `mtu`, `has-ip4`, …).
  - `Ip4Config(a{sv})` — IPv4 address/DNS/routes for NM to apply.
  - `Ip6Config(a{sv})` — (unused; veepin is IPv4-only).
  - `SecretsRequired(s message, as hints)` — ask NM's secret agent for more.
  - `Failure(u reason)` — fatal error.
- **Property:** `State (u)`.

**Key architectural consequence:** config flows *from* the daemon *to* NM via the
`Config` / `Ip4Config` signals, and **NM applies the addressing and routing.**
The daemon reports the tunnel; it does not `ip addr`/`ip route`. This is the
inverse of `cmd/ikev2/main.go` today, and it is a simplification — NM handles the
default route, the host-route-to-gateway (so ESP does not recurse into the
tunnel), DNS registration, and `never-default` for split tunneling.

### 2.2 Relevant enums (verify against `nm-vpn-dbus-interface.h`)

```
NM_VPN_SERVICE_STATE:  UNKNOWN=0 INIT=1 SHUTDOWN=2 STARTING=3 STARTED=4 STOPPING=5 STOPPED=6
NM_VPN_PLUGIN_FAILURE: LOGIN_FAILED=0 CONNECT_FAILED=1 BAD_IP_CONFIG=2
```

These integers must be emitted in the order NM expects or it will treat the
plugin as hung. Do not hard-code from memory — generate them from, or assert them
against, the installed header at build time.

### 2.3 `Ip4Config` dict keys we populate

| Key | Sig | Source in veepin |
|-----|-----|-------------------|
| `address` | `u` | `ClientResult.AssignedIP` (network byte order uint32) |
| `prefix` | `u` | prefix length derived from `ClientResult.Netmask` |
| `gateway` | `u` | resolved server outer IP |
| `dns` | `au` | `ClientResult.DNS` |
| `mtu` | `u` | tunnel MTU (compute from outer MTU − ESP/UDP overhead) |
| `never-default` | `b` | `!full-tunnel` |
| `routes` | `aau` | optional split-tunnel routes |

`Config` additionally carries `tundev` (`s`, from `TUN.Name()`) and `has-ip4=true`,
`has-ip6=false`.

---

## 3. What the core already provides

The client is already close to what the plugin needs — the plugin is mostly a
D-Bus shell around existing code:

| Plugin needs | Already in tree |
|--------------|-----------------|
| Reusable in-process client | `internal/ike.Client` → `Connect()` returns `ClientResult` |
| Assigned IP / netmask / DNS | `ClientResult.AssignedIP` / `.Netmask` / `.DNS` |
| TUN device name | `dataplane.TUN.Name()` |
| Run data path without touching routes | `cmd/ikev2 -no-route` already does this |
| Config knobs (server, psk, id, user/pass, server-id, full-tunnel) | existing `cmd/ikev2` flags |

**Deltas required in the core (all CGO-free, all in the root module):**

- **D1 — Public client facade.** Promote the handshake+datapath wiring currently
  inlined in `cmd/ikev2/main.go` into a small **public** package so external code
  can drive a session without reaching into `internal/`. Proposed
  `client` package (`github.com/xen0bit/veepin/client`) exposing:

  ```go
  type Config struct {
      Server, PSK, LocalID, ServerID string
      EAPUser, EAPPassword           string
      TUNName                        string // "" = kernel picks
  }
  type Session struct { /* ... */ }
  type Result struct {
      TUNName    string
      AssignedIP net.IP
      Netmask    net.IP
      Gateway    net.IP   // server outer IP (for NM's host route)
      DNS        []net.IP
      MTU        int
  }
  // Dial performs the handshake, brings up the TUN, and starts the ESP pump
  // WITHOUT installing any routes/addresses. The caller (or NM) does that.
  func Dial(ctx context.Context, cfg Config) (*Session, Result, error)
  func (s *Session) Wait() error   // blocks until the tunnel drops / ctx cancels
  func (s *Session) Close() error  // tears down pump + TUN
  ```

  `cmd/ikev2/main.go` is then refactored to call this facade (its route
  installation stays in the command, not the library). This keeps `internal/`
  private and gives the NM module a stable, CGO-free surface to import. It also
  benefits any third-party embedder.

- **D2 — Netmask→prefix and MTU helpers** (trivial; live in `client`).

Nothing here adds a dependency or CGO to the core.

---

## 4. Architecture and isolation strategy

The plugin lives in a **nested Go module** rooted at `nm/`, plus C sources for the
libnm pieces. This is the mechanism that *structurally* guarantees constraints
1–2.

```
veepin/                      # ROOT MODULE — zero deps, CGO_ENABLED=0
├── go.mod                    #   github.com/xen0bit/veepin   (unchanged: stdlib only)
├── client/                   #   NEW public facade (D1) — CGO-free, no deps
├── cmd/{ikev2d,ikev2,testclient}
├── internal/...
└── nm/                       # NESTED MODULE — may use deps + CGO/C
    ├── go.mod                #   github.com/xen0bit/veepin/nm
    │                         #   require github.com/xen0bit/veepin  (+ replace ../)
    │                         #   require github.com/godbus/dbus/v5
    ├── cmd/
    │   └── nm-veepin-service/   # the D-Bus VPN daemon (Go + godbus, CGO-free)
    ├── internal/
    │   ├── dbusplugin/       # NM VPN.Plugin contract impl over godbus
    │   └── nmconfig/         # connection-dict <-> client.Config mapping
    ├── editor/               # GUI editor plugin — C against libnm (built by gcc)
    │   ├── veepin-editor.c
    │   └── Makefile
    ├── authdialog/           # optional secret-prompt helper (C or Go)
    ├── data/
    │   ├── nm-veepin-service.name          # NM VPN descriptor
    │   └── nm-veepin-service.conf          # D-Bus system policy
    └── Makefile              # builds the nested module + C artifacts + packaging
```

### 4.1 Why a nested module (and not build tags)

- **`go build ./...`, `go test ./...`, `go vet ./...` at the repo root never
  descend into `nm/`** — a nested module is invisible to the parent module's
  package pattern. So root CI, the Makefile, and GoReleaser cannot accidentally
  pull godbus or trigger CGO. The invariant holds by construction, not vigilance.
- The root `go.mod` stays byte-for-byte dependency-free; only `nm/go.mod` lists
  godbus.
- The nested module imports the core via
  `require github.com/xen0bit/veepin v0.0.0` + `replace github.com/xen0bit/veepin => ../`.
  It imports the **public** `client` package (D1), not `internal/` — clean across
  the module boundary and not reliant on the `internal` path exemption.

A single-module + `//go:build cgo` / build-tag approach was considered and
rejected: it keeps CGO out of the default build but still pollutes the root
`go.mod` with godbus and makes "is the core really dep-free?" a matter of tags
rather than structure.

### 4.2 The CGO question, precisely

With the relaxed constraint, where does CGO/C actually appear?

- **The D-Bus daemon does NOT need CGO.** It is Go, uses **godbus** (pure Go,
  cgo-free, MIT), and calls straight into the `client` facade. Writing it against
  `libnm` in C would be backwards — the tunnel logic is Go. So the daemon stays
  CGO-free even though it is *allowed* to use CGO.
- **CGO/C is spent on the `libnm` GUI editor `.so`** (`nm/editor/`, plain C via
  `pkg-config libnm`), and optionally the auth-dialog. These are GObject shared
  libraries by NM's design; C is the idiomatic (and only sane) way to produce
  them. They are built by `gcc`, never by `go build`, so they cannot affect any
  Go binary's CGO status.

Net: the relaxed constraint is what unblocks **Phase 2** (the graphical form). It
is not needed for a working, toggleable VPN.

### 4.3 Dependency decision: godbus vs. hand-rolled D-Bus

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **`github.com/godbus/dbus/v5`** | pure Go, cgo-free, ubiquitous, MIT; days not weeks | one dep in the `nm` module | **Recommended** |
| Hand-rolled D-Bus subset (stdlib) | keeps even `nm` dep-free; matches "from scratch" ethos | ~1–2k LoC of SASL-EXTERNAL + marshalling; more surface to get wrong | Fallback / future hardening |

Because deps are isolated to the nested module, godbus does not touch the core's
zero-dep claim. Recommend godbus for Phase 0–1; a stdlib D-Bus transport can
replace it later behind the same internal interface if desired.

---

## 5. Component specifications

### 5.1 `.name` descriptor (`nm/data/nm-veepin-service.name`)

```ini
[VPN Connection]
name=veepin
service=org.freedesktop.NetworkManager.veepin
program=/usr/libexec/nm-veepin-service
supports-multiple-connections=true

[GNOME]
auth-dialog=/usr/libexec/nm-veepin-auth-dialog
properties=/usr/lib/NetworkManager/libnm-vpn-plugin-veepin.so
supports-external-ui-mode=true
service=org.freedesktop.NetworkManager.veepin

[libnm]
plugin=/usr/lib/NetworkManager/libnm-vpn-plugin-veepin.so
```

The `service=` name, the bus name the daemon requests, the policy file, and the
`vpn-type` used with `nmcli` must all be exactly
`org.freedesktop.NetworkManager.veepin`. In Phase 0 the `[GNOME]`/`[libnm]`
lines can be omitted (no editor yet).

### 5.2 D-Bus daemon (`nm/cmd/nm-veepin-service`)

- Requests bus name `org.freedesktop.NetworkManager.veepin` on the **system**
  bus; exports the `VPN.Plugin` object.
- **`Connect`**: parse the `a{sa{sv}}` connection dict via `nmconfig` → a
  protocol name plus an option map; call `client.Dial(ctx, protocol, opts)`; on
  success emit `Config` + `Ip4Config`, then `StateChanged(STARTED)`. On failure
  emit `Failure(...)` + `StateChanged(STOPPED)`.
  The service blank-imports every protocol package it can dial (`ikev2`,
  `wireguard`, `openvpn`, `sstp`, `ssh`, `anyconnect`, `nebula`, `masque`,
  `fortinet`, `l2tp`); without the import the binary still links and every
  `Connect` fails at runtime with "unknown protocol", so
  `TestDefaultProtocolIsRegistered` and `TestAllSupportedProtocolsRegistered`
  guard it.
- **`NeedSecrets`**: return `"vpn"` if a secret the selected protocol needs is
  absent from the connection's secrets (`secretMissing`), else `""`. Drives NM's
  secret-agent/auth-dialog prompt.
- **`Disconnect`**: `Session.Close()`, emit `StateChanged(STOPPED)`, quit.
- Runs the `Session.Wait()` loop on a goroutine; a dropped tunnel → `Failure` +
  state transition so NM can react.
- Idle-exit after disconnect (NM re-spawns on demand).
- Structured logging to stderr/journal; **never** log secrets.

**State machine:** `INIT → STARTING → (Config,Ip4Config) → STARTED →
STOPPING → STOPPED`, with any error routing to `Failure` then `STOPPED`.

### 5.3 Connection-dict mapping (`nm/internal/nmconfig`)

Maps NM's `vpn.data` / `vpn.secrets` string maps to a protocol name plus the
option map `client.Dial` parses. Three keys are consumed by the plugin itself;
everything else is passed through to the protocol untouched, so a new protocol's
options need no change here.

Three keys are consumed by the plugin itself:

| NM `vpn.data` key | Consumed by | Notes |
|-------------------|-------------|-------|
| `protocol` | plugin | which protocol to dial; default `ikev2` |
| `full-tunnel` | plugin (→ `never-default`) | `"yes"`/`"no"`, default yes |
| `mtu` | plugin (→ `Ip4Config` mtu) | optional override |

Everything else is a protocol option, passed through untouched. The key names
deliberately match the protocol packages' option constants (`ikev2.OptGateway`,
`fortinet.OptServer`, and friends), so the pass-through needs no translation
table. What `nmconfig` adds per protocol is only the *bookkeeping* NM needs before
it spawns anything: the minimum non-secret keys (`requireKeys`) and which secrets
it must prompt for (`secretMissing`). Every protocol veepin ships is dialable —
the set is `nmconfig.SupportedProtocols`:

| `protocol=` | required `vpn.data` keys | required `vpn.secrets` |
|-------------|--------------------------|------------------------|
| `ikev2` (default) | `gateway`, `local-id` | `psk`; `password` if `user` set |
| `wireguard` | `public-key`,`endpoint`,`address`,`allowed-ips` — or `config` (wg-quick) | `private-key` unless `config` |
| `openvpn` | `remote` — or `config` (`.ovpn`) | `password` if `username` set |
| `sstp` | `server`, `user` | `password` |
| `ssh` | `server`, `user` | `password` unless `identity` (key file) set |
| `anyconnect` | `server`, `user` | `password` |
| `nebula` | `ca`, `cert`, `key` (PEM paths) | — |
| `masque` | `server` | — |
| `fortinet` | `server`, `user` | `password` (`token`/`totp` optional for 2FA) |
| `l2tp` | `server`, `user` | `psk` **and** `password` |

File-path credentials (CA/cert/key PEMs, wg-quick/`.ovpn` files, an SSH identity
key) live in `vpn.data`, not `vpn.secrets`, so they are not treated as
NM-prompted secrets. The insecure `toy` example protocol is intentionally not
offered.

`protocol` defaults to `ikev2`, so profiles written before veepin gained more
protocols keep working unchanged. An unsupported value is rejected in `Parse`
rather than deferred to `client.Dial`, so NM gets a clear error before it spawns
anything. Two tests keep the wiring honest: `nmconfig` is unit-tested per
protocol (pass-through, required-key rejection, secret bookkeeping), and the
service command's `TestAllSupportedProtocolsRegistered` fails if a supported
protocol's package is not blank-imported (a runtime "unknown protocol") or a
registered protocol is missing from `SupportedProtocols`.

The GTK **editor** (`nm/editor`) has a protocol chooser at the top of the form
that switches between the IKEv2 and WireGuard field sets, so either can be created
graphically; the other protocols are configured from the command line (richer
editor forms are the outstanding GUI phase). A WireGuard profile can equally be
created from the command line:

```sh
nmcli connection add type vpn vpn-type org.freedesktop.NetworkManager.veepin \
  con-name wg-home \
  vpn.data 'protocol=wireguard, public-key=…, endpoint=vpn.example.com:51820, address=10.0.0.2/32, allowed-ips=0.0.0.0/0' \
  vpn.secrets 'private-key=…, preshared-key=…'
nmcli connection up wg-home
```

This package is plain data mapping and is **unit-testable without a bus** — the
bulk of the daemon's correctness tests live here.

### 5.4 D-Bus system policy (`nm/data/nm-veepin-service.conf`)

Installed to `/usr/share/dbus-1/system.d/`. Allows `root` to own the well-known
name and NM to call it:

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.freedesktop.NetworkManager.veepin"/>
    <allow send_destination="org.freedesktop.NetworkManager.veepin"/>
  </policy>
  <policy context="default">
    <deny own="org.freedesktop.NetworkManager.veepin"/>
    <allow send_destination="org.freedesktop.NetworkManager.veepin"/>
  </policy>
</busconfig>
```

### 5.5 Connection provisioning (Phase 0, no editor)

Until the editor `.so` exists, create connections with `nmcli` (or a keyfile in
`/etc/NetworkManager/system-connections/`):

```sh
nmcli connection add type vpn con-name home-veepin ifname '*' \
  vpn-type org.freedesktop.NetworkManager.veepin \
  vpn.data 'gateway=vpn.example.com, local-id=client.example.com, server-id=vpn.example.com, full-tunnel=yes'
nmcli connection modify home-veepin vpn.secrets 'psk=a-strong-preshared-key'
nmcli connection up home-veepin
```

Once created, the connection appears in the GNOME quick-settings VPN toggle and
supports autoconnect — the "minimal wrapper" milestone.

### 5.6 GUI editor plugin (`nm/editor/`, Phase 2)

Plain C against `libnm` (+ `libnma`/`libnm-gtk` for the widget). Implements the
`NMVpnEditorPlugin` factory (`nm_vpn_editor_plugin_factory`) and an
`NMVpnEditor` that binds a GTK form (gateway, local id, server id, auth mode
PSK/EAP, PSK/username/password) to the `vpn.data`/`vpn.secrets` maps above. Built
with `pkg-config --cflags --libs libnm` into
`libnm-vpn-plugin-veepin.so`. Modeled on the `properties/` directory of existing
in-tree NM plugins (e.g. network-manager-vpnc), which are the reference
implementations. No Go here.

### 5.7 auth-dialog (`nm/authdialog/`, Phase 2, optional)

Implements NM's external-UI-mode / stdin-stdout secrets protocol to prompt for
the PSK/password. Can be C (libnma) or a small Go binary. Skippable if secrets
are always provisioned via `nmcli`/keyfile.

---

## 6. Build and packaging

- **Root build is untouched.** `make build`, `go build ./...`, and GoReleaser
  continue to compile only the three CGO-free binaries. No new deps, no CGO.
- **`nm/Makefile`** drives the plugin:
  - `make -C nm service` → `go build ./cmd/nm-veepin-service` (CGO-free, godbus).
  - `make -C nm editor` → `gcc $(pkg-config --cflags --libs libnm libnma) -shared`
    → `libnm-vpn-plugin-veepin.so`.
  - `make -C nm install` → drop the `.name`, `.conf`, service binary
    (`/usr/libexec`), and `.so` (`/usr/lib/NetworkManager/`) into place.
  - `make -C nm deb` → a standalone `.deb` (see below).
- **Packaging.** The plugin ships as its **own** package `veepin-nm` (deb/rpm),
  separate from the core `veepin` package, and declares a runtime dependency on
  `libnm0` (+ `libnma` if the editor is included) and `networkmanager`. Two
  options:
  - keep the plugin's packaging in `nm/` (its own nfpms or `dpkg-deb`), so the
    core's `.goreleaser.yaml` remains CGO-free and simple; **recommended**;
  - or add a separate GoReleaser config under `nm/` invoked by a distinct CI job.

Keeping the plugin's build/packaging entirely inside `nm/` preserves the clean
separation and avoids teaching the core release pipeline about CGO or libnm.

---

## 7. Testing strategy

- **Unit (no bus), in the `nm` module:**
  - `nmconfig`: exhaustive connection-dict ↔ `client.Config` mapping, including
    missing-required-key and PSK-vs-EAP selection.
  - `Ip4Config`/`Config` marshalling: assert the emitted `a{sv}` dicts key-by-key
    (address byte order, prefix from netmask, `never-default`).
  - State-machine transitions with a fake bus connection.
- **Integration:**
  - Spin the daemon on a **private session bus** (`dbus-daemon --session`),
    invoke `Connect`/`Disconnect` from a test client, assert the emitted signals.
    Point it at the in-repo `ikev2d` test server (reuse the harness behind
    `internal/ike`'s `TestClientConnectPSK`) so a real handshake runs end to end
    without needing NM.
  - Root-required, TUN-touching paths run behind the same guards the existing
    data-path tests use.
- **Manual acceptance (documented runbook):** on a Pop!\_OS box, `make -C nm
  install`, `nmcli ... up`, verify address/DNS/routes via `ip addr`/`ip route`/
  `resolvectl`, verify the GNOME toggle, verify teardown restores routing.
- **`client` facade (root module):** a CGO-free test that `Dial`s the in-repo test
  server, asserts `Result` fields, and `Close`s cleanly — this is also net-new
  coverage for the refactor D1.

---

## 8. CI

- **Root CI (`.github/workflows/ci.yml`) unchanged and still CGO-free** — it never
  sees `nm/`.
- **New optional job `nm` (own workflow or matrix entry):** runs only when `nm/**`
  changes. Steps: `apt-get install libnm-dev libnma-dev`; `go build`/`go test` the
  nested module; `make -C nm editor` to compile the C `.so`. This is the *only*
  place a C toolchain / libnm headers enter CI, and it cannot affect the core
  jobs.

---

## 9. Security considerations

- **Runs as root.** NM spawns the service as root; it opens a TUN and hands
  addressing to NM. Keep the attack surface minimal: no shelling out, parse the
  connection dict defensively, bound all lengths.
- **Secrets.** PSK/password arrive via `vpn.secrets` and NM's secret agent; never
  log them, never write them to disk, zero buffers where practical. `NeedSecrets`
  must accurately report what is missing so NM prompts rather than the daemon
  failing opaquely.
- **D-Bus policy.** The `.conf` restricts name ownership to root and calls to NM;
  do not widen it.
- **No route recursion.** NM installs the host route to the gateway; confirm the
  daemon reports `gateway` so encapsulated ESP does not re-enter the tunnel (the
  problem `cmd/ikev2` solves by hand today).
- **Inherited auth caveats.** EAP-MSCHAPv2's dated crypto and PSK server-auth
  limitations carry over unchanged; this plugin does not alter the security of
  the handshake, only its desktop integration.

---

## 10. Phased plan

| Phase | Deliverable | Components | Est. | CGO/C? |
|-------|-------------|------------|------|--------|
| **D1** | Public `client` facade + refactor `cmd/ikev2` onto it | root `client/` | 1–2 d | no |
| **0** | Working, toggleable VPN via `nmcli` (no graphical form) | `.name`, D-Bus daemon, `nmconfig`, policy `.conf`, provisioning docs | 4–6 d | no |
| **1** | Robustness: full state machine, `NeedSecrets`/agent flow, MTU, failure/reporting, integration tests | daemon hardening + tests | 3–5 d | no |
| **2** | Graphical *Add VPN* form + secret prompt | C `libnm` editor `.so`, auth-dialog | 4–7 d | **yes** |
| **3** | Packaging + CI | `veepin-nm` deb/rpm, `nm` CI job, runbook | 2–3 d | build-only |

**Milestone "minimal wrapper" = end of Phase 0:** a NetworkManager-managed IKEv2
connection to an `ikev2d` server, created with `nmcli`, toggled from the GNOME
menu, with NM owning routes/DNS — no strongSwan, no CGO in any shipped Go binary,
root module still stdlib-only.

Phases D1→1 are all pure Go and reuse `internal/ike` almost verbatim; the CGO
budget is spent solely in Phase 2 on the one artifact NM's design forces into C.

---

## 11. Open decisions

1. **D-Bus transport:** godbus (recommended) vs. hand-rolled stdlib D-Bus in the
   `nm` module. Does not affect the core either way.
2. **Editor language for Phase 2:** plain C (idiomatic, matches reference plugins)
   vs. CGO `c-shared` (keeps it "in Go" but fights GObject). Lean plain C.
3. **auth-dialog:** ship one in Phase 2, or rely on NM's built-in
   password-request UI + `nmcli`-provisioned secrets for longer.
4. **Facade location/name:** `client` vs. `vpnclient` vs. `pkg/...`; and how much
   of `cmd/ikev2`'s wiring to lift into it.
5. **Packaging owner:** self-contained `nm/` packaging (recommended) vs. extending
   the root GoReleaser pipeline.

---

## 12. References

- NetworkManager VPN plugin D-Bus API: `nm-vpn-dbus-interface.h`,
  `org.freedesktop.NetworkManager.VPN.Plugin` / `.Connection`.
- `libnm` `NMVpnServicePlugin`, `NMVpnEditorPlugin`, `NMVpnEditor`.
- Reference in-tree plugins to model the editor on: `network-manager-vpnc`,
  `network-manager-openvpn` (`properties/` and `src/` layouts).
- godbus: `github.com/godbus/dbus/v5`.
- In-repo: `internal/ike` (client + handshake), `internal/dataplane` (TUN + pump),
  `cmd/ikev2/main.go` (the wiring to refactor behind the `client` facade).

---

## 13. Implementation status & runbook

### What is built (Phases D1 + 0)

| Piece | Location | Notes |
|-------|----------|-------|
| Public client facade | `client/` (root module) | `Dial`/`Session`/`Result`; CGO-free, no deps; `cmd/ikev2` refactored onto it |
| Nested plugin module | `nm/go.mod` | `github.com/xen0bit/veepin/nm`; the **only** module that uses godbus |
| Connection-dict mapping | `nm/internal/nmconfig` | bus-free, unit-tested |
| D-Bus VPN service | `nm/internal/dbusplugin`, `nm/cmd/nm-veepin-service` | implements `VPN.Plugin`; integration-tested on a private bus |
| `.name` descriptor + D-Bus policy | `nm/data/` | references the editor `.so` |
| GUI editor plugin (`.so`) | `nm/editor/veepin-editor.c` | C/libnm GObject; graphical Add-VPN form; saved secrets; dlopen smoke-tested |
| Auth-dialog | `nm/authdialog/veepin-auth-dialog.c` | C/libnma; prompts for not-saved secrets; non-interactive paths tested |
| Packaging | `nm/nfpm.yaml.in` | `veepin-nm` `.deb`/`.rpm` via `make packages` |
| Build/install | `nm/Makefile` | `make build` (Go, CGO-free) / `make editor` (C) / `make packages` / `sudo make install` |

The core binaries (`ikev2d`/`ikev2`/`testclient`) remain CGO-free and the root
module remains dependency-free — the root `go build ./...` never descends into
`nm/`.

### Phase 1 progress

Done: context-cancellable handshake (`client.Dial` aborts an in-flight IKE
exchange instead of waiting out its read deadlines); the
Disconnect-during-handshake race is fixed (no session leak, correct terminal
state); auth-vs-transport failure classification (a rejected PSK/password maps to
NM `LoginFailed` so NM re-prompts, everything else to `ConnectFailed`), carried
by `ike.ErrAuthFailed` → `client.ErrAuth`; and an optional per-connection `mtu`
override in `vpn.data`.

Remaining: interactive secrets (`ConnectInteractive`/`SecretsRequired`/
`NewSecrets`) — currently secrets must be present at Connect (NM's
`NeedSecrets` → agent → Connect flow covers the common case).

### Phase 2 progress

Done: the **C/libnm GUI editor plugin** (`nm/editor/veepin-editor.c`) — a
GObject shared library providing the graphical *Add VPN* form (gateway, local/
server ID, PSK, username/password, full-tunnel, MTU), mapping widgets to the
`vpn.data`/`vpn.secrets` keys the service consumes and pre-filling from an
existing connection. Built with `make editor` and verified by a dlopen
smoke-test (`make editor-test`, headless via `xvfb`) that drives the real
factory → get_editor → update_connection round-trip and the validation path. The
`nm` CI job now installs `libnm-dev`/`libgtk-3-dev` and builds+tests it.

Saved secrets: the editor stores the PSK/password with `NM_SETTING_SECRET_FLAG_NONE`
(system-saved) by default, so the root service receives them at Connect with no
prompt; a "Save the pre-shared key / password" checkbox can switch them to
`NOT_SAVED`, which the auth-dialog then prompts for.

### Phase 2b — auth-dialog (done)

`nm/authdialog/veepin-auth-dialog.c` is the C/libnma helper NM runs when a
connection has secrets flagged `NOT_SAVED`. It speaks NM's auth-dialog stdio
protocol (`nm_vpn_service_plugin_read_vpn_details` in, `key\nvalue\n` pairs +
blank-line terminator out), prompts for the missing PSK/password via
`NMAVpnPasswordDialog`, and is referenced from the `.name`'s `[GNOME]
auth-dialog=`. The non-interactive paths (saved secret echoed, EAP emits both,
foreign service refused) are covered by `authdialog_test.sh`, run in CI; the
GTK prompt itself needs a user and is exercised manually.

### Phase 3 progress

Done: the **`veepin-nm` package** (`nm/nfpm.yaml.in` + `make packages`) builds a
`.deb` and `.rpm` bundling the service, the editor `.so` (into the multiarch NM
plugin dir), the `.name` descriptor and the D-Bus policy, with runtime deps on
`network-manager`/`libgtk-3-0` (rpm: `NetworkManager`/`gtk3`) and
post-install/-remove hooks that reload NetworkManager. It is a **separate**
package from the CGO-free core so the core release pipeline never gains a
`libnm`/`libgtk` dependency. The `nm` CI job builds and uploads the packages.

### Install — package (recommended)

```sh
cd nm
make packages                       # builds bin/pkg/veepin-nm_*.deb and .rpm
sudo apt install ./bin/pkg/veepin-nm_*.deb   # (or: sudo dnf install ./bin/pkg/veepin-nm-*.rpm)
```

The package installs the service, editor `.so`, `.name` and D-Bus policy, and its
post-install hook reloads NetworkManager.

### Install — from source

```sh
# Build and install the service, editor .so, .name descriptor, and D-Bus policy.
cd nm
make build editor
sudo make install          # -> /usr/lib/NetworkManager/nm-veepin-service
                           #    /usr/lib/<multiarch>/NetworkManager/libnm-vpn-plugin-veepin.so
                           #    /usr/lib/NetworkManager/VPN/nm-veepin-service.name
                           #    /usr/share/dbus-1/system.d/nm-veepin-service.conf
sudo systemctl reload NetworkManager
```

### Create a connection — GUI

With the editor `.so` installed, GNOME Settings / nm-connection-editor →
**Add VPN → "IKEv2 (veepin)"** now shows a form (gateway, local/server ID, PSK,
username/password, full-tunnel, MTU). Fill it in and save. Equivalently, `nmcli`
still works:

### Create a connection — nmcli

```sh
# PSK:
nmcli connection add type vpn con-name home-veepin ifname '*' \
  vpn-type org.freedesktop.NetworkManager.veepin \
  vpn.data 'gateway=vpn.example.com, local-id=client.example.com, server-id=vpn.example.com, full-tunnel=yes'
nmcli connection modify home-veepin vpn.secrets 'psk=a-strong-preshared-key'

# EAP-MSCHAPv2 (username/password) instead:
#   vpn.data '... , user=alice'
#   vpn.secrets 'psk=a-strong-preshared-key, password=wonderland'

nmcli connection up home-veepin
```

Once created, the connection also appears in the GNOME quick-settings VPN toggle.

### Verify

```sh
nmcli connection show --active           # home-veepin listed, state activated
ip addr show                             # tun device has the assigned internal IP
ip route                                 # default via tun (full tunnel) + host route to the server
resolvectl status                        # pushed DNS servers present
journalctl -u NetworkManager -f          # watch Connect/StateChanged/Ip4Config
nmcli connection down home-veepin       # tears down; routes/DNS reverted by NM
```

### Debugging the service directly

The service normally talks to the **system** bus (needs the installed policy +
root). For local inspection without installing, run it on the session bus:

```sh
nm/bin/nm-veepin-service -session &
busctl --user introspect org.freedesktop.NetworkManager.veepin \
  /org/freedesktop/NetworkManager/VPN/Plugin org.freedesktop.NetworkManager.VPN.Plugin
```

### Uninstall

```sh
nmcli connection delete home-veepin
cd nm && sudo make uninstall && sudo systemctl reload NetworkManager
```
