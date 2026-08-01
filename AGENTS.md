# veepin — working notes for coding agents

A from-scratch userspace VPN in pure Go. Sixteen production protocols, **client
and server for every one**, each verified in Docker against a real third-party
implementation *and* against itself.

That sentence is the whole thesis, and it is what most decisions here follow
from. Read it as three constraints:

- **From scratch.** No third-party protocol libraries. Dependencies are
  `golang.org/x/{crypto,net,sys}` and nothing else. `x/crypto` is there because
  WireGuard mandates ChaCha20-Poly1305 and BLAKE2s; `x/net` for QUIC.
- **Both roles.** A protocol is not "added" until `veepin connect <p>` and
  `veepin serve <p>` both work. Half a protocol is not a milestone.
- **Verified against a real peer.** A veepin↔veepin test proves the two halves
  agree with each other, which is not the same as being right. See
  [The interop matrix earns its keep](#the-interop-matrix-earns-its-keep).

## Orientation

```
cmd/veepin/          the CLI: connect, serve, probe
client/              the registry, and the Session/Result/Server contracts
dataplane/           TUN, address pool, packet pump, routing, shaping — protocol-agnostic
internal/cryptoutil/ the primitives — protocol-agnostic
<proto>/             the public facade for one protocol: Config, Opt* consts, Dial, NewServer
internal/<proto>/    that protocol's implementation
tests/interop/       Docker cells: one compose file per direction, per protocol
internal/livingreadme/  the interop matrix, which drives both the README tables and the CI shards
nm/                  a separate Go module: the NetworkManager plugin
```

Two shared packages carry the PPP protocols: `internal/ppp` (LCP, MS-CHAPv2,
IPCP, both roles) and `internal/mschap`. Two carry IPsec: `internal/ikev2/esp`
(the RFC 4303 data path, used by five protocols now) and `internal/ikev1` (which
serves both L2TP/IPsec and Cisco IPsec).

`toy` / `internal/toy` is a deliberately insecure worked example with a written
spec. It is the right thing to read first when adding a protocol, and it must
never carry traffic.

## Hard rules

These are contracts, not conventions. Breaking one is silent at compile time and
wrong at runtime.

- **`Dial` installs no routes and no addresses.** It returns a `client.Result`
  the caller applies. See `client/client.go`.
- **`client.Result.Gateway` is the server's OUTER address** — the one dialled on
  the underlying network, never an address inside the tunnel. It exists so the
  caller can pin a host route and stop the tunnel's own packets recursing into
  it. Getting this wrong is silent: the handshake succeeds, the interface comes
  up, and every packet leaves by the wrong door. `client.Result.Validate`
  catches the common mistake.
- **`NewServer` opens the TUN and validates, but binds nothing.** Sockets are
  bound in `ListenAndServe`, so the caller can configure host networking first.
- **Parsers return subslices of their input.** The inbound data path is
  allocation-free by design; a parser that copies costs one allocation per
  packet. `datapath_test.go` in each package pins this.
- **`internal/` is where implementations live.** The `<proto>/` package is the
  supported surface and should be thin.

## The mechanical guards

CI fails loudly and by name if you skip a step. Knowing these up front saves a
round trip:

| Guard | What it requires |
|---|---|
| `docs_test.go` — `TestPackageDocNamesEveryProtocol` | `doc.go`'s package comment names every registered package |
| `docs_test.go` — `TestREADMECountsProtocolsCorrectly` | **every** occurrence of "*N* production protocols" and "*Nth* registered protocol" in the README agrees with the registry — spelled out ("sixteen", "seventeenth") |
| `fuzztargets_test.go` — `TestFuzzTargetsAreAllListed` | every `Fuzz*` in the tree is in the `TARGETS` heredoc in `.github/workflows/ci.yml`, and `expected=N` matches the count |
| `cmd/veepin/main_test.go` | every registered protocol has a `connect` case |
| `cmd/veepin/flags_test.go` | every registered server protocol has a `serve` case; every bound flag reaches the option map (it perturbs each one and requires the map to change); every emitted key has a matching `Opt*` const |
| `cmd/veepin/flags_test.go` — `TestClientOptSpecsMatchTheKeysTheProtocolReads` | every registered client protocol declares `RegisterClientOpts`, and its spec keys and `connect` flags are the same set |
| `cmd/veepin/flags_test.go` — `TestRequiredClientOptsAreTheOnesTheParseRejects` | an option whose absence the parse rejects with "is required" is marked `Required: true` |
| `docs_test.go` — `TestEveryOptConstIsDescribedByAnOptSpec` | every `Opt*` const a facade declares is named as a `Key` in one of its two OptSpec tables — this is what catches an option the parse reads that no flag emits, which both flag-driven guards above are blind to |
| `internal/livingreadme/interop_test.go` | every test named in the matrix exists, and every `TestInterop*` is in the matrix — **a test absent from the matrix runs in no CI shard and therefore never runs** |
| `nm/cmd/.../TestAllSupportedProtocolsRegistered` | `nmconfig.SupportedProtocols` and the service's blank imports agree |

`docs_test.go` reaches the registry through blank imports of every facade
package. Forget to add yours and the count check passes — against a registry
that has not heard of your protocol. Add the import first.

## Adding a protocol

Roughly the order that works. One commit per phase.

1. **`internal/<proto>/` codecs first**, with tests, before any I/O. Framing,
   then whatever the control plane parses. Every codec gets a "reject every
   truncation" test — loop over every prefix of a valid message.
2. **Both roles over an in-memory pipe** (`net.Pipe`) or a real
   `net.Listener`/`tls.NewListener`, in `e2e_test.go`. Assert the data path
   moves a byte-identical packet in both directions, shaped and unshaped.
3. **`<proto>/` facade** — `Config`, `Opt*` consts, `Dial`, a `dialer`
   implementing `client.Dialer`, `func init() { client.Register(...) }`; and
   `server.go` with the same shape for `client.RegisterServer`. Implement
   `client.Prober` on any path that can go quiet.
   Then **`<proto>/opts.go`** — one `client.OptSpec` per client option, through
   `client.RegisterClientOpts`, alongside the server's `client.RegisterServerOpts`
   in `server.go`. This is what the management panel renders a form from and what
   `veepin profile add` and client-config generation validate against; without it
   the protocol is dialable but unmanageable. Mark `Secret` on anything that is
   key material *or a path to it*, and `Required` on anything the parse rejects
   the absence of. Three guards in the table above enforce all of this, and the
   third catches the case the other two structurally cannot.
4. **CLI cases** in `cmd/veepin/connect.go` and `serve.go`, plus direct imports.
5. **Docs**: `doc.go`, the README protocol table + usage-runbook table + the
   spelled-out counts, `doc/usage/<proto>.md`, `internal/<proto>/README.md`, and
   a `doc/security.md` section if the protocol has a weakness worth naming.
6. **`datapath_test.go`** — the `AllocsPerRun` guard and `Benchmark*` swept over
   `{64, 576, 1400}`.
7. **`fuzz_test.go`** + the `ci.yml` `TARGETS` list + `expected=`.
8. **Interop** — peer image dir, `compose.<proto>*.yml` per cell, entrypoints
   under `tests/interop/veepin/`, `TestInterop*` funcs, an `interopRow` in
   `internal/livingreadme/interop.go`, and the facade dir added to **both**
   path-filter lists in `.github/workflows/interop.yml`. Use `runInteropBench`
   for the first test of a cell so the throughput table fills.
9. **NetworkManager** — `nm/internal/nmconfig/nmconfig.go` (`SupportedProtocols`,
   `requireKeys`, `secretMissing`), `nm/Makefile` (`VEEPIN_PROTOCOLS` +
   `LABEL_<proto>`), `nm/editor/veepin-editor.c` (a `FieldDef` table + a `PROTO`
   row), and a blank import in `nm/cmd/nm-veepin-service/main.go`.

### The gate before pushing

```sh
gofmt -l .                                   # must print nothing
go build ./... && go vet ./...
go test -race ./...                          # correctness
go test ./...                                # again: the AllocsPerRun guards need no race detector
golangci-lint run
go mod tidy && git diff --exit-code go.mod go.sum
cd nm && go build ./... && go test -race ./... && cd ..
make interop                                 # needs Docker
```

Two of those are easy to skip and both bite. `gofmt` is checked by a dedicated
CI step that `golangci-lint` does not cover. And the **second, race-free** `go
test ./...` is not redundant: the race detector perturbs allocation counts, so
the `AllocsPerRun` guards skip under `-race` and only run in that pass.

## The interop matrix earns its keep

Run the interop cells locally before pushing. `docker compose` reuses a running
container when only a bind-mounted file changed, so **tear down between runs** or
you will test the old code and misread the result:

```sh
cd tests/interop
docker compose -f compose.<cell>.yml down -v --remove-orphans
go test -tags interop -run 'TestInterop<Name>' -v -timeout 15m ./...
```

Why it matters, concretely. While adding Pulse, the two ESP keying blocks were
wired to the wrong directions **at both ends**. That produces a pair of security
associations that agree perfectly *with each other* — so the veepin↔veepin cell
passed, every unit test passed, and only openconnect noticed. A self-test can
only prove the two halves are consistent. Cross-implementation tests are what
prove they are correct.

Two corollaries:

- When a data path has a fallback, **assert the fast path actually came up**.
  `runInteropRequiringLog` exists for this: a bare ping passes just as happily
  on a silent fallback, which is exactly what was masking the bug above.
- When a protocol has no open-source server, the client-direction cell gets the
  fixed `—†` label rather than a false ✗ (see the Fortinet precedent in
  `internal/livingreadme/interop.go`).

## Protocol work: things learned the hard way

- **Read the reference implementation's source, not a summary of it.** For
  Pulse, the cipher identifiers in my own plan were wrong (`AES-128-CBC` is 2 and
  `AES-256-CBC` is 5), and the configuration packet turned out to have four
  length fields that must agree or a client refuses it outright. `curl` the file
  and read it; a summarised fetch loses exactly the offsets that matter.
- **Where a peer enforces a value, emit exactly that value** and say so in a
  comment naming the peer. Several constants in `internal/pulse` and
  `internal/gp` are only explicable that way.
- **Endianness is not uniform inside a protocol.** Pulse is big-endian
  throughout except the ESP SPI. GlobalProtect's frame header is big-endian
  except the kind word. Both have a test whose whole purpose is to stop a
  tidy-up from "fixing" them.
- **`net/http` will reject requests that real clients send.** openconnect's
  GlobalProtect tunnel request is `GET <path> HTTP/1.1\r\n\r\n` with no headers
  at all, and Go rejects HTTP/1.1 without `Host` before any handler runs — hence
  `internal/gp/listener.go`, which splits the tunnel off in front of `net/http`
  by request line. Related: a kept-alive control connection carries the next
  request past that splitter, so the control plane sets `Connection: close`.
- **Mutually-consistent bugs are the dangerous class.** Anything where both ends
  make the same choice — key direction, nonce orientation, who-sends-first —
  needs either a cross-implementation test or a unit test written from the
  *peer's* point of view. `TestKeyBlocksNameTheirOwnInboundDirection` in
  `internal/pulse` is the model.
- **Reordering is real.** In the Cisco IPsec XAuth exchange, the client sends its
  acknowledgement and its configuration request back to back; gating the second
  on the first turned ordinary datagram reordering into a failed session. Prefer
  dispatching on *what a message is* over *what the state machine expected next*.
- **Shaping needs no peer support**, on any protocol here. Over ESP it is
  RFC 4303 §2.7 traffic-flow-confidentiality padding; over a framed layer-3
  tunnel it is trailing filler the receiver trims by the inner IP header's own
  Total Length, as every IP stack does. Every shaped interop cell exists to
  prove a stock client tolerates it.

## House style

The code reads like prose and the comments carry the reasoning. Match it.

- **Comments say *why*, and name the alternative not taken.** "Little-endian,
  deliberately" beats "read the SPI". If a value came from a peer's source or a
  packet dump, say which.
- **Package-level doc comments open each file** with the shape of the thing —
  often an ASCII or mermaid diagram of the exchange. See `internal/pulse/auth.go`
  or `internal/ikev1/aggressive.go`.
- **Test names are claims.** `TestSPIIsLittleEndian`,
  `TestConfigOmitsESPWhenThereIsNone`,
  `TestEncodeSplitIncludeSkipsWhatItCannotSay`. The comment above a test says
  what breaks if it fails, not what it does.
- **Errors are lower-case, prefixed with the package name**, and the drop path on
  a data path uses pre-built sentinels so a flood of bad packets allocates
  nothing.
- **Every `internal/<proto>/README.md` ends with an honest caveats section.**
  Missing forward secrecy, unimplemented modes, protocol weaknesses veepin
  inherits — state them plainly. `doc/security.md` carries the longer form.
- Prefer `for i := range n` over `for i := 0; i < n; i++`, and
  `strings.SplitSeq` over `strings.Split` — the linter enforces both.

## Known flakes

Re-run these; don't "fix" them.

- `AllocsPerRun` assertions in the "Test (no race, for allocation assertions)" step.
- `fuzz (smoke)` reporting "context deadline exceeded" — that is a timeout, not
  a crash.
- `internal/ikev2/ike` — "ESP packet never reached the server TUN".
- `internal/fortinet` — `TestDTLSAttachesToTLSTunnel`.
- The release workflow's `nm-packages` job dying on an Ubuntu mirror sync.

## Cutting a release

Tags drive it: `.github/workflows/release.yml` runs GoReleaser on any pushed
`v*` tag, and the changelog is generated from `feat:`/`fix:` commits (the
`docs`/`test`/`chore`/`ci` types, scoped forms included, are filtered out).

**Do not tag the tip of `main` blindly.** The living-README workflow commits its
regenerated tables with `[skip ci]` in the message, and GitHub skips *every*
workflow for a push whose head commit carries that marker — the tag push
included. The tag lands, the workflow never runs, and no release appears. There
is no error anywhere; `gh release list` simply does not show it.

Check before tagging, and tag a commit without the marker:

```sh
git log -1 --format=%s origin/main    # must not contain [skip ci]
```

If the tip does carry it, land a real commit first and tag that.

## Sequencing several protocols

They serialise, because they all touch `doc.go`, the README protocol table and
the spelled-out counts. Branch off the previous one, and note that **this repo's
workflows only trigger on pull requests whose base is `main`** — a PR stacked on
another branch gets no checks at all. Merge in order and rebase each onto `main`
before expecting CI.
