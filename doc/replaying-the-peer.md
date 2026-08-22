# Replaying the peer

The interop matrix is the load-bearing evidence in this project — the whole
argument of [`AGENTS.md`](../AGENTS.md) rests on it — and it is also the heaviest
thing in it: Docker, pinned peer images, fifteen-minute timeouts, path filters
that decide whether a shard runs at all. Which means the evidence that matters
most is the evidence a developer checks least often.

So capture it once and replay it forever. Two corpora of real peer traffic are
committed under
[`internal/capture/goldens/corpora/`](../internal/capture/goldens/corpora), and
`go test ./...` replays them against veepin's own codecs in milliseconds, with no
Docker, no network and no root.

```
$ go test ./internal/capture/...
ok  	github.com/xen0bit/veepin/internal/capture         0.005s
ok  	github.com/xen0bit/veepin/internal/capture/goldens 0.004s
```

## The one thing this must not be allowed to become

**A corpus is not a substitute for the live cell.** A recording pins the peer as
it was on the day it was captured. It cannot notice that strongSwan 6.1 changed a
default, that a new transform appeared in a proposal, or that the peer stopped
tolerating something it used to accept. Trusting a corpus as current would be the
most sophisticated instance yet of the exact failure this project keeps finding —
a green test that proves the two halves agree with a *memory* rather than with a
peer.

The design answers that directly rather than warning about it. Each corpus has an
exported `Check` — the assertions that must hold over it — and **the same
function runs twice**:

| Where | Against what | Says |
|---|---|---|
| `internal/capture/goldens` | the committed corpus | veepin still agrees with what strongSwan sent in August |
| `tests/interop` (`interop` tag) | a capture taken seconds ago | and strongSwan still sends it |

Neither is asked to be the other. That is the only reason a check is an exported
function instead of a test body.

## What is recorded, and why those two

| Corpus | Cell | Peer | Direction |
|---|---|---|---|
| `ikev2-strongswan` | `compose.client-ss.yml` | strongSwan 6.0.0 | veepin initiates, strongSwan responds |
| `wireguard-wgge` | `compose.wireguard-server.yml` | wireguard-go | **wireguard-go initiates**, veepin responds |

The WireGuard direction is deliberate. The handshake initiation is the message
with the MACs and the encrypted static key in it, so capturing the cell where the
*peer* sends it is what makes the strong check possible: veepin's own Noise
responder is handed a real wireguard-go initiation offline and asked to do the
whole job — verify mac1 against its static key, run both Diffie-Hellmans, decrypt
the peer's static public key — and the recovered key is compared against the one
the cell configured. A wrong answer is not an error, it is a specific wrong 32
octets.

For IKEv2 the strong check is a different shape: every layer of every captured
message is re-encoded and compared **octet for octet** — header, payload chain,
and each body through its own `Parse`/`Marshal` pair. A parser that accepts the
peer's message proves only that veepin is tolerant. Re-emitting the identical
octets proves the two *encoders* agree, which is the one thing a veepin↔veepin
test can never show, and precisely the mutually-consistent-bug class `AGENTS.md`
keeps returning to.

On top of that the responder's `IKE_SA_INIT` must still advertise
`IKEV2_FRAGMENTATION_SUPPORTED`. veepin fragments its own IKE output only when
the peer offers it, so losing the advertisement would put certificate
authentication straight back on the oversized-datagram path — invisibly, because
the certificate cell mints the smallest certificate that exists.

## What the first capture taught

The chain rebuild failed on `IKE_AUTH` the first time it ran, and the cause was
not a bug. `Builder.Add` links each payload to the next one and writes 0 into the
last, which is right for every payload except `SK`: RFC 7296 §3.14 gives its
NextPayload field a different job — it names the first payload *inside* the
ciphertext. A captured `IKE_AUTH` request therefore ends `23 00 01 4f` where a
rebuild produces `00 00 01 4f`, and the two disagree without either being wrong.

veepin's own encoder gets this right. What the mismatch caught was an
over-general assertion. It is written down in
[`internal/capture/goldens/ikev2.go`](../internal/capture/goldens/ikev2.go)
rather than quietly worked around, because "the last payload's NextPayload is
zero" is exactly the kind of near-universal truth a tidy-up would restore.

## Fuzz seeds

The second return. The seed corpora for `FuzzParseMessage`, `FuzzParseBodies`
and `FuzzParseMessages` were buffers of zeroes and a hand-built header; they are
now sixteen entries of real peer traffic, which puts the fuzzer one mutation away
from a valid message rather than back at the first bounds check. Go runs
everything in `testdata/fuzz/<Target>/` on an ordinary `go test`, so the coverage
arrives in the normal pass too.

A seed's whole value is its provenance, and a seed that drifted — a hand-edit to
make a failure go away, a stale file left after a recapture — would look
identical and be worth nothing. `TestEveryFuzzSeedComesFromACapture` requires
every committed seed to be traceable, byte for byte, to a record or a payload
body in a committed corpus.

## Recording a new one

A corpus must come from a live cell or it is not evidence of anything, so there
is no offline path to producing one.

1. Add a `Golden` to `goldens.Registry`: the compose file, the peer's name and
   version, an `Extract` that labels the cell's messages, and a `Check`.
2. Add a `TestInterop…CorpusStillMatchesTheLivePeer` in
   `tests/interop/capture_test.go`, naming the service tcpdump runs in — which
   must be the side that **listens**, since the capture has to be recording
   before the first handshake message and only the listener can be started early
   without the exchange starting without it.
3. List that test in `internal/livingreadme/interop.go`, or CI puts it in no
   shard and it never runs.
4. Generate the file:

   ```sh
   VEEPIN_UPDATE_GOLDENS=1 go test -tags interop -run TestInteropYourCorpus \
       -v -timeout 15m ./tests/interop/
   ```

Write the check *after* looking at what the peer actually sent. Both checks here
found something on the run that produced them, and neither finding was in the
plan that asked for them.

Two limits are deliberate rather than provisional. The pcap reader does not
reassemble IP fragments and **errors** rather than skipping them — returning a
first fragment as though it were a whole datagram would put a message in the
corpus that no peer ever sent, and IKE with certificates is exactly where
oversized UDP lives. And a corpus records ciphertext where the exchange is
encrypted: `IKE_SA_INIT`, a WireGuard handshake and an L2TP control message are
in the clear and fully round-trippable, but anything under an `SK` payload or a
TLS record is opaque without keys the format deliberately does not carry.
