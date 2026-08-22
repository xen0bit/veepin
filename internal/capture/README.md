# internal/capture — recorded peer traffic, replayed offline

Not to be confused with [`internal/replay`](../replay), which is a sliding-window
anti-replay check for a data path. This package is about *recordings*: it holds
the golden-corpus format and a from-scratch pcap reader, so a capture taken once
from a live interop cell can be replayed against veepin's own codecs by a plain
`go test ./...` — no Docker, no network, no fifteen-minute timeout.

## Why

The interop matrix is the load-bearing evidence in this repository, and it is
also the heaviest thing in it. Which means the evidence that matters most is the
evidence a developer checks least often. Capturing a cell once and committing the
result turns "did I break strongSwan?" from a CI shard into a millisecond.

## Files

| File | What it holds |
|---|---|
| `corpus.go` | the golden-corpus text format: `Corpus`, `Record`, `Marshal`, `Parse` |
| `pcap.go` | classic-pcap reading plus Ethernet/SLL/IPv4/IPv6/UDP decode, to `Datagram` |

The corpus format is text on purpose. A golden file is only useful if a human can
read the diff when it changes, and a binary blob that "just differs" gets rubber
stamped. Metadata as `key = value`, free comments preserved, then one record per
message:

```
# strongSwan answers without a cookie.
> peer ike_sa_init_response
2920...
```

## What a replay proves

That veepin's parser accepts bytes a real implementation actually emitted, and —
where the codec is a `Marshal`/`Parse` pair — that veepin's **encoder** produces
those same bytes back. The second half is the valuable one. It is an oracle
somebody else wrote, which is the only kind that catches the
mutually-consistent-bug class `AGENTS.md` keeps returning to: a veepin↔veepin
test proves the two halves agree with each other, not that either is right.

## Caveats

**A corpus is not a substitute for the live cell, and must never be allowed to
read as one.** A recording pins the peer as it was on the day it was captured. It
cannot notice that strongSwan 6.1 changed a default, that a new transform
appeared in a proposal, or that the peer stopped tolerating something it used to
accept. Trusting a corpus as current would be the most sophisticated instance yet
of the exact failure this repository keeps finding — a green test that proves the
two halves agree with a *memory* rather than with a peer. The live cells stay;
the corpus is what makes them cheap to have confidence in between runs.

Two narrower limits, both deliberate:

- **The pcap reader does not reassemble IP fragments, and errors rather than
  skipping them.** Returning the first fragment as though it were the whole
  datagram would put a message in the corpus that no peer ever sent — and IKE
  with certificates is exactly where oversized UDP lives, which is to say exactly
  where a corpus is most wanted.
- **A corpus records ciphertext where the exchange is encrypted.** IKE_SA_INIT,
  a WireGuard handshake and an L2TP control message are all in the clear and are
  fully round-trippable; anything under an SK payload or a TLS record is opaque
  without keys this format deliberately does not carry.
