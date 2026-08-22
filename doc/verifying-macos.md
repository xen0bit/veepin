# Verifying the macOS client by hand

The interop harness is Docker, and Docker on macOS is a Linux VM. So every cell
in the matrix runs a Linux `veepin` no matter what laptop starts it, and the
macOS data path — `dataplane/tun_darwin.go`, `client_route_darwin.go`,
`client_dns_darwin.go` — is verified by a person with a Mac or not at all.

This is the same shape as [`verifying-shaping.md`](verifying-shaping.md), which
exists because a vendor client cannot be put in a container either. Both pages
are here so that "we cannot automate this" does not quietly become "nobody
checked".

**Status: unverified.** The code compiles for `darwin/amd64` and `darwin/arm64`
in CI (`GOOS=darwin go build ./...`), which proves the syscalls and constants
type-check and nothing more. No one has run it. Until someone works through
this page and says so, treat macOS as "written, not proven" — the tree's own
standard for the difference, and the reason SoftEther's matrix row says what it
says.

## What is being checked, and why each step

Four things can be wrong independently, and the order below is chosen so that a
failure tells you which:

| Step | What it proves | The failure it isolates |
|---|---|---|
| 1 | the utun opens | the control-socket dance: `CTLIOCGINFO`, the unit number, `UTUN_OPT_IFNAME` |
| 2 | packets cross | the 4-octet AF header — the one thing macOS has and Linux's `IFF_NO_PI` turns off |
| 3 | routes apply and revert | `ifconfig`/`route` argument shapes, and `route -n get default` parsing |
| 4 | DNS applies and reverts | the `networksetup` service-name lookup, which is the fiddliest part |

## Prerequisites

- macOS 12 or later, on Intel or Apple silicon.
- Go 1.22+.
- **root.** macOS has no capability model, so there is no equivalent of
  `setcap cap_net_admin+ep`. Every step below is `sudo`.
- A reachable veepin server. Any protocol will do; the examples use WireGuard
  because its server is the easiest to stand up on a Linux box, and IKEv2
  because it exercises the dual-stack path.

```sh
git clone https://github.com/xen0bit/veepin && cd veepin
go build -o veepin ./cmd/veepin
```

## Step 1 — the device opens

```sh
sudo ./veepin probe wireguard \
    -private-key "$(cat client.key)" \
    -public-key "$SERVER_PUBKEY" \
    -endpoint vpn.example.com:51820 \
    -address 10.0.0.2/32
```

`probe` dials, prints the negotiated configuration and closes, changing no host
state — which is exactly what you want for a first run on a laptop you rely on.

**Expect** a line naming a `utunN` interface. **If it fails** with `utun
CTLIOCGINFO`, the control name lookup is wrong; with `utun connect`, either you
are not root or that unit is taken (try `-tun utun9`, or omit `-tun` to let the
kernel choose).

## Step 2 — packets cross

This is the step that catches the AF header, and it is the one most likely to
fail, because getting it wrong produces a tunnel that comes up perfectly and
moves nothing.

```sh
sudo ./veepin connect wireguard … -no-route -tun utun9
```

In a second terminal:

```sh
sudo ifconfig utun9 inet 10.0.0.2 10.0.0.2 netmask 255.255.255.0 up
ping -c 3 10.0.0.1          # the server's inner address
```

**Expect** replies. **If the pings are lost** while the server's log shows the
handshake completing, the AF header is the suspect: `tcpdump -ni utun9` should
show plain IP packets, and if it shows nothing at all in one direction, the
header is being written or stripped wrongly in that direction. Both halves are
in `tun_darwin.go`'s `Read` and `Write`, and both are big-endian — writing the
family host-order gives a device that accepts every packet and delivers none.

## Step 3 — routing applies and reverts

Take a copy of the routing table first, because the point of the step is that it
comes back:

```sh
netstat -rn > /tmp/routes.before
sudo ./veepin connect wireguard … -tun utun9        # full tunnel, no -no-route
```

While it is up, in a second terminal:

```sh
netstat -rn | grep -E '^(0/1|128.0/1)'   # the two halves, via utun9
curl -s https://ifconfig.me               # should be the server's address
```

Then `Ctrl-C` the client and:

```sh
netstat -rn > /tmp/routes.after
diff /tmp/routes.before /tmp/routes.after   # expect no difference
curl -s https://ifconfig.me                 # should be your own address again
```

**The diff is the assertion.** A tunnel that comes up and routes correctly but
leaves a `/1` behind on teardown is worse than one that never worked, because
the machine keeps half-working afterwards.

Repeat with `-route 10.0.0.0/8` and with `-exclude 1.1.1.1` and diff again.

## Step 4 — DNS applies and reverts

```sh
networksetup -getdnsservers "$(networksetup -listnetworkserviceorder | \
    grep -B1 "Device: $(route -n get default | awk '/interface:/{print $2}')" | \
    head -1 | sed 's/^([0-9]*) //')"
```

That command is the same lookup `client_dns_darwin.go` does, written out — run
it first, and note what it prints, because that is what must come back.

Bring the tunnel up, then:

```sh
scutil --dns | head -20      # the tunnel's resolvers should be first
dig +short internal.example.com   # a name that only exists inside the tunnel
```

`Ctrl-C`, then re-run the `-getdnsservers` command and check it prints what it
printed before. **If the service lookup fails** the error names the interface it
could not map; the likely cause is a network service whose device line
`-listnetworkserviceorder` formats differently from the parser's expectation,
and the fix belongs in `primaryNetworkService`.

## What is knowingly not supported

- **The kill switch.** `-kill-switch` refuses on macOS, naming why: the Linux
  implementation needs blackhole routes with per-route metrics so it can be
  armed while the tunnel is healthy, and the BSD table has no metrics. See
  [Doing it yourself with pf](#doing-it-yourself-with-pf) below — the protection
  is available, it just has to be yours rather than veepin's.
- **The layer-2 protocols.** `softether` and `l2tpv3` need a TAP device, and
  macOS has none in-kernel. `OpenTAP` says so rather than failing obscurely.
- **GSO.** A Linux offload with no utun equivalent. `GSO()` is false and the
  pump takes its ordinary path, which is what it already does for any device
  reporting none.
- **`veepin serve`.** Nothing stops it, and the TUN and routing pieces are
  shared with the client — but `internal/hostnet` shells out to `iptables` and
  `sysctl` with Linux spellings, so NAT setup will not work. Serving from a Mac
  is not a goal; dialling from one is.

## Doing it yourself with pf

A kill switch on macOS is a `pf` ruleset, and veepin will not install one. The
reason is specific rather than squeamish: `pfctl -a veepin -f -` loads rules
into an anchor happily and pf never evaluates them, because an anchor is only
consulted if the **active ruleset references it** — and the stock
`/etc/pf.conf` hooks only `com.apple/*`. Making it work means editing
`/etc/pf.conf` permanently, or replacing your whole ruleset for the life of the
tunnel and restoring it afterwards. Either one is veepin owning your host's
firewall, and the second fails in the wrong direction: a crash leaves the anchor
referenced and empty, so traffic flows and you believe you are protected.

If you want it, own it. Add one line to `/etc/pf.conf`, after the existing
`anchor` lines:

```
anchor "veepin"
```

Then, with the tunnel's interface and your server's address in hand:

```sh
# TUN is the utun veepin reported; SERVER is the OUTER address it dialled
# (client.Result.Gateway), not an address inside the tunnel.
sudo pfctl -a veepin -f - <<EOF
block drop out all
pass out quick on lo0 all
pass out quick on $TUN all
pass out quick proto udp to $SERVER
EOF
sudo pfctl -E          # note the token it prints
```

To take it down, flush the anchor and release the reference count you took —
`-X` rather than `-d`, so pf stays enabled if something else was using it:

```sh
sudo pfctl -a veepin -F rules
sudo pfctl -X <token>
```

Two things to get right, both of which are the same mistakes the Linux
implementation exists to avoid:

- **`$SERVER` is the outer address**, the one on the underlying network. Putting
  a tunnel-internal address there fences the tunnel out of its own transport and
  nothing connects.
- **Load the rules before you connect, not after.** Arming afterwards leaves
  however long the handshake takes as plaintext, which is the window the whole
  mechanism exists to close.

Adapt the `pass out quick proto udp` line to your protocol's transport — `tcp`
for SSTP, SSH, AnyConnect and Fortinet; `udp` for IKEv2, WireGuard, MASQUE,
Nebula and L2TP.

## Reporting

Open an issue with the macOS version, the hardware, the protocol, and which
step failed. A step-3 or step-4 failure is worth the `netstat -rn` diff or the
`-getdnsservers` output; a step-2 failure is worth the `tcpdump -ni utunN`.
