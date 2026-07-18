package anyconnect

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// HTTP paths in the exchange. The tunnel path is Cisco's and is what OpenConnect
// and ocserv both use.
const (
	authPath   = "/auth"
	tunnelPath = "/CSCOSSLC/tunnel"
)

// sessionCookie is the cookie name carrying the session token from the
// authentication exchange to the CONNECT request.
const sessionCookie = "webvpn"

// TunnelConfig is the addressing a server assigns a client. In AnyConnect this
// arrives as CONNECT response headers rather than through an in-tunnel
// negotiation, so it is fully known before the first packet moves.
type TunnelConfig struct {
	Address net.IP   // the client's inner address
	Netmask net.IP   // its netmask
	DNS     []net.IP // DNS servers to use over the tunnel
	MTU     int      // inner MTU
	// SplitInclude are the destinations routed into the tunnel. Empty means a
	// full tunnel, which is what the protocol says an absent header implies.
	SplitInclude []string
	// Domains are the search domains, space-separated as the header carries them.
	Domains string
}

// Header names carrying that configuration. The X-CSTP-* set is the server's
// reply; a client sends the request half to state what it can accept.
const (
	hdrVersion       = "X-CSTP-Version"
	hdrAddress       = "X-CSTP-Address"
	hdrNetmask       = "X-CSTP-Netmask"
	hdrDNS           = "X-CSTP-DNS"
	hdrMTU           = "X-CSTP-MTU"
	hdrBaseMTU       = "X-CSTP-Base-MTU"
	hdrAddressType   = "X-CSTP-Address-Type"
	hdrSplitInclude  = "X-CSTP-Split-Include"
	hdrDefaultDomain = "X-CSTP-Default-Domain"
	hdrDPD           = "X-CSTP-DPD"
	hdrKeepalive     = "X-CSTP-Keepalive"
	hdrDisconnected  = "X-CSTP-Disconnected-Timeout"
	hdrSessTimeout   = "X-CSTP-Session-Timeout"
	hdrIdleTimeout   = "X-CSTP-Idle-Timeout"
	hdrHostname      = "X-CSTP-Hostname"
	hdrLease         = "X-CSTP-Lease-Duration"
)

// defaultMTU is the inner MTU veepin assigns when acting as the server. It
// leaves room for the CSTP header, the TLS record overhead and the IP/TCP
// carrier inside a 1500-octet path.
const defaultMTU = 1400

// buildConnectRequest constructs the CONNECT that turns the authenticated HTTPS
// connection into a tunnel.
func buildConnectRequest(host, cookie, hostname string, baseMTU int) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodConnect, "https://"+host+tunnelPath, nil)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: build CONNECT: %w", err)
	}
	req.Host = host
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cookie", sessionCookie+"="+cookie)
	req.Header.Set(hdrVersion, "1")
	req.Header.Set(hdrHostname, hostname)
	req.Header.Set(hdrBaseMTU, strconv.Itoa(baseMTU))
	req.Header.Set(hdrMTU, strconv.Itoa(baseMTU))
	// IPv4 only: the data path forwards IPv4, so asking for an IPv6 address would
	// mean accepting one veepin cannot route.
	req.Header.Set(hdrAddressType, "IPv4")
	return req, nil
}

// userAgent identifies veepin as an AnyConnect client. Servers parse this and
// some gate features on recognising the product name, so it follows the shape
// OpenConnect uses.
const userAgent = "AnyConnect-compatible veepin agent " + clientVersion

// parseTunnelConfig reads the addressing out of a CONNECT response's headers.
func parseTunnelConfig(h http.Header) (TunnelConfig, error) {
	var cfg TunnelConfig
	addr := h.Get(hdrAddress)
	if addr == "" {
		return cfg, fmt.Errorf("anyconnect: server assigned no address (%s missing)", hdrAddress)
	}
	cfg.Address = net.ParseIP(addr)
	if cfg.Address == nil {
		return cfg, fmt.Errorf("anyconnect: server sent an unparseable address %q", addr)
	}
	if mask := h.Get(hdrNetmask); mask != "" {
		cfg.Netmask = net.ParseIP(mask)
	}
	if cfg.Netmask == nil {
		cfg.Netmask = net.IPv4(255, 255, 255, 255)
	}
	// DNS servers arrive as repeated headers, and some servers instead comma-join
	// them into one, so both shapes are accepted.
	for _, v := range h.Values(hdrDNS) {
		for s := range strings.SplitSeq(v, ",") {
			if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	}
	cfg.MTU = defaultMTU
	if v := h.Get(hdrMTU); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MTU = n
		}
	}
	for _, v := range h.Values(hdrSplitInclude) {
		for s := range strings.SplitSeq(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.SplitInclude = append(cfg.SplitInclude, s)
			}
		}
	}
	cfg.Domains = h.Get(hdrDefaultDomain)
	return cfg, nil
}

// writeTunnelConfig renders a server's assignment as CONNECT response headers.
func writeTunnelConfig(h *headerList, cfg TunnelConfig, dpd, keepalive int) {
	h.set(hdrVersion, "1")
	h.set(hdrAddress, cfg.Address.String())
	h.set(hdrNetmask, cfg.Netmask.String())
	for _, ip := range cfg.DNS {
		h.add(hdrDNS, ip.String())
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	h.setInt(hdrMTU, mtu)
	h.setInt(hdrBaseMTU, mtu)
	for _, r := range cfg.SplitInclude {
		h.add(hdrSplitInclude, r)
	}
	if cfg.Domains != "" {
		h.set(hdrDefaultDomain, cfg.Domains)
	}
	h.setInt(hdrDPD, dpd)
	h.setInt(hdrKeepalive, keepalive)
	// Zero disables each timeout: veepin holds a session for as long as its
	// connection lives rather than expiring it on a clock.
	h.set(hdrSessTimeout, "0")
	h.set(hdrIdleTimeout, "0")
	h.set(hdrDisconnected, "0")
	h.set(hdrLease, "0")
}
