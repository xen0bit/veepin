package anyconnect

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestMarshalParseRoundTrip(t *testing.T) {
	payload := []byte("an IP packet, notionally")
	frame := marshal(typeData, payload)

	if got := frame[:4]; !bytes.Equal(got, magic[:]) {
		t.Errorf("magic = %x, want %x", got, magic)
	}
	typ, length, err := parseHeader(frame)
	if err != nil {
		t.Fatal(err)
	}
	if typ != typeData {
		t.Errorf("type = %#x, want %#x", typ, typeData)
	}
	if length != len(payload) {
		t.Errorf("length = %d, want %d", length, len(payload))
	}
}

// TestReadPacketStream: packets are read one at a time out of a single stream,
// including a zero-length one, since keepalives carry no payload.
func TestReadPacketStream(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(marshal(typeData, []byte("first")))
	buf.Write(marshal(typeKeepalive, nil))
	buf.Write(marshal(typeDPDReq, []byte("probe")))

	want := []struct {
		typ     byte
		payload string
	}{
		{typeData, "first"},
		{typeKeepalive, ""},
		{typeDPDReq, "probe"},
	}
	for i, w := range want {
		typ, payload, err := readPacket(&buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if typ != w.typ || string(payload) != w.payload {
			t.Errorf("packet %d = (%#x, %q), want (%#x, %q)", i, typ, payload, w.typ, w.payload)
		}
	}
	if _, _, err := readPacket(&buf); err != io.EOF {
		t.Errorf("after the last packet, err = %v, want EOF", err)
	}
}

func TestParseHeaderRejectsBadMagic(t *testing.T) {
	bad := marshal(typeData, []byte("x"))
	bad[1] = 'X'
	if _, _, err := parseHeader(bad); err == nil {
		t.Error("parseHeader accepted a packet with corrupt magic")
	}
	if _, _, err := parseHeader([]byte{'S', 'T'}); err == nil {
		t.Error("parseHeader accepted a truncated header")
	}
}

// TestResponseHeadersKeepProtocolCasing guards the interop bug this cost:
// net/http canonicalizes X-CSTP-MTU to X-Cstp-Mtu, and AnyConnect clients match
// these names case-sensitively — openconnect reports "No MTU received" and
// aborts. Responses must therefore go out with the protocol's own casing.
func TestResponseHeadersKeepProtocolCasing(t *testing.T) {
	var h headerList
	writeTunnelConfig(&h, TunnelConfig{
		Address: parseIP(t, "10.11.0.2"),
		Netmask: parseIP(t, "255.255.255.0"),
		MTU:     1400,
	}, 30, 20)

	var buf bytes.Buffer
	if err := writeConnectOK(&buf, h); err != nil {
		t.Fatal(err)
	}
	wire := buf.String()
	for _, name := range []string{hdrMTU, hdrAddress, hdrNetmask, hdrDPD} {
		if !strings.Contains(wire, "\r\n"+name+": ") {
			t.Errorf("response is missing %q with its protocol casing:\n%s", name, wire)
		}
	}
}

// TestParseTunnelConfig reads a server's assignment the way a real one sends it:
// repeated DNS headers, a split-include route, and an MTU.
func TestParseTunnelConfig(t *testing.T) {
	h := http.Header{}
	h.Set(hdrAddress, "10.12.0.5")
	h.Set(hdrNetmask, "255.255.255.0")
	h.Add(hdrDNS, "8.8.8.8")
	h.Add(hdrDNS, "1.1.1.1")
	h.Set(hdrMTU, "1300")
	h.Add(hdrSplitInclude, "192.168.0.0/16")

	cfg, err := parseTunnelConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Address.Equal(parseIP(t, "10.12.0.5")) {
		t.Errorf("Address = %v", cfg.Address)
	}
	if len(cfg.DNS) != 2 {
		t.Errorf("DNS = %v, want two servers", cfg.DNS)
	}
	if cfg.MTU != 1300 {
		t.Errorf("MTU = %d, want 1300", cfg.MTU)
	}
	if len(cfg.SplitInclude) != 1 || cfg.SplitInclude[0] != "192.168.0.0/16" {
		t.Errorf("SplitInclude = %v", cfg.SplitInclude)
	}

	// A response with no address is not a usable tunnel.
	if _, err := parseTunnelConfig(http.Header{}); err == nil {
		t.Error("parseTunnelConfig accepted a response with no address")
	}
}

// TestAuthExchangeRoundTrip: the form a veepin server presents must be one a
// veepin client can answer, and the answers must come back out by name.
func TestAuthExchangeRoundTrip(t *testing.T) {
	served, err := marshalConfigAuth(credentialForm())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseConfigAuth(served)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Type != "auth-request" || parsed.Auth.Form == nil {
		t.Fatalf("parsed = %+v, want an auth-request with a form", parsed)
	}

	replied, err := marshalConfigAuth(answerForm(parsed.Auth.Form, "alice", "s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := parseConfigAuth(replied)
	if err != nil {
		t.Fatal(err)
	}
	if got := reply.Auth.field("username"); got != "alice" {
		t.Errorf("username = %q, want alice", got)
	}
	if got := reply.Auth.field("password"); got != "s3cret" {
		t.Errorf("password = %q, want s3cret", got)
	}
}

// TestCompleteMessageOmitsEmptyForm guards the other interop bug this cost: Go
// renders a zero-valued struct field as <form method="" action=""/>, which
// openconnect reads as a malformed form it cannot handle rather than as absent.
func TestCompleteMessageOmitsEmptyForm(t *testing.T) {
	body, err := marshalConfigAuth(completeMessage("id", "token"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "<form") {
		t.Errorf("completion message carries an empty form:\n%s", body)
	}
	if !strings.Contains(string(body), "<session-token>token</session-token>") {
		t.Errorf("completion message is missing the session token:\n%s", body)
	}
}

func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}
