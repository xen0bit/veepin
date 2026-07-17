package ppp

import (
	"net"
	"testing"

	"github.com/xen0bit/veepin/internal/mschap"
)

// captureTransport records the frames the session sends.
type captureTransport struct{ frames [][]byte }

func (c *captureTransport) SendPPP(frame []byte) error {
	c.frames = append(c.frames, append([]byte(nil), frame...))
	return nil
}

// lastCP pops the most recent sent frame and decodes it as a control-protocol
// packet, asserting its PPP protocol.
func (c *captureTransport) lastCP(t *testing.T, wantProto uint16) cpPacket {
	t.Helper()
	if len(c.frames) == 0 {
		t.Fatal("no frame sent")
	}
	frame := c.frames[len(c.frames)-1]
	proto, payload, ok := decodeFrame(frame)
	if !ok || proto != wantProto {
		t.Fatalf("frame protocol = %#x, want %#x", proto, wantProto)
	}
	pkt, ok := parseCP(payload)
	if !ok {
		t.Fatal("malformed control packet")
	}
	return pkt
}

type recordHandler struct {
	ntResponse [mschap.NTResponseLen]byte
	authed     bool
	cfg        IPConfig
	up         bool
	err        error
}

func (r *recordHandler) Authenticated(nt [mschap.NTResponseLen]byte) {
	r.authed = true
	r.ntResponse = nt
}
func (r *recordHandler) NetworkUp(cfg IPConfig) { r.up = true; r.cfg = cfg }
func (r *recordHandler) Closed(err error)       { r.err = err }

// deliver feeds a server-originated control packet to the session.
func deliver(s *Session, protocol uint16, code, id byte, body []byte) {
	s.Receive(encodeFrame(protocol, cpPacket{Code: code, ID: id, Body: body}.marshal()))
}

// TestFullNegotiation drives a scripted server through LCP, MS-CHAPv2, and IPCP,
// checking the client's responses and that it surfaces the assigned IP, DNS, and
// the NT response the crypto binding needs.
func TestFullNegotiation(t *testing.T) {
	const username, password = "User", "clientPass"
	tr := &captureTransport{}
	h := &recordHandler{}
	s := New(username, password, tr, h)

	// 1. Start -> LCP Configure-Request.
	s.Start()
	req := tr.lastCP(t, ProtocolLCP)
	if req.Code != codeConfigureRequest {
		t.Fatalf("first packet code = %d, want Configure-Request", req.Code)
	}

	// 2. Server acks our LCP request, and sends its own with MS-CHAPv2 auth.
	deliver(s, ProtocolLCP, codeConfigureAck, req.ID, req.Body)
	serverLCP := marshalOptions([]option{
		{Type: optMRU, Value: []byte{0x05, 0xdc}},
		{Type: optAuthProto, Value: authMSCHAPv2},
		{Type: optMagic, Value: []byte{1, 2, 3, 4}},
	})
	deliver(s, ProtocolLCP, codeConfigureRequest, 7, serverLCP)
	if ack := tr.lastCP(t, ProtocolLCP); ack.Code != codeConfigureAck || ack.ID != 7 {
		t.Fatalf("expected LCP Ack for id 7, got code %d id %d", ack.Code, ack.ID)
	}

	// 3. Server sends the MS-CHAPv2 challenge; client must respond.
	var authCh [16]byte
	for i := range authCh {
		authCh[i] = byte(i + 1)
	}
	challengeBody := append([]byte{16}, authCh[:]...)
	challengeBody = append(challengeBody, "server"...)
	deliver(s, ProtocolCHAP, chapChallenge, 9, challengeBody)

	resp := tr.lastCP(t, ProtocolCHAP)
	if resp.Code != chapResponse || resp.ID != 9 {
		t.Fatalf("expected CHAP Response id 9, got code %d id %d", resp.Code, resp.ID)
	}
	// Extract the peer challenge and NT response the client generated.
	if len(resp.Body) < 1+mschapResponseValueLen || resp.Body[0] != mschapResponseValueLen {
		t.Fatalf("CHAP response value size = %d, want %d", resp.Body[0], mschapResponseValueLen)
	}
	var peerCh [16]byte
	var ntResp [mschap.NTResponseLen]byte
	copy(peerCh[:], resp.Body[1:17])
	copy(ntResp[:], resp.Body[25:49])
	if string(resp.Body[50:]) != username {
		t.Errorf("CHAP response name = %q, want %q", resp.Body[50:], username)
	}

	// 4. Server proves itself with the matching authenticator response.
	authString := mschap.AuthenticatorResponse(authCh, peerCh, username, password, ntResp)
	deliver(s, ProtocolCHAP, chapSuccess, 9, []byte(authString+" M=Welcome"))
	if !h.authed {
		t.Fatal("Authenticated event not fired")
	}
	if h.ntResponse != ntResp {
		t.Error("Authenticated NT response does not match the one sent")
	}

	// 5. Client starts IPCP; server naks with the assigned IP and DNS.
	ipcpReq := tr.lastCP(t, ProtocolIPCP)
	if ipcpReq.Code != codeConfigureRequest {
		t.Fatalf("expected IPCP Configure-Request, got code %d", ipcpReq.Code)
	}
	nak := marshalOptions([]option{
		{Type: optIPAddress, Value: []byte{10, 0, 0, 5}},
		{Type: optPrimaryDNS, Value: []byte{8, 8, 8, 8}},
		{Type: optSecondaryDNS, Value: []byte{0, 0, 0, 0}},
	})
	deliver(s, ProtocolIPCP, codeConfigureNak, ipcpReq.ID, nak)

	// Client resends with the adopted values; server acks it.
	ipcpReq2 := tr.lastCP(t, ProtocolIPCP)
	if ipcpReq2.Code != codeConfigureRequest {
		t.Fatalf("expected resent IPCP Configure-Request, got code %d", ipcpReq2.Code)
	}
	deliver(s, ProtocolIPCP, codeConfigureAck, ipcpReq2.ID, ipcpReq2.Body)

	// Server sends its own IPCP request; client acks and the network comes up.
	deliver(s, ProtocolIPCP, codeConfigureRequest, 20, marshalOptions([]option{
		{Type: optIPAddress, Value: []byte{10, 0, 0, 1}},
	}))

	if !h.up {
		t.Fatal("NetworkUp event not fired")
	}
	if !h.cfg.LocalIP.Equal(net.IPv4(10, 0, 0, 5)) {
		t.Errorf("assigned IP = %v, want 10.0.0.5", h.cfg.LocalIP)
	}
	if len(h.cfg.DNS) != 1 || !h.cfg.DNS[0].Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("DNS = %v, want [8.8.8.8]", h.cfg.DNS)
	}
	if h.err != nil {
		t.Errorf("unexpected Closed(%v)", h.err)
	}
}

// TestAuthFailure checks a CHAP Failure surfaces as a Closed error.
func TestAuthFailure(t *testing.T) {
	tr := &captureTransport{}
	h := &recordHandler{}
	s := New("User", "wrong", tr, h)
	s.Start()

	// Skip straight to auth by opening LCP both ways.
	req := tr.lastCP(t, ProtocolLCP)
	deliver(s, ProtocolLCP, codeConfigureAck, req.ID, req.Body)
	deliver(s, ProtocolLCP, codeConfigureRequest, 1, marshalOptions([]option{
		{Type: optAuthProto, Value: authMSCHAPv2},
	}))
	var authCh [16]byte
	deliver(s, ProtocolCHAP, chapChallenge, 2, append([]byte{16}, authCh[:]...))
	deliver(s, ProtocolCHAP, chapFailure, 2, []byte("E=691 R=0 C=00 V=3 M=Access denied"))

	if h.err == nil {
		t.Fatal("expected Closed error on auth failure")
	}
	if h.up {
		t.Error("NetworkUp should not fire on auth failure")
	}
}

// TestLCPAuthNakToMSCHAPv2 checks that when the server offers an auth protocol we
// do not implement (PAP here), the client Configure-Naks it proposing MS-CHAPv2
// rather than rejecting and failing — the negotiation SoftEther requires.
func TestLCPAuthNakToMSCHAPv2(t *testing.T) {
	tr := &captureTransport{}
	h := &recordHandler{}
	s := New("User", "pass", tr, h)
	s.Start()

	pap := marshalOptions([]option{{Type: optAuthProto, Value: []byte{0xc0, 0x23}}})
	deliver(s, ProtocolLCP, codeConfigureRequest, 1, pap)

	nak := tr.lastCP(t, ProtocolLCP)
	if nak.Code != codeConfigureNak {
		t.Fatalf("expected Configure-Nak, got code %d", nak.Code)
	}
	opts, ok := parseOptions(nak.Body)
	if !ok || len(opts) != 1 || opts[0].Type != optAuthProto || string(opts[0].Value) != string(authMSCHAPv2) {
		t.Fatalf("Nak should propose MS-CHAPv2, got body %x", nak.Body)
	}
	if h.err != nil {
		t.Errorf("unexpected Closed(%v) — must keep negotiating", h.err)
	}
}

// TestLCPRejectDropsMagic checks that a Configure-Reject of our Magic-Number
// option (SoftEther does this) makes the client resend without it, instead of
// looping on the same rejected request forever.
func TestLCPRejectDropsMagic(t *testing.T) {
	tr := &captureTransport{}
	h := &recordHandler{}
	s := New("User", "pass", tr, h)
	s.Start()

	first := tr.lastCP(t, ProtocolLCP)
	opts, _ := parseOptions(first.Body)
	var magicOpt option
	for _, o := range opts {
		if o.Type == optMagic {
			magicOpt = o
		}
	}
	if magicOpt.Type != optMagic {
		t.Fatal("first LCP request carried no Magic-Number option")
	}

	deliver(s, ProtocolLCP, codeConfigureReject, first.ID, marshalOptions([]option{magicOpt}))

	resent := tr.lastCP(t, ProtocolLCP)
	if resent.Code != codeConfigureRequest {
		t.Fatalf("expected a resent Configure-Request, got code %d", resent.Code)
	}
	ropts, _ := parseOptions(resent.Body)
	for _, o := range ropts {
		if o.Type == optMagic {
			t.Error("resent request still contains Magic-Number after a Reject")
		}
	}
}

// TestIPFrameHelpers checks the IP encapsulation round-trips.
func TestIPFrameHelpers(t *testing.T) {
	pkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	frame := EncapsulateIP(pkt)
	got, ok := IsIP(frame)
	if !ok {
		t.Fatal("IsIP did not recognise an IP frame")
	}
	if string(got) != string(pkt) {
		t.Errorf("round trip = %x, want %x", got, pkt)
	}
	if _, ok := IsIP(encodeFrame(ProtocolLCP, []byte{1, 2})); ok {
		t.Error("IsIP matched an LCP frame")
	}
}
