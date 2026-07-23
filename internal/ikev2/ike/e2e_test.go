package ike

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// TestEndToEndHandshake drives a full IKE_SA_INIT + IKE_AUTH exchange as an
// initiator against a live Server, then verifies a Child SA was established and
// exercises an INFORMATIONAL liveness probe. This is the top-level proof that
// the responder state machine, key derivation, SK protection and payload codec
// all interoperate.
func TestEndToEndHandshake(t *testing.T) {
	psk := []byte("correct horse battery staple")

	// Pick free UDP ports for the IKE and NAT-T sockets.
	p500 := freeUDPPort(t)
	p4500 := freeUDPPort(t)

	childCh := make(chan *ChildSA, 1)
	cfg := Config{
		ListenIP:  "127.0.0.1",
		Port500:   p500,
		Port4500:  p4500,
		PSK:       psk,
		LocalID:   FQDNIdentity("responder.test"),
		Logger:    log.New(io.Discard, "", 0),
		OnChildSA: func(sa *IKESA, c *ChildSA) { childCh <- c },
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond) // let sockets bind

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500}

	// --- Initiator socket ---
	cli, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))

	it := &initiator{tb: t, conn: cli, psk: psk, id: FQDNIdentity("initiator.test")}
	it.doSAInit()
	it.doAuth()

	select {
	case child := <-childCh:
		if child.OutboundSPI == 0 || child.InboundSPI == 0 {
			t.Fatalf("child SPIs not set: in=%#x out=%#x", child.InboundSPI, child.OutboundSPI)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA established")
	}

	it.doLiveness()
}

// initiator is a minimal IKEv2 initiator used only for testing.
type initiator struct {
	tb   testing.TB
	conn *net.UDPConn
	psk  []byte
	id   Identity

	spiI, spiR uint64
	suite      Suite
	dh         cryptoutil.DHGroup
	ni, nr     []byte
	keys       SAKeys
	saInitReq  []byte
	saInitResp []byte
	sendMsgID  uint32

	// advertiseFrag makes doSAInit send IKE_FRAGMENTATION_SUPPORTED (RFC 7383);
	// fragAck records whether the responder echoed it. Off by default so the
	// existing tests exercise the unfragmented path unchanged.
	advertiseFrag bool
	fragAck       bool

	// Child SA results.
	assignedIP                net.IP
	childOutSPI, childRespSPI uint32
	childES                   ESPSuite
	childEncI, childIntegI    []byte
	childEncR, childIntegR    []byte
}

func (it *initiator) send(pkt []byte) {
	if _, err := it.conn.Write(pkt); err != nil {
		it.tb.Fatalf("initiator send: %v", err)
	}
}

func (it *initiator) recv() []byte {
	buf := make([]byte, 65535)
	n, err := it.conn.Read(buf)
	if err != nil {
		it.tb.Fatalf("initiator recv: %v", err)
	}
	return buf[:n]
}

func (it *initiator) doSAInit() {
	it.spiI = newIKESPI()
	dh, err := transform.DH(payload.DH_CURVE25519)
	if err != nil {
		it.tb.Fatal(err)
	}
	it.dh = dh
	pub, err := dh.Generate()
	if err != nil {
		it.tb.Fatal(err)
	}
	it.ni = randomNonce(32)

	prop := DefaultIKEProposal()
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{prop}}))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: payload.DH_CURVE25519, KeyData: pub}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(it.ni))
	// NAT detection payloads (as a real client behind NAT would send). We fake
	// hashes; the server just records whether they match its own view.
	local := it.conn.LocalAddr().(*net.UDPAddr)
	srcHash := natDetectionHash(it.spiI, 0, local.IP, uint16(local.Port))
	dstHash := natDetectionHash(it.spiI, 0, net.IPv4zero, 0)
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP, Data: srcHash,
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP, Data: dstHash,
	}))
	if it.advertiseFrag {
		addFragSupported(b)
	}
	chain := b.Bytes()

	hdr := payload.Header{
		InitiatorSPI: it.spiI,
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: payload.IKE_SA_INIT,
		Flags:        payload.FlagInitiator,
		MessageID:    0,
		Length:       uint32(payload.HeaderLen + len(chain)),
	}
	req := append(hdr.Marshal(nil), chain...)
	it.saInitReq = req
	it.send(req)

	resp := it.recv()
	it.saInitResp = append([]byte(nil), resp...)
	msg, err := payload.ParseMessage(resp)
	if err != nil {
		it.tb.Fatalf("SA_INIT resp parse: %v", err)
	}
	it.spiR = msg.Header.ResponderSPI
	it.fragAck = findFragSupported(msg.Payloads)

	saPay := msg.Find(payload.TypeSA)
	kePay := msg.Find(payload.TypeKE)
	noncePay := msg.Find(payload.TypeNonce)
	if saPay == nil || kePay == nil || noncePay == nil {
		it.tb.Fatalf("SA_INIT resp missing payloads")
		return
	}
	sa, err := payload.ParseSA(saPay.Body)
	if err != nil {
		it.tb.Fatal(err)
	}
	suite, _, err := SelectIKESuite(sa)
	if err != nil {
		it.tb.Fatalf("initiator cannot resolve chosen suite: %v", err)
	}
	it.suite = suite

	ke, _ := payload.ParseKE(kePay.Body)
	shared, err := it.dh.ComputeSecret(ke.KeyData)
	if err != nil {
		it.tb.Fatal(err)
	}
	it.nr = payload.ParseNonce(noncePay.Body)

	_, keys := DeriveIKEKeys(suite.PRF, shared, it.ni, it.nr,
		it.spiI, it.spiR, suite.encKeyLen(), suite.integKeyLen())
	it.keys = keys
}

func (it *initiator) doAuth() {
	// Build inner payloads: IDi, AUTH, CP(CFG_REQUEST), SA(ESP), TSi, TSr.
	idBody := idPayloadBody(it.id)
	authData := computePSKAuth(it.suite.PRF, it.psk, it.saInitReq, it.nr, it.keys.SKpi, idBody)

	it.childOutSPI = newChildSPI()
	espSPI := u32BE(it.childOutSPI)
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}

	// CFG_REQUEST asking for an internal address, netmask and DNS.
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{
		{Type: payload.CFGInternalIP4Address},
		{Type: payload.CFGInternalIP4Netmask},
		{Type: payload.CFGInternalIP4DNS},
	}}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: authData,
	}))
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{DefaultESPProposal(espSPI)},
	}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))

	it.sendMsgID = 1
	pkt := it.buildEnc(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes())
	it.send(pkt)

	resp := it.recv()
	first, inner := it.openEnc(resp)
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		it.tb.Fatalf("AUTH resp inner parse: %v", err)
	}

	// Verify responder AUTH.
	idrPay := findInner(inners, payload.TypeIDr)
	authPay := findInner(inners, payload.TypeAUTH)
	if idrPay == nil || authPay == nil {
		it.tb.Fatalf("AUTH resp missing IDr/AUTH; got %d payloads", len(inners))
		return
	}
	ra, _ := payload.ParseAuth(authPay.Body)
	idr, _ := payload.ParseID(idrPay.Body)
	peerIDBody := idPayloadBody(Identity{Type: idr.Type, Data: idr.Data})
	if err := verifyPeerPSKAuth(it.suite.PRF, it.psk, it.saInitResp, it.ni,
		it.keys.SKpr, peerIDBody, ra.Data); err != nil {
		it.tb.Fatalf("responder AUTH verification failed: %v", err)
	}

	// Capture the assigned internal address from the CFG_REPLY.
	if cpPay := findInner(inners, payload.TypeCP); cpPay != nil {
		cp, perr := payload.ParseCP(cpPay.Body)
		if perr == nil {
			if v, ok := cp.AttrValue(payload.CFGInternalIP4Address); ok {
				it.assignedIP = net.IP(v).To4()
			}
		}
	}

	// Capture the negotiated Child SA (responder's inbound SPI = our outbound).
	saPay := findInner(inners, payload.TypeSA)
	if saPay == nil {
		it.tb.Fatalf("AUTH resp did not carry a Child SA")
		return
	}
	espSA, _ := payload.ParseSA(saPay.Body)
	es, _, serr := SelectESPSuite(espSA)
	if serr != nil {
		it.tb.Fatalf("initiator cannot resolve ESP suite: %v", serr)
	}
	it.childES = es
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		it.childRespSPI = beU32(espSA.Proposals[0].SPI)
	}
	// Derive the same Child keys the server derived.
	it.deriveChildKeys()
}

// deriveChildKeys computes the Child SA key material as the initiator, matching
// the responder's derivation (RFC 7296 2.17).
func (it *initiator) deriveChildKeys() {
	es := it.childES
	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	total := 2*encLen + 2*integLen
	km := DeriveChildKeys(it.suite.PRF, it.keys.SKd, nil, it.ni, it.nr, total)
	off := 0
	take := func(n int) []byte { b := km[off : off+n]; off += n; return b }
	it.childEncI = take(encLen)
	if integLen > 0 {
		it.childIntegI = take(integLen)
	}
	it.childEncR = take(encLen)
	if integLen > 0 {
		it.childIntegR = take(integLen)
	}
}

func (it *initiator) doLiveness() {
	it.sendMsgID = 2
	pkt := it.buildEnc(payload.INFORMATIONAL, 2, payload.NoNextPayload, nil)
	it.send(pkt)
	resp := it.recv()
	// Should decrypt to an empty inner chain.
	first, inner := it.openEnc(resp)
	if first != payload.NoNextPayload || len(inner) != 0 {
		it.tb.Fatalf("liveness resp not empty: first=%s len=%d", first, len(inner))
	}
}

// buildEnc seals an initiator->responder message.
func (it *initiator) buildEnc(ex payload.ExchangeType, msgID uint32,
	firstInner payload.PayloadType, innerChain []byte) []byte {

	hdr := payload.Header{
		InitiatorSPI: it.spiI,
		ResponderSPI: it.spiR,
		ExchangeType: ex,
		Flags:        payload.FlagInitiator,
		MessageID:    msgID,
	}
	pkt, err := buildEncryptedMessage(hdr, it.suite, it.keys, dirInitiatorToResponder, firstInner, innerChain)
	if err != nil {
		it.tb.Fatalf("initiator seal: %v", err)
	}
	return pkt
}

// openEnc opens a responder->initiator message.
func (it *initiator) openEnc(pkt []byte) (payload.PayloadType, []byte) {
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		it.tb.Fatalf("initiator parse resp: %v", err)
	}
	sk := msg.Find(payload.TypeSK)
	if sk == nil {
		it.tb.Fatalf("resp missing SK payload")
		return 0, nil
	}
	first, inner, err := decryptSK(pkt, msg.Header, *sk, it.suite, it.keys, dirResponderToInitiator)
	if err != nil {
		it.tb.Fatalf("initiator decrypt resp: %v", err)
	}
	return first, inner
}

// freeUDPPort returns an available UDP port on loopback.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}
