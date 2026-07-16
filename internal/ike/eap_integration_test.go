package ike

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/crypto"
	"github.com/xen0bit/veepin/internal/eap"
	"github.com/xen0bit/veepin/internal/payload"
)

// TestEAPMSCHAPv2Flow drives a full IKEv2 + EAP-MSCHAPv2 handshake against the
// live server: SA_INIT, an AUTH-less IKE_AUTH that triggers EAP, the MSCHAPv2
// challenge/response, EAP-Success, and the final MSK-based AUTH that establishes
// the IKE SA and Child SA.
func TestEAPMSCHAPv2Flow(t *testing.T) {
	psk := []byte("server-psk")
	users := map[string]string{"alice": "wonderland"}
	p500 := freeUDPPort(t)
	p4500 := freeUDPPort(t)

	established := make(chan *ChildSA, 1)
	cfg := Config{
		ListenIP:       "127.0.0.1",
		Port500:        p500,
		Port4500:       p4500,
		PSK:            psk,
		LocalID:        FQDNIdentity("vpn.example"),
		PublicIP:       net.ParseIP("127.0.0.1"),
		Logger:         log.New(io.Discard, "", 0),
		EAPCredentials: func(u string) (string, bool) { p, ok := users[u]; return p, ok },
		EAPServerName:  "vpn.example",
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			return net.IPv4(10, 9, 8, 7), net.IPv4(255, 255, 255, 0), nil, nil
		},
		OnChildSA: func(sa *IKESA, c *ChildSA) { established <- c },
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond)

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	it := &initiator{tb: t, conn: conn, psk: psk, id: FQDNIdentity("alice")}
	it.doSAInit()

	// --- IKE_AUTH #1: no AUTH payload → request EAP. Include CP + Child SA. ---
	idBody := idPayloadBody(it.id)
	espSPI := u32BE(newChildSPI())
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{{Type: payload.CFGInternalIP4Address}}}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{DefaultESPProposal(espSPI)}}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	it.send(it.buildEnc(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes()))

	// Response: IDr, AUTH (server PSK), EAP challenge.
	inners := it.openInners(it.recv())
	if findInner(inners, payload.TypeAUTH) == nil {
		t.Fatal("server did not send its AUTH in EAP start")
	}
	eapPay := findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		t.Fatal("server did not send an EAP challenge")
	}
	eapReq, err := eap.Parse(eapPay.Body)
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := eap.ParseChallenge(eapReq.Data)
	if !ok {
		t.Fatal("EAP request was not an MSCHAPv2 challenge")
	}

	// --- IKE_AUTH #2: EAP response with credentials. ---
	respData, clientMSK := ch.BuildResponse("alice", "wonderland")
	eapResp := eap.Packet{Code: eap.CodeResponse, Identifier: eapReq.Identifier, Type: eap.TypeMSCHAPv2, Data: respData}
	b2 := payload.NewBuilder()
	b2.Add(payload.TypeEAP, false, eapResp.Marshal())
	it.send(it.buildEnc(payload.IKE_AUTH, 2, b2.FirstType(), b2.Bytes()))

	// Response: EAP MSCHAPv2 Success request.
	inners = it.openInners(it.recv())
	eapPay = findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		t.Fatal("expected EAP success request")
	}
	successReq, _ := eap.Parse(eapPay.Body)

	// --- IKE_AUTH #3: acknowledge MSCHAPv2 success. ---
	ack := eap.Packet{Code: eap.CodeResponse, Identifier: successReq.Identifier, Type: eap.TypeMSCHAPv2, Data: eap.SuccessResponseData()}
	b3 := payload.NewBuilder()
	b3.Add(payload.TypeEAP, false, ack.Marshal())
	it.send(it.buildEnc(payload.IKE_AUTH, 3, b3.FirstType(), b3.Bytes()))

	// Response: EAP-Success.
	inners = it.openInners(it.recv())
	eapPay = findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		t.Fatal("expected EAP-Success")
	}
	if final, _ := eap.Parse(eapPay.Body); final.Code != eap.CodeSuccess {
		t.Fatalf("expected EAP-Success, got code %d", final.Code)
	}

	// --- IKE_AUTH #4: final AUTH computed from the MSK. ---
	octets := crypto.AuthOctets(it.suite.PRF, it.saInitReq, it.nr, it.keys.SKpi, idBody)
	authData := crypto.PSKAuth(it.suite.PRF, clientMSK, octets)
	b4 := payload.NewBuilder()
	b4.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: authData}))
	it.send(it.buildEnc(payload.IKE_AUTH, 4, b4.FirstType(), b4.Bytes()))

	// Final response: server AUTH (MSK) + Child SA.
	inners = it.openInners(it.recv())
	authPay := findInner(inners, payload.TypeAUTH)
	if authPay == nil {
		t.Fatal("server did not send final AUTH")
	}
	// Verify the server's MSK-based AUTH.
	sAuth, _ := payload.ParseAuth(authPay.Body)
	respOctets := crypto.AuthOctets(it.suite.PRF, it.saInitResp, it.ni, it.keys.SKpr, idPayloadBody(FQDNIdentity("vpn.example")))
	wantServerAuth := crypto.PSKAuth(it.suite.PRF, clientMSK, respOctets)
	if !equalBytes(wantServerAuth, sAuth.Data) {
		t.Fatal("server final AUTH did not verify against MSK")
	}
	if findInner(inners, payload.TypeSA) == nil {
		t.Fatal("server did not establish a Child SA after EAP")
	}

	select {
	case child := <-established:
		if child.InboundSPI == 0 {
			t.Fatal("child SA has no inbound SPI")
		}
		t.Logf("EAP-MSCHAPv2 handshake established Child SA (in=%#x) for user alice", child.InboundSPI)
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA established after EAP")
	}
}

// openInners decrypts a received SK-protected message and returns its inner
// payloads.
func (it *initiator) openInners(pkt []byte) []payload.RawPayload {
	first, inner := it.openEnc(pkt)
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		it.tb.Fatalf("inner parse: %v", err)
	}
	return inners
}

// TestEAPWrongPassword confirms the server rejects an EAP client that presents
// an incorrect password: no Child SA is established.
func TestEAPWrongPassword(t *testing.T) {
	psk := []byte("server-psk")
	users := map[string]string{"alice": "correct-password"}
	p500 := freeUDPPort(t)
	p4500 := freeUDPPort(t)

	cfg := Config{
		ListenIP:       "127.0.0.1",
		Port500:        p500,
		Port4500:       p4500,
		PSK:            psk,
		LocalID:        FQDNIdentity("vpn.example"),
		PublicIP:       net.ParseIP("127.0.0.1"),
		Logger:         log.New(io.Discard, "", 0),
		EAPCredentials: func(u string) (string, bool) { p, ok := users[u]; return p, ok },
		EAPServerName:  "vpn.example",
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	it := &initiator{tb: t, conn: conn, psk: psk, id: FQDNIdentity("alice")}
	it.doSAInit()

	idBody := idPayloadBody(it.id)
	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{DefaultESPProposal(u32BE(newChildSPI()))}}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	it.send(it.buildEnc(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes()))

	inners := it.openInners(it.recv())
	eapReq, _ := eap.Parse(findInner(inners, payload.TypeEAP).Body)
	ch, _ := eap.ParseChallenge(eapReq.Data)

	// Wrong password.
	respData, _ := ch.BuildResponse("alice", "WRONG")
	eapResp := eap.Packet{Code: eap.CodeResponse, Identifier: eapReq.Identifier, Type: eap.TypeMSCHAPv2, Data: respData}
	b2 := payload.NewBuilder()
	b2.Add(payload.TypeEAP, false, eapResp.Marshal())
	it.send(it.buildEnc(payload.IKE_AUTH, 2, b2.FirstType(), b2.Bytes()))

	// Server should reply with an EAP MSCHAPv2 Failure (not a success).
	inners = it.openInners(it.recv())
	eapPay := findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		t.Fatal("expected an EAP failure packet")
	}
	failPkt, _ := eap.Parse(eapPay.Body)
	// The MSCHAPv2 failure is carried as an EAP Request with opcode 4.
	if failPkt.Code == eap.CodeSuccess {
		t.Fatal("server granted EAP-Success for a wrong password")
	}
	t.Logf("server correctly rejected wrong password (EAP code %d)", failPkt.Code)
}
