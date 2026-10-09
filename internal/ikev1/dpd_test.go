package ikev1

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestDPDNotifyRoundTrip(t *testing.T) {
	s := NewSession(Config{})
	s.initCookie = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	s.respCookie = [8]byte{9, 10, 11, 12, 13, 14, 15, 16}

	body := s.buildDPDNotify(notifyRUThere, 0x11223344)
	if binary.BigEndian.Uint32(body[0:4]) != doiIPsec || body[4] != protoISAKMP {
		t.Errorf("DOI/protocol = %d/%d", binary.BigEndian.Uint32(body[0:4]), body[4])
	}
	if body[5] != dpdSPILen {
		t.Errorf("SPI size = %d, want %d (the cookie pair)", body[5], dpdSPILen)
	}
	if string(body[8:16]) != string(s.initCookie[:]) || string(body[16:24]) != string(s.respCookie[:]) {
		t.Error("the SPI is not the cookie pair")
	}
	typ, seq, ok := parseDPDNotify(body)
	if !ok || typ != notifyRUThere || seq != 0x11223344 {
		t.Fatalf("parsed as (%d, %#x, %v)", typ, seq, ok)
	}
}

// TestParseDPDNotifyRejectsOthers: an ordinary status or error notification is
// not a DPD message, and reading a sequence number out of one would answer a
// question nobody asked.
func TestParseDPDNotifyRejectsOthers(t *testing.T) {
	s := NewSession(Config{})
	body := s.buildDPDNotify(notifyRUThere, 1)
	binary.BigEndian.PutUint16(body[6:8], 16384) // a plain status notification
	if _, _, ok := parseDPDNotify(body); ok {
		t.Error("a non-DPD notification parsed as DPD")
	}
	for i := range len(body) {
		if _, _, ok := parseDPDNotify(body[:i]); ok {
			t.Errorf("a %d-octet prefix parsed as DPD", i)
		}
	}
}

// TestPingNeedsAnEstablishedSession: before phase 2 completes the exchange
// itself is the liveness evidence, and there are no SKEYID_a-keyed informational
// messages to send.
func TestPingNeedsAnEstablishedSession(t *testing.T) {
	if _, err := NewSession(Config{}).Ping(); err == nil {
		t.Fatal("a fresh session answered Ping")
	}
}

// TestDPDOverAnEstablishedExchange runs a real R-U-THERE / R-U-THERE-ACK round
// trip between two live sessions.
func TestDPDOverAnEstablishedExchange(t *testing.T) {
	initCfg, respCfg := remoteAccessConfigs("alice", "password", []byte("group-secret"))
	p := newPair(t, initCfg, respCfg)
	p.run(t)

	p.mu.Lock()
	initErr, respErr := p.initErr, p.respErr
	p.mu.Unlock()
	if initErr != nil || respErr != nil {
		t.Fatalf("the exchange did not establish: initiator=%v responder=%v", initErr, respErr)
	}

	// Both directions: a gateway probes its clients as readily as the reverse.
	for _, side := range []struct {
		name string
		s    *Session
	}{{"initiator", p.initiator}, {"responder", p.responder}} {
		for round := range 2 {
			ack, err := side.s.Ping()
			if err != nil {
				t.Fatalf("%s Ping round %d: %v", side.name, round, err)
			}
			select {
			case <-ack:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s round %d: the peer never acknowledged", side.name, round)
			}
		}
	}
}

// TestOnlyAVerifiedMessageCountsAsAuthenticated pins the answer the gateways
// move a peer's address on. An established session's messages are routed to it
// by the initiator cookie, which is cleartext in every IKE header -- so if a
// tampered message, or one bearing only the right cookie, came back
// "authenticated", one datagram from anyone on the path would redirect where the
// gateway sends that client's IKE (and, for L2TP, its ESP).
func TestOnlyAVerifiedMessageCountsAsAuthenticated(t *testing.T) {
	initCfg, respCfg := remoteAccessConfigs("alice", "password", []byte("group-secret"))
	p := newPair(t, initCfg, respCfg)
	p.run(t)
	if p.initErr != nil || p.respErr != nil {
		t.Fatalf("the exchange did not establish: initiator=%v responder=%v", p.initErr, p.respErr)
	}

	sent := make(chan []byte, 4)
	tap := func(msg []byte) { sent <- msg }
	p.tap.Store(&tap)
	ack, err := p.initiator.Ping()
	if err != nil {
		t.Fatal(err)
	}
	<-ack
	ruThere := <-sent

	tampered := append([]byte(nil), ruThere...)
	tampered[len(tampered)-1] ^= 1
	if p.responder.HandleInbound(tampered) {
		t.Error("a DPD message that fails to decrypt and verify was reported authenticated")
	}

	cookieOnly := append([]byte(nil), ruThere[:28]...) // the header, cookies and all
	cookieOnly = append(cookieOnly, make([]byte, 32)...)
	if p.responder.HandleInbound(cookieOnly) {
		t.Error("a message carrying nothing but the session's cookies was reported authenticated")
	}

	// A genuine R-U-THERE, as the initiator built it, is the one that counts.
	// (Resent here: the responder already answered the first copy, and DPD
	// tolerates a duplicate, which is what a retransmission looks like.)
	if !p.responder.HandleInbound(ruThere) {
		t.Error("a genuine DPD message under the established SA was not reported authenticated")
	}
}
