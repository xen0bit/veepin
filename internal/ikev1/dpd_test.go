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
