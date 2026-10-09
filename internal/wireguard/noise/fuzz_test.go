package noise

import (
	"net/netip"
	"testing"
)

// FuzzCookieReplies feeds arbitrary datagrams to both ends of the cookie
// exchange: an initiator's ConsumeCookieReply, which reads whatever arrives
// addressed to its index, and a responder's mac checks and reply builder, which
// run on every initiation-sized datagram under load. All of it is
// attacker-controlled; none of it may panic, and none of it may accept what it
// did not authenticate.
func FuzzCookieReplies(f *testing.F) {
	var initStatic, respStatic [KeySize]byte
	for i := range initStatic {
		initStatic[i] = byte(i + 1)
		respStatic[i] = byte(i + 100)
	}
	respPub, err := PublicKey(respStatic)
	if err != nil {
		f.Fatal(err)
	}
	checker, err := NewCookieChecker(respStatic, 0)
	if err != nil {
		f.Fatal(err)
	}
	src := netip.MustParseAddrPort("192.0.2.1:51820")

	seed, _ := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
	init, err := seed.Initiation()
	if err != nil {
		f.Fatal(err)
	}
	reply, err := checker.CookieReply(init, src)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(init)
	f.Add(reply)
	f.Add([]byte{3, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		i, err := NewInitiator(Config{LocalStatic: initStatic, RemoteStatic: respPub})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := i.Initiation(); err != nil {
			t.Fatal(err)
		}
		if _, err := i.ConsumeCookieReply(data); err == nil {
			t.Fatal("a cookie reply for an initiation nobody saw authenticated")
		}
		if checker.CheckMAC1(data) {
			if _, err := checker.CookieReply(data, src); err != nil {
				t.Fatalf("CookieReply refused a message that passed CheckMAC1: %v", err)
			}
		}
		_ = checker.CheckMAC2(data, src)
	})
}
