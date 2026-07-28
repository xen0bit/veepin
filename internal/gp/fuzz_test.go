package gp

import (
	"net"
	"testing"
)

// Every parser here reads bytes off a peer that may be hostile or simply a
// different PAN-OS version. A panic on malformed input is a denial of service;
// each of these must reject or round-trip, never crash.

func FuzzParseFrame(f *testing.F) {
	f.Add(EncodeFrame(EtherTypeIPv4, []byte{0x45, 0x00, 0x00, 0x14}))
	f.Add(EncodeKeepalive())
	f.Add([]byte{})
	f.Add([]byte{0x1a, 0x2b, 0x3c, 0x4d, 0x08, 0x00, 0xff, 0xff, 0x01, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, rest, err := ParseFrame(data)
		if err != nil {
			return
		}
		// An accepted packet must account for exactly the input it consumed: the
		// header plus its body, with the remainder untouched.
		consumed := len(data) - len(rest)
		if consumed != frameHeaderLen+len(frame.Payload) {
			t.Fatalf("consumed %d octets for a %d-octet body", consumed, len(frame.Payload))
		}
		// The payload must be a view of the input rather than a copy, which is
		// what makes the inbound path allocation-free.
		if len(frame.Payload) > 0 && &frame.Payload[0] != &data[frameHeaderLen] {
			t.Fatal("ParseFrame copied its input")
		}
	})
}

// FuzzEncodeParseFrame checks the other direction: whatever EncodeFrame produces
// must parse back to the same packet, for any payload.
func FuzzEncodeParseFrame(f *testing.F) {
	f.Add(uint16(EtherTypeIPv4), []byte{0x45})
	f.Add(uint16(EtherTypeIPv6), []byte{})
	f.Add(uint16(0), make([]byte, 1500))

	f.Fuzz(func(t *testing.T, etherType uint16, payload []byte) {
		if len(payload) > maxFramePayload {
			return
		}
		frame, rest, err := ParseFrame(EncodeFrame(etherType, payload))
		if err != nil {
			t.Fatalf("a packet this code encoded did not parse: %v", err)
		}
		if len(rest) != 0 {
			t.Fatalf("%d octets left over", len(rest))
		}
		if frame.EtherType != etherType || string(frame.Payload) != string(payload) {
			t.Fatalf("round trip gave %#04x/%x, want %#04x/%x",
				frame.EtherType, frame.Payload, etherType, payload)
		}
	})
}

func FuzzParseConfigXML(f *testing.F) {
	esp, err := GenerateESP("aes-128-cbc", "sha1")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(BuildConfigXML(Config{AssignedIP: net.IPv4(10, 50, 0, 7), ESP: esp}))
	f.Add(BuildConfigXML(Config{}))
	f.Add([]byte(`<response><ip-address>10.0.0.2</ip-address></response>`))
	f.Add([]byte(`<response><ipsec><c2s-spi>0xzz</c2s-spi></ipsec></response>`))
	f.Add([]byte(""))
	f.Add([]byte("<not-xml"))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfigXML(data)
		if err != nil {
			return
		}
		// A keying block that parsed must either key an SA or be rejected by
		// NewSA. What must not happen is a half-built block reaching the data
		// path, so exercise the same call the client makes.
		if cfg.ESP != nil {
			_, _ = cfg.ESP.NewSA(true)
			_, _ = cfg.ESP.NewSA(false)
		}
	})
}

func FuzzParseLoginResponse(f *testing.F) {
	f.Add(BuildLoginResponse(LoginInfo{AuthCookie: "abc", User: "alice"}))
	f.Add([]byte(`<jnlp><application-desc><argument>x</argument></application-desc></jnlp>`))
	f.Add([]byte(""))
	f.Add([]byte("<jnlp>"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseLoginResponse(data)
	})
}

func FuzzParsePreloginResponse(f *testing.F) {
	f.Add(BuildPreloginResponse("hello"))
	f.Add([]byte(`<prelogin-response><status>Error</status></prelogin-response>`))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePreloginResponse(data)
	})
}

func FuzzParseLoginForm(f *testing.F) {
	f.Add(BuildLoginForm("alice", "pw", "host", "10.50.0.7"))
	f.Add("user=x&passwd=y")
	f.Add("")
	f.Add("%%%")

	f.Fuzz(func(t *testing.T, body string) {
		_, _ = ParseLoginForm(body)
		_, _ = ParseGetConfigForm(body)
		_, _ = ParseTunnelRequest(body)
	})
}

// FuzzActivationPing covers the one packet parser on the ESP inbound path. It
// runs on every decapsulated packet, so it sees whatever an authenticated peer
// chooses to send — and ActivationReply must never be reachable for a packet
// IsActivationPing rejected.
func FuzzActivationPing(f *testing.F) {
	ping, err := BuildActivationPing(net.IPv4(10, 50, 0, 7), net.IPv4(198, 51, 100, 1), 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ping)
	f.Add(ping[:30])
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if !IsActivationPing(data) {
			if _, err := ActivationReply(data); err == nil {
				t.Fatal("ActivationReply accepted a packet IsActivationPing rejected")
			}
			return
		}
		reply, err := ActivationReply(data)
		if err != nil {
			t.Fatalf("ActivationReply refused a recognised ping: %v", err)
		}
		if len(reply) != len(data) {
			t.Fatalf("reply is %d octets, request was %d", len(reply), len(data))
		}
		// The reply must not itself read as a request, or two gateways pointed at
		// each other would answer forever.
		if IsActivationPing(reply) {
			t.Fatal("the reply reads as another activation ping")
		}
	})
}
