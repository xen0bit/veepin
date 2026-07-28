package pulse

import "testing"

// Fuzz targets for the Ivanti Connect Secure codecs.
//
// Everything here runs on input a peer chose. The IF-T/TLS header is parsed
// before anything is authenticated at all; the AVP and EAP chains are parsed
// during authentication, before the password has been checked; and the
// configuration and ESP-keying packets are parsed after it, but they drive the
// client's address, routes and — in the ESP packet's case — its keys.
//
// Every one of these formats carries at least one peer-supplied length that
// bounds a slice, which is what makes them worth fuzzing rather than merely
// testing.

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, HeaderLen))
	f.Add(EncodeData(1, []byte{0x45, 0, 0, 20}))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Walk the whole buffer the way the data path does: one read can land
		// on any number of whole or partial messages.
		rest := data
		for {
			m, next, err := ParseMessage(rest)
			if err != nil {
				return
			}
			if len(next) >= len(rest) {
				t.Fatalf("ParseMessage did not consume anything from %d octets", len(rest))
			}
			if len(m.Payload) > len(rest) {
				t.Fatalf("payload of %d octets from a %d-octet buffer", len(m.Payload), len(rest))
			}
			rest = next
		}
	})
}

func FuzzParseAVPs(f *testing.F) {
	f.Add([]byte{})
	f.Add(EncodeAVPString(AVPCookie, "session"))
	f.Add(append(EncodeAVPString(AVPUsername, "alice"),
		encodeAVPRaw(AVPEAPMessage, EncodeEAPExpanded(EAPResponse, 1, JuniperSubtypePassword, []byte{2, 2, 9, 'h', 'u', 'n', 't', 'e', 'r'}))...))

	f.Fuzz(func(t *testing.T, data []byte) {
		avps, err := ParseAVPs(data)
		if err != nil {
			return
		}
		for _, a := range avps {
			if len(a.Value) > len(data) {
				t.Fatalf("AVP value of %d octets from a %d-octet chain", len(a.Value), len(data))
			}
			// An EAP-Message AVP is parsed again one layer down, which is where
			// the nesting gets deep enough to be worth exercising.
			if a.Code == AVPEAPMessage {
				_, _ = ParseEAP(a.Value)
			}
		}
	})
}

func FuzzParseEAP(f *testing.F) {
	f.Add([]byte{})
	f.Add(EncodeEAP(EAPResponse, 1, EAPTypeIdentity, []byte("anonymous")))
	f.Add(EncodeEAPExpanded(EAPRequest, 2, JuniperSubtypeAVP, nil))
	f.Add(EncodeEAPResult(EAPSuccess, 3))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseEAP(data)
		if err != nil {
			return
		}
		if len(p.Data) > len(data) {
			t.Fatalf("EAP data of %d octets from a %d-octet packet", len(p.Data), len(data))
		}
	})
}

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, cfgPreambleLen))
	f.Add(BuildConfig(Config{
		Address: []byte{10, 70, 0, 2},
		Netmask: []byte{255, 255, 255, 0},
		MTU:     1400,
		Domain:  "example.test",
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseConfig(data)
		if err != nil {
			return
		}
		for _, r := range c.Routes {
			if r.Net == nil || r.Net.IP == nil || r.Net.Mask == nil {
				t.Fatalf("half-parsed route %v", r.Net)
			}
		}
	})
}

func FuzzParseESPPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, espMinPayloadLen))
	if k, err := GenerateKeys(EncAES256CBC, HMACSHA256); err == nil {
		if p, berr := BuildESPPacket(k); berr == nil {
			f.Add(p)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		k, block, err := ParseESPPacket(data, EncAES256CBC, HMACSHA256)
		if err != nil {
			return
		}
		if len(k.EncKey) != 32 || len(k.HMACKey) != 32 {
			t.Fatalf("keys of %d/%d octets for AES-256/SHA-256", len(k.EncKey), len(k.HMACKey))
		}
		if len(block) != 6+SecretsLen {
			t.Fatalf("keying block of %d octets", len(block))
		}
	})
}
