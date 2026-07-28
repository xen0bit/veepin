package ikev1

import "testing"

// Fuzz targets for the ISAKMP/IKEv1 codec.
//
// Main Mode's first two messages are parsed with no key at all, so the header,
// the payload chain and the SA attribute walk all run on wholly unauthenticated
// input. IKEv1's chaining is the same shape as IKEv2's — each payload carries
// its own length and names the next — with the extra hazard that SA payloads
// nest transforms and attributes several levels deep.

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 28))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = parseHeader(data)
	})
}

func FuzzParsePayloads(f *testing.F) {
	f.Add(uint8(1), []byte{})
	f.Add(uint8(1), make([]byte, 8))
	f.Add(uint8(13), make([]byte, 32)) // vendor ID chain

	f.Fuzz(func(t *testing.T, first uint8, chain []byte) {
		payloads, consumed, err := parsePayloads(first, chain)
		if err != nil {
			return
		}
		if consumed > len(chain) {
			t.Fatalf("consumed %d octets of a %d-octet chain", consumed, len(chain))
		}
		// The SA payload nests transforms and attributes, which is the deepest
		// untrusted structure in this protocol; walk it the way the exchange does.
		for _, p := range payloads {
			_, _, _, _ = parseSA(p.body)
			_, _ = parseAttrs(p.body)
		}
	})
}

func FuzzParseAttrs(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x01, 0x00, 0x05})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseAttrs(data)
	})
}

func FuzzParseSA(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = parseSA(data)
	})
}

// FuzzParseCfg covers the Attribute payload that carries XAuth and Mode-Config.
// It is decrypted before it is parsed, so the input is authenticated — but the
// values inside it are still whatever the peer chose, and a gateway's
// configuration reply drives address, DNS and route decisions on the client.
func FuzzParseCfg(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, cfgHeaderLen))
	f.Add(buildCfg(cfgPayload{
		typ:        cfgReply,
		identifier: 1,
		attrs: []attr{
			varAttr(cfgAttrIP4Address, []byte{10, 0, 0, 1}),
			varAttr(unitySplitInclude, make([]byte, splitIncludeLen)),
			basicAttr(xauthStatus, xauthStatusOK),
		},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := parseCfg(data)
		if err != nil {
			return
		}
		// The whole way an assignment is read, including the vendor attributes
		// whose values are fixed-width structures the peer supplies.
		r := parseCfgReply(c)
		for _, n := range r.SplitInclude {
			if n.IP == nil || n.Mask == nil {
				t.Fatalf("split-include network %v is half-parsed", n)
			}
		}
	})
}

// FuzzParseDPDNotify covers the dead-peer-detection Notification. It arrives on
// an established session, so it is authenticated — but it is the one message a
// live tunnel keeps parsing indefinitely, and its SPI length is peer-supplied.
func FuzzParseDPDNotify(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 8))
	f.Add(NewSession(Config{}).buildDPDNotify(notifyRUThere, 1))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseDPDNotify(data)
	})
}
