package ike

import (
	"bytes"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// outHdr is the header every test in this file fragments under.
func outHdr(msgID uint32) payload.Header {
	return payload.Header{
		InitiatorSPI: 0x1122334455667788, ResponderSPI: 0x8877665544332211,
		ExchangeType: payload.IKE_AUTH, Flags: payload.FlagInitiator, MessageID: msgID,
	}
}

// reassemble runs the datagrams a sender produced back through the receive path
// -- parse, decryptSKF, fragReassembler -- exactly as a peer would, and returns
// the inner-payload bytes and the first inner type it recovered.
func reassemble(t *testing.T, pkts [][]byte, suite Suite, keys SAKeys, dir keyDir, msgID uint32) ([]byte, payload.PayloadType) {
	t.Helper()
	var reasm fragReassembler
	for i, raw := range pkts {
		msg, err := payload.ParseMessage(raw)
		if err != nil {
			t.Fatalf("parse fragment %d: %v", i+1, err)
		}
		skf := msg.Find(payload.TypeSKF)
		if skf == nil {
			t.Fatalf("fragment %d carries no SKF payload", i+1)
		}
		fragNum, total, first, chunk, err := decryptSKF(raw, *skf, suite, keys, dir)
		if err != nil {
			t.Fatalf("decrypt fragment %d: %v", i+1, err)
		}
		out, firstInner, complete, err := reasm.add(msgID, fragNum, total, first, chunk)
		if err != nil {
			t.Fatalf("reassemble fragment %d: %v", i+1, err)
		}
		if complete {
			if i != len(pkts)-1 {
				t.Fatalf("reassembly completed at fragment %d of %d", i+1, len(pkts))
			}
			return out, firstInner
		}
	}
	t.Fatal("fragments exhausted without completing reassembly")
	return nil, 0
}

// TestFragmentedMessageReassemblesToTheOriginal is the round trip that has to
// hold before anything else here means much: what buildFragmentedMessage emits,
// the receive path turns back into the exact inner-payload chain it was given.
func TestFragmentedMessageReassemblesToTheOriginal(t *testing.T) {
	for _, tc := range []struct {
		name string
		encr uint16
	}{
		{"aes-gcm", payload.ENCR_AES_GCM_16},
		{"aes-cbc", payload.ENCR_AES_CBC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suite := buildTestSuite(t, tc.encr)
			keys := randomKeys(suite)
			inner := bytes.Repeat([]byte("veepin-outbound-fragment-"), 200) // 5000 bytes

			pkts, err := buildFragmentedMessage(outHdr(1), suite, keys, dirInitiatorToResponder, payload.TypeIDi, inner)
			if err != nil {
				t.Fatalf("buildFragmentedMessage: %v", err)
			}
			if len(pkts) < 2 {
				t.Fatalf("5000 octets produced %d fragments, want several", len(pkts))
			}
			got, firstInner := reassemble(t, pkts, suite, keys, dirInitiatorToResponder, 1)
			if !bytes.Equal(got, inner) {
				t.Fatalf("reassembled %d octets, want %d, and the contents differ", len(got), len(inner))
			}
			if firstInner != payload.TypeIDi {
				t.Fatalf("first inner payload type = %v, want IDi", firstInner)
			}
		})
	}
}

// TestEveryFragmentFitsUnderTheThreshold: a fragmenter that emits a fragment
// over the threshold has done nothing but add round trips. This is the property
// the whole feature exists for, so it is asserted on the datagrams themselves
// rather than inferred from the arithmetic that produced them.
func TestEveryFragmentFitsUnderTheThreshold(t *testing.T) {
	for _, tc := range []struct {
		name string
		encr uint16
	}{
		{"aes-gcm", payload.ENCR_AES_GCM_16},
		{"aes-cbc", payload.ENCR_AES_CBC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suite := buildTestSuite(t, tc.encr)
			keys := randomKeys(suite)
			for _, size := range []int{1, 1280, 1281, 4096, 20000} {
				inner := bytes.Repeat([]byte{0xA5}, size)
				pkts, err := buildFragmentedMessage(outHdr(2), suite, keys, dirResponderToInitiator, payload.TypeIDr, inner)
				if err != nil {
					t.Fatalf("inner %d octets: %v", size, err)
				}
				for i, p := range pkts {
					if len(p) > fragmentThreshold {
						t.Errorf("inner %d octets: fragment %d of %d is %d octets, over the %d threshold",
							size, i+1, len(pkts), len(p), fragmentThreshold)
					}
				}
			}
		})
	}
}

// TestFirstFragmentNamesTheInnerTypeAndTheRestDoNot pins the RFC 7383 section
// 2.5.3 asymmetry from the receiver's point of view. Fragment 1's SKF generic
// header carries the first inner payload's type; every later fragment carries
// zero, because its plaintext continues a chain rather than starting one.
//
// This is a mutually-consistent-bug candidate: a sender that wrote the type on
// every fragment and a receiver that read it from every fragment would agree
// with each other perfectly and with nobody else. Reading it out of the raw
// bytes at the offset the RFC specifies is what makes this a real check.
func TestFirstFragmentNamesTheInnerTypeAndTheRestDoNot(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)
	inner := bytes.Repeat([]byte{0x5A}, 6000)

	pkts, err := buildFragmentedMessage(outHdr(3), suite, keys, dirInitiatorToResponder, payload.TypeIDi, inner)
	if err != nil {
		t.Fatalf("buildFragmentedMessage: %v", err)
	}
	if len(pkts) < 3 {
		t.Fatalf("got %d fragments, need at least 3 to test the asymmetry", len(pkts))
	}
	// The SKF generic header's Next Payload is the first octet after the IKE
	// header, since SKF is the only top-level payload.
	for i, p := range pkts {
		got := payload.PayloadType(p[payload.HeaderLen])
		want := payload.NoNextPayload
		if i == 0 {
			want = payload.TypeIDi
		}
		if got != want {
			t.Errorf("fragment %d Next Payload = %v, want %v", i+1, got, want)
		}
	}
}

// TestFragmentEncodersAgree checks the production encoder against the
// independent one in fragment_test.go that stands in for a peer. They were
// written from the RFC separately; if they disagree, one of them is wrong and
// this says so rather than letting the reassembly tests validate a shared
// mistake.
func TestFragmentEncodersAgree(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_CBC)
	keys := randomKeys(suite)
	hdr := outHdr(4)
	chunk := bytes.Repeat([]byte("chunk"), 37)

	mine, err := sealSKF(hdr, suite, keys.SKei, keys.SKai,
		suite.Cipher.IVLen(), suite.Integ.ICVLen, suite.Cipher.BlockLen(),
		1, 3, payload.TypeIDi, chunk)
	if err != nil {
		t.Fatalf("sealSKF: %v", err)
	}
	theirs := sealFragment(t, hdr, suite, keys, dirInitiatorToResponder, payload.TypeIDi, 1, 3, chunk)

	// The ciphertext differs (each seal draws a fresh IV), so compare the
	// framing: everything up to the IV, and the total length.
	const framing = payload.HeaderLen + 4 + skfPrefixLen
	if !bytes.Equal(mine[:framing], theirs[:framing]) {
		t.Errorf("framing differs\n mine: %x\ntheirs: %x", mine[:framing], theirs[:framing])
	}
	if len(mine) != len(theirs) {
		t.Errorf("length differs: mine %d, theirs %d", len(mine), len(theirs))
	}
}

// TestCertificateSizedAuthActuallyFragments is the regression test for the
// defect this work exists to fix. A certificate IKE_AUTH -- an RSA-2048 leaf,
// an intermediate, and a 256-octet signature -- is 2.5-3.5 KB, which is what
// made "veepin never fragments its own output" a bug rather than a choice. An
// inner chain that size must produce more than one datagram.
func TestCertificateSizedAuthActuallyFragments(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)

	// 3 KB stands in for leaf + intermediate + signature + the CP/SA/TS
	// payloads every IKE_AUTH carries alongside them.
	inner := bytes.Repeat([]byte{0xC7}, 3000)
	pkts, err := sealMaybeFragment(outHdr(5), suite, keys, dirInitiatorToResponder, payload.TypeIDi, inner, true)
	if err != nil {
		t.Fatalf("sealMaybeFragment: %v", err)
	}
	if len(pkts) < 2 {
		t.Fatalf("a %d-octet certificate IKE_AUTH produced %d datagram(s); it must fragment", len(inner), len(pkts))
	}
	got, _ := reassemble(t, pkts, suite, keys, dirInitiatorToResponder, 5)
	if !bytes.Equal(got, inner) {
		t.Fatal("the fragmented certificate IKE_AUTH did not reassemble to itself")
	}
}

// TestNoFragmentationWithoutNegotiation: a peer that never advertised RFC 7383
// will not reassemble SKF payloads, so sending them to one is a dead handshake.
// Oversize or not, an unnegotiated peer gets exactly one datagram.
func TestNoFragmentationWithoutNegotiation(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)
	inner := bytes.Repeat([]byte{0x11}, 4000)

	pkts, err := sealMaybeFragment(outHdr(6), suite, keys, dirInitiatorToResponder, payload.TypeIDi, inner, false)
	if err != nil {
		t.Fatalf("sealMaybeFragment: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("an unnegotiated peer got %d datagrams, want exactly 1", len(pkts))
	}
	// The IKE header's Next Payload sits after the two 8-octet SPIs (RFC 7296
	// section 3.1), so offset 16 -- not the last octet of the header.
	if got := payload.PayloadType(pkts[0][16]); got != payload.TypeSK {
		t.Errorf("unfragmented message's first payload = %v, want SK", got)
	}
}

// TestSmallMessagesAreNotFragmented: the threshold has to cut both ways, or
// every DPD probe becomes an SKF exchange. A message that fits is sent whole
// even when the peer supports fragmentation.
func TestSmallMessagesAreNotFragmented(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)

	for _, size := range []int{0, 1, 64, 512} {
		pkts, err := sealMaybeFragment(outHdr(7), suite, keys, dirInitiatorToResponder,
			payload.TypeIDi, bytes.Repeat([]byte{0x22}, size), true)
		if err != nil {
			t.Fatalf("inner %d octets: %v", size, err)
		}
		if len(pkts) != 1 {
			t.Errorf("a %d-octet message produced %d datagrams, want 1", size, len(pkts))
		}
	}
}

// TestFragmentCountRefusesToExceedTheReassemblyBound: veepin's own reassembler
// caps a message at maxFragments, and every implementation caps somewhere.
// Emitting more than we would accept is a message no peer can be assumed to
// take, so it fails at the sender where the error is attributable.
func TestFragmentCountRefusesToExceedTheReassemblyBound(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)

	// Comfortably past maxFragments * fragmentThreshold.
	huge := bytes.Repeat([]byte{0x33}, maxFragments*fragmentThreshold*2)
	if _, err := buildFragmentedMessage(outHdr(8), suite, keys, dirInitiatorToResponder, payload.TypeIDi, huge); err == nil {
		t.Fatal("accepted a message needing more than maxFragments fragments")
	}
}
