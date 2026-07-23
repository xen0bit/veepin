package ike

import (
	"bytes"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// sealFragment builds one SKF (Encrypted Fragment) message carrying chunk as
// fragment fragNum of total (RFC 7383 section 2.5). It mirrors what a peer set
// to always fragment emits — veepin itself never fragments its output, so this
// encoder lives only in the tests that drive the reassembly path.
//
// skfNext is the SKF generic header's Next Payload: the first inner payload's
// type for fragment 1, and NoNextPayload for the rest.
func sealFragment(tb testing.TB, hdr payload.Header, suite Suite, keys SAKeys, dir keyDir,
	skfNext payload.PayloadType, fragNum, total uint16, chunk []byte) []byte {
	tb.Helper()
	encKey, integKey := encryptKeys(keys, dir)

	buildAAD := func(sealedLen int) []byte {
		skfPayloadLen := 4 + skfPrefixLen + sealedLen // generic header + prefix + iv||ct||icv
		h := hdr
		h.NextPayload = payload.TypeSKF
		h.Version = 0x20
		h.Length = uint32(payload.HeaderLen + skfPayloadLen)
		aad := h.Marshal(nil)
		// SKF generic payload header, then Fragment Number / Total Fragments.
		aad = append(aad, byte(skfNext), 0x00, byte(skfPayloadLen>>8), byte(skfPayloadLen))
		aad = append(aad, byte(fragNum>>8), byte(fragNum), byte(total>>8), byte(total))
		return aad
	}

	// The sealed length is deterministic from chunk and suite, so a first seal
	// with a placeholder AAD reveals it; then seal for real over the correct AAD.
	probe, err := sealSK(suite, encKey, integKey, buildAAD(0), chunk)
	if err != nil {
		tb.Fatalf("seal fragment probe: %v", err)
	}
	aad := buildAAD(len(probe))
	sealed, err := sealSK(suite, encKey, integKey, aad, chunk)
	if err != nil {
		tb.Fatalf("seal fragment: %v", err)
	}
	return append(aad, sealed...)
}

// fragmentInner splits an inner-payload chain into n SKF messages for the given
// exchange/message ID. Fragment 1 carries firstInner as its Next Payload; the
// rest carry NoNextPayload.
func (it *initiator) fragmentInner(ex payload.ExchangeType, msgID uint32,
	firstInner payload.PayloadType, innerChain []byte, n int) [][]byte {
	it.tb.Helper()
	if n < 1 {
		n = 1
	}
	hdr := payload.Header{
		InitiatorSPI: it.spiI, ResponderSPI: it.spiR,
		ExchangeType: ex, Flags: payload.FlagInitiator, MessageID: msgID,
	}
	size := (len(innerChain) + n - 1) / n
	if size == 0 {
		size = len(innerChain)
		n = 1
	}
	var out [][]byte
	for i := range n {
		lo := i * size
		hi := min(lo+size, len(innerChain))
		next := payload.NoNextPayload
		if i == 0 {
			next = firstInner
		}
		out = append(out, sealFragment(it.tb, hdr, it.suite, it.keys, dirInitiatorToResponder,
			next, uint16(i+1), uint16(n), innerChain[lo:hi]))
		if hi == len(innerChain) {
			break
		}
	}
	return out
}

// TestFragmentRoundTrip is the crypto-and-reassembly unit: an inner-payload
// chain fragmented into SKF messages, each decrypted independently, feeds a
// reassembler and comes back byte-identical.
func TestFragmentRoundTrip(t *testing.T) {
	suite := buildTestSuite(t, payload.ENCR_AES_GCM_16)
	keys := randomKeys(suite)

	// A synthetic inner chain (its bytes need not parse as payloads for this
	// level — only the fragment framing and reassembly are under test).
	inner := bytes.Repeat([]byte("veepin-fragment-"), 200) // 3200 bytes
	hdr := payload.Header{
		InitiatorSPI: 0x1122334455667788, ResponderSPI: 0x8877665544332211,
		ExchangeType: payload.IKE_AUTH, Flags: payload.FlagInitiator, MessageID: 1,
	}

	const n = 5
	var reasm fragReassembler
	var got []byte
	for i := range n {
		size := (len(inner) + n - 1) / n
		lo, hi := i*size, min((i+1)*size, len(inner))
		next := payload.NoNextPayload
		if i == 0 {
			next = payload.TypeIDi
		}
		raw := sealFragment(t, hdr, suite, keys, dirInitiatorToResponder, next, uint16(i+1), uint16(n), inner[lo:hi])

		msg, err := payload.ParseMessage(raw)
		if err != nil {
			t.Fatalf("parse fragment %d: %v", i+1, err)
		}
		skf := msg.Find(payload.TypeSKF)
		if skf == nil {
			t.Fatalf("fragment %d has no SKF payload", i+1)
		}
		fragNum, total, first, chunk, err := decryptSKF(raw, *skf, suite, keys, dirInitiatorToResponder)
		if err != nil {
			t.Fatalf("decrypt fragment %d: %v", i+1, err)
		}
		if total != n {
			t.Fatalf("fragment %d reports total %d, want %d", i+1, total, n)
		}
		out, firstInner, complete, err := reasm.add(hdr.MessageID, fragNum, total, first, chunk)
		if err != nil {
			t.Fatalf("reassemble fragment %d: %v", i+1, err)
		}
		if complete {
			if i != n-1 {
				t.Fatalf("reassembly completed early at fragment %d", i+1)
			}
			if firstInner != payload.TypeIDi {
				t.Fatalf("reassembled first inner = %v, want IDi", firstInner)
			}
			got = out
		}
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("reassembled %d bytes, want %d, content mismatch", len(got), len(inner))
	}
}

// TestFragmentReassemblerDuplicatesAndOrder confirms out-of-order delivery and
// duplicate fragments both reassemble correctly.
func TestFragmentReassemblerDuplicatesAndOrder(t *testing.T) {
	var r fragReassembler
	// total=3, deliver as 3,1,3(dup),2.
	feed := func(num uint16, first payload.PayloadType, b []byte) (bool, []byte) {
		out, _, complete, err := r.add(7, num, 3, first, b)
		if err != nil {
			t.Fatalf("add fragment %d: %v", num, err)
		}
		return complete, out
	}
	if c, _ := feed(3, 0, []byte("CCC")); c {
		t.Fatal("completed after only fragment 3")
	}
	if c, _ := feed(1, payload.TypeIDi, []byte("AAA")); c {
		t.Fatal("completed after only 3,1")
	}
	if c, _ := feed(3, 0, []byte("XXX")); c {
		t.Fatal("a duplicate fragment 3 should not complete or overwrite")
	}
	complete, out := feed(2, 0, []byte("BBB"))
	if !complete {
		t.Fatal("not complete after all three fragments")
	}
	if string(out) != "AAABBBCCC" {
		t.Fatalf("reassembled %q, want AAABBBCCC (dup must not corrupt)", out)
	}
}

// TestFragmentReassemblerRejectsBadCounts guards the DoS bounds.
func TestFragmentReassemblerRejectsBadCounts(t *testing.T) {
	var r fragReassembler
	if _, _, _, err := r.add(1, 1, 0, 0, nil); err == nil {
		t.Fatal("total=0 must be rejected")
	}
	if _, _, _, err := r.add(1, 1, maxFragments+1, 0, nil); err == nil {
		t.Fatal("total > maxFragments must be rejected")
	}
	if _, _, _, err := r.add(1, 0, 2, 0, nil); err == nil {
		t.Fatal("fragment number 0 must be rejected")
	}
	if _, _, _, err := r.add(1, 3, 2, 0, nil); err == nil {
		t.Fatal("fragment number > total must be rejected")
	}
}

// TestFragmentationNegotiated confirms the responder echoes
// IKE_FRAGMENTATION_SUPPORTED when the initiator advertises it, and stores the
// enabled flag on the SA.
func TestFragmentationNegotiated(t *testing.T) {
	p500, _, srv, _ := mobikeServer(t)
	defer srv.Close()

	it := newInitiator(t, "127.0.0.1", p500, []byte("mobike-psk"))
	defer it.conn.Close()
	it.advertiseFrag = true
	it.doSAInit()
	if !it.fragAck {
		t.Fatal("responder did not echo IKE_FRAGMENTATION_SUPPORTED")
	}

	srv.mu.RLock()
	sa := srv.byRSPI[it.spiR]
	srv.mu.RUnlock()
	if sa == nil {
		t.Fatal("no SA after SA_INIT")
	}
	sa.mu.Lock()
	enabled := sa.fragEnabled
	sa.mu.Unlock()
	if !enabled {
		t.Fatal("server did not enable fragmentation on the SA")
	}
}

// TestFragmentationNotOfferedStaysOff confirms the responder does not enable
// fragmentation when the initiator never advertised it.
func TestFragmentationNotOfferedStaysOff(t *testing.T) {
	p500, _, srv, _ := mobikeServer(t)
	defer srv.Close()

	it := newInitiator(t, "127.0.0.1", p500, []byte("mobike-psk"))
	defer it.conn.Close()
	it.doSAInit() // advertiseFrag stays false
	if it.fragAck {
		t.Fatal("responder echoed fragmentation support that was never offered")
	}
}

// TestServerReassemblesFragmentedAuth is the end-to-end responder proof: an
// initiator that negotiated fragmentation splits its IKE_AUTH across several SKF
// messages, and the server reassembles them into one message, authenticates it,
// and establishes the Child SA — exactly the strongSwan fragmentation=force
// case.
func TestServerReassemblesFragmentedAuth(t *testing.T) {
	p500, _, srv, dp := mobikeServer(t)
	defer srv.Close()

	it := newInitiator(t, "127.0.0.1", p500, []byte("mobike-psk"))
	defer it.conn.Close()
	it.advertiseFrag = true
	it.doSAInit()
	if !it.fragAck {
		t.Fatal("fragmentation was not negotiated")
	}

	// Build the exact IKE_AUTH inner chain doAuth would send, then fragment it.
	idBody := idPayloadBody(it.id)
	authData := computePSKAuth(it.suite.PRF, it.psk, it.saInitReq, it.nr, it.keys.SKpi, idBody)
	it.childOutSPI = newChildSPI()
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{
		{Type: payload.CFGInternalIP4Address},
	}}
	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: authData,
	}))
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{DefaultESPProposal(u32BE(it.childOutSPI))},
	}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))

	it.sendMsgID = 1
	frags := it.fragmentInner(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes(), 3)
	if len(frags) < 2 {
		t.Fatalf("expected the IKE_AUTH to split into multiple fragments, got %d", len(frags))
	}
	for _, f := range frags {
		it.send(f)
	}

	// One reassembled, authenticated response with the Child SA proves success.
	first, inner := it.openEnc(it.recv())
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		t.Fatalf("AUTH resp inner parse: %v", err)
	}
	if findInner(inners, payload.TypeSA) == nil {
		t.Fatalf("server did not establish a Child SA from the fragmented IKE_AUTH")
	}
	select {
	case <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA reached the data path")
	}
}

// TestServerRejectsFragmentWithoutNegotiation confirms a fragment on an SA that
// never negotiated fragmentation is dropped (the server never answers), rather
// than reassembled.
func TestServerRejectsFragmentWithoutNegotiation(t *testing.T) {
	p500, _, srv, _ := mobikeServer(t)
	defer srv.Close()

	it := newInitiator(t, "127.0.0.1", p500, []byte("mobike-psk"))
	defer it.conn.Close()
	it.doSAInit() // no fragmentation advertised

	// Send a lone SKF fragment. The server must ignore it.
	hdr := payload.Header{
		InitiatorSPI: it.spiI, ResponderSPI: it.spiR,
		ExchangeType: payload.IKE_AUTH, Flags: payload.FlagInitiator, MessageID: 1,
	}
	raw := sealFragment(t, hdr, it.suite, it.keys, dirInitiatorToResponder,
		payload.TypeIDi, 1, 2, []byte("partial"))
	it.send(raw)

	_ = it.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 65535)
	if _, err := it.conn.Read(buf); err == nil {
		t.Fatal("server answered an SKF fragment on a non-fragmentation SA")
	}
}
