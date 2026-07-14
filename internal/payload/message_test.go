package payload

import (
	"bytes"
	"net"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{
		InitiatorSPI: 0x1122334455667788,
		ResponderSPI: 0x99aabbccddeeff00,
		NextPayload:  TypeSA,
		Version:      0x20,
		ExchangeType: IKE_SA_INIT,
		Flags:        FlagInitiator,
		MessageID:    0,
		Length:       HeaderLen,
	}
	got, err := ParseHeader(h.Marshal(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("header mismatch:\n got %+v\nwant %+v", got, h)
	}
}

func TestMessageChainRoundTrip(t *testing.T) {
	b := NewBuilder()
	b.Add(TypeNonce, false, []byte("nonce-bytes"))
	b.Add(TypeNotify, false, MarshalNotify(NotifyPayload{
		Protocol: ProtoNone, Type: NATDetectionSourceIP, Data: []byte("hash"),
	}))
	chain := b.Bytes()

	h := Header{
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: IKE_SA_INIT,
		Length:       uint32(HeaderLen + len(chain)),
	}
	full := append(h.Marshal(nil), chain...)

	m, err := ParseMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Payloads) != 2 {
		t.Fatalf("want 2 payloads, got %d", len(m.Payloads))
	}
	if m.Payloads[0].Type != TypeNonce || !bytes.Equal(m.Payloads[0].Body, []byte("nonce-bytes")) {
		t.Fatalf("nonce payload wrong: %+v", m.Payloads[0])
	}
	n, err := ParseNotify(m.Payloads[1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != NATDetectionSourceIP || !bytes.Equal(n.Data, []byte("hash")) {
		t.Fatalf("notify wrong: %+v", n)
	}
}

func TestSARoundTrip(t *testing.T) {
	sa := SAPayload{Proposals: []Proposal{{
		Num:      1,
		Protocol: ProtoIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_GCM_16, KeyLen: 256},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransformDH, ID: DH_CURVE25519},
		},
	}}}
	got, err := ParseSA(MarshalSA(sa))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Proposals) != 1 || len(got.Proposals[0].Transforms) != 3 {
		t.Fatalf("proposal shape wrong: %+v", got)
	}
	tr, ok := got.Proposals[0].Get(TransformENCR)
	if !ok || tr.ID != ENCR_AES_GCM_16 || tr.KeyLen != 256 {
		t.Fatalf("encr transform wrong: %+v ok=%v", tr, ok)
	}
}

func TestTSRoundTrip(t *testing.T) {
	ts := TSPayload{Selectors: []TrafficSelector{{
		Type:       TSIPv4AddrRange,
		IPProtocol: IPProtoAny,
		StartPort:  0,
		EndPort:    65535,
		StartAddr:  net.ParseIP("10.0.0.0"),
		EndAddr:    net.ParseIP("10.0.0.255"),
	}}}
	got, err := ParseTS(MarshalTS(ts))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Selectors) != 1 {
		t.Fatalf("want 1 selector, got %d", len(got.Selectors))
	}
	s := got.Selectors[0]
	if !s.StartAddr.Equal(net.ParseIP("10.0.0.0")) || !s.EndAddr.Equal(net.ParseIP("10.0.0.255")) {
		t.Fatalf("selector addrs wrong: %v-%v", s.StartAddr, s.EndAddr)
	}
	if s.EndPort != 65535 {
		t.Fatalf("selector port wrong: %d", s.EndPort)
	}
}

func TestCPRoundTrip(t *testing.T) {
	cp := CPPayload{
		Type: CFGReply,
		Attrs: []CFGAttr{
			{Type: CFGInternalIP4Address, Value: net.ParseIP("10.10.10.2").To4()},
			{Type: CFGInternalIP4Netmask, Value: net.ParseIP("255.255.255.0").To4()},
			{Type: CFGInternalIP4DNS, Value: net.ParseIP("1.1.1.1").To4()},
		},
	}
	got, err := ParseCP(MarshalCP(cp))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != CFGReply || len(got.Attrs) != 3 {
		t.Fatalf("cp shape wrong: %+v", got)
	}
	addr, ok := got.AttrValue(CFGInternalIP4Address)
	if !ok || !net.IP(addr).Equal(net.ParseIP("10.10.10.2")) {
		t.Fatalf("cp address wrong: %v ok=%v", net.IP(addr), ok)
	}
	dns, ok := got.AttrValue(CFGInternalIP4DNS)
	if !ok || !net.IP(dns).Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("cp dns wrong: %v", net.IP(dns))
	}
}
