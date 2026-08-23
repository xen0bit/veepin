package goldens

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/internal/capture"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// A corpus with no entry in Registry is a file nothing reads; an entry with no
// corpus is an assertion nothing runs. Both are silent, and both are exactly
// the shape of failure this package was written to stop happening elsewhere.
func TestEveryCorpusHasACheckAndEveryCheckACorpus(t *testing.T) {
	names, err := Names()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no corpora are embedded, so every check below covers nothing")
	}
	for _, n := range names {
		if _, ok := Registry[n]; !ok {
			t.Errorf("corpora/%s.corpus has no entry in Registry, so nothing ever reads it", n)
		}
	}
	for n := range Registry {
		if !slices.Contains(names, n) {
			t.Errorf("Registry names %q but corpora/%s.corpus does not exist, so that check never runs", n, n)
		}
	}
}

// The fast half of the pairing this package is built on: every committed
// capture still satisfies everything claimed of it, offline, in milliseconds.
// The slow half runs the identical check against a live peer in the interop
// shard, which is what notices when the peer itself changes.
func TestEveryCommittedCorpusPassesItsCheck(t *testing.T) {
	names, err := Names()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			c, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := Registry[name].Check(c); err != nil {
				t.Fatalf("%v", err)
			}
			// Provenance is the corpus's own expiry warning, and a check that
			// ran against an undated recording would be reassuring for as long
			// as nobody looked.
			if c.Peer == "" || c.Captured == "" || c.Cell == "" {
				t.Fatalf("corpus %s has incomplete provenance: %+v", name, c)
			}
			if c.Cell != Registry[name].Cell {
				t.Errorf("corpus says it came from %q, Registry says %q", c.Cell, Registry[name].Cell)
			}
		})
	}
}

// The IKEv2 check has to notice a peer that stops advertising RFC 7383
// fragmentation, because veepin only fragments its own IKE output when the peer
// does — and before doc/claims-and-reach-plan.md item 1 it never fragmented at
// all. Losing the advertisement would put certificate authentication straight
// back on the oversized-datagram path with every cell still green, since the
// cert cell mints the smallest certificate that exists.
func TestTheIKEv2CheckNoticesAPeerThatStopsOfferingFragmentation(t *testing.T) {
	c := mustLoad(t, "ikev2-strongswan")
	i := indexOf(t, c, labelSAInitResponse)
	c.Records[i].Bytes = rebuildWithout(t, c.Records[i].Bytes, payload.IKEFragmentationSupported)

	err := CheckIKEv2(c)
	if err == nil {
		t.Fatal("a responder with no FRAGMENTATION_SUPPORTED passed the check")
	}
	if !strings.Contains(err.Error(), "FRAGMENTATION_SUPPORTED") {
		t.Fatalf("the error does not name what is missing: %v", err)
	}
}

// The round trip must compare octets, not structures. A check that compared
// decoded values would accept any re-encoding of them and would therefore prove
// nothing about the two encoders agreeing, which is its entire purpose.
//
// The probe is a transform attribute in TLV form. RFC 7296 3.3.5 defines Key
// Length in TV form, and veepin's parser reads a TLV attribute and discards it
// — so a TLV-carrying transform decodes fine and re-encodes shorter. Only a
// byte comparison sees that.
func TestTheIKEv2CheckComparesOctetsAndNotStructures(t *testing.T) {
	c := mustLoad(t, "ikev2-strongswan")
	i := indexOf(t, c, labelSAInitResponse)
	c.Records[i].Bytes = rebuildWithTLVAttribute(t, c.Records[i].Bytes)

	if err := CheckIKEv2(c); err == nil {
		t.Fatal("a payload that re-encodes to different octets passed the check")
	} else if !strings.Contains(err.Error(), "does not re-encode") {
		t.Fatalf("the error blames the wrong thing: %v", err)
	}
}

// Direction is not decoration. A peer record is an oracle somebody else wrote;
// a veepin record is a witness to what veepin did that day. A check run against
// veepin's own output is a mirror, and would pass forever.
func TestACheckRefusesToTreatVeepinsOwnTrafficAsTheOracle(t *testing.T) {
	for _, tc := range []struct{ name, label string }{
		{"ikev2-strongswan", labelSAInitResponse},
		{"wireguard-wgge", labelWGInitiation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mustLoad(t, tc.name)
			c.Records[indexOf(t, c, tc.label)].Dir = capture.FromVeepin
			if err := Registry[tc.name].Check(c); err == nil {
				t.Fatal("the check accepted veepin's own traffic as the peer's")
			}
		})
	}
}

// This is the strongest assertion in the package, so it needs proof that it can
// fail: veepin's responder must reject an initiation that is not addressed to
// its static key, which is what mac1 exists to say.
func TestTheWireGuardCheckNoticesAnInitiationThatIsNotAddressedToVeepin(t *testing.T) {
	c := mustLoad(t, "wireguard-wgge")
	rec := &c.Records[indexOf(t, c, labelWGInitiation)]
	// Offset 50 is inside the encrypted static key, which mac1 covers.
	rec.Bytes[50] ^= 0x01

	err := CheckWireGuard(c)
	if err == nil {
		t.Fatal("a tampered initiation was accepted")
	}
	if !strings.Contains(err.Error(), "rejects a real wireguard-go initiation") {
		t.Fatalf("the error blames the wrong thing: %v", err)
	}
}

// Verifying mac1 means holding the static key it is computed over, so this
// package carries a copy of the cell's fixed test keys. Rotating them in the
// compose file without rotating them here would leave the check verifying a
// handshake nobody makes any more — and it would still pass, against the
// committed corpus, forever.
func TestTheWireGuardKeysStillMatchTheCell(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "interop", Registry["wireguard-wgge"].Cell)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the cell: %v", err)
	}
	for _, want := range []string{wgServerPrivateB64, wgClientPublicB64} {
		if !strings.Contains(string(data), want) {
			t.Errorf("%s no longer contains the key this package checks mac1 with (%s...); "+
				"the corpus and the cell now describe different peers", path, want[:12])
		}
	}
}

func mustLoad(t *testing.T, name string) *capture.Corpus {
	t.Helper()
	c, err := Load(name)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func indexOf(t *testing.T, c *capture.Corpus, label string) int {
	t.Helper()
	for i, r := range c.Records {
		if r.Label == label {
			return i
		}
	}
	t.Fatalf("no record labelled %q", label)
	return -1
}

// rebuildWithout re-emits an IKE message with every Notify of the given type
// removed, fixing the header length so the result is well-formed.
func rebuildWithout(t *testing.T, msg []byte, drop payload.NotifyType) []byte {
	t.Helper()
	hdr, err := payload.ParseHeader(msg)
	if err != nil {
		t.Fatal(err)
	}
	m, err := payload.ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	b := payload.NewBuilder()
	for _, p := range m.Payloads {
		if p.Type == payload.TypeNotify {
			if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == drop {
				continue
			}
		}
		b.Add(p.Type, p.Critical, p.Body)
	}
	return finish(hdr, b)
}

// rebuildWithTLVAttribute re-emits an IKE message with a TLV-format attribute
// appended to the first transform of the first proposal in its SA payload.
func rebuildWithTLVAttribute(t *testing.T, msg []byte) []byte {
	t.Helper()
	hdr, err := payload.ParseHeader(msg)
	if err != nil {
		t.Fatal(err)
	}
	m, err := payload.ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	b := payload.NewBuilder()
	for _, p := range m.Payloads {
		if p.Type != payload.TypeSA {
			b.Add(p.Type, p.Critical, p.Body)
			continue
		}
		b.Add(p.Type, p.Critical, withTLVAttr(t, p.Body))
	}
	return finish(hdr, b)
}

// withTLVAttr grows the first transform of the first proposal by a four-octet
// TLV attribute with an empty value, adjusting the two lengths above it.
func withTLVAttr(t *testing.T, sa []byte) []byte {
	t.Helper()
	// Proposal substructure: 0(1) reserved(1) length(2) num(1) protocol(1)
	// spiSize(1) numTransforms(1), then the SPI, then the transforms.
	if len(sa) < 8 {
		t.Fatal("SA payload too short to edit")
	}
	spiSize := int(sa[6])
	transformOff := 8 + spiSize
	if len(sa) < transformOff+8 {
		t.Fatal("SA payload has no first transform")
	}
	attr := []byte{0x00, 0x0e, 0x00, 0x00} // TLV: type 14 (Key Length), length 0

	out := slices.Clone(sa)
	trLen := int(binary.BigEndian.Uint16(out[transformOff+2 : transformOff+4]))
	// Splice the attribute in at the end of the first transform.
	end := transformOff + trLen
	out = slices.Insert(out, end, attr...)
	binary.BigEndian.PutUint16(out[transformOff+2:transformOff+4], uint16(trLen+len(attr)))
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])+uint16(len(attr)))
	return out
}

func finish(hdr payload.Header, b *payload.Builder) []byte {
	hdr.NextPayload = b.FirstType()
	hdr.Length = uint32(payload.HeaderLen + len(b.Bytes()))
	return append(hdr.Marshal(nil), b.Bytes()...)
}
