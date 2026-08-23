package capture

import (
	"bytes"
	"strings"
	"testing"
)

// A corpus is written once and read for years, so the round trip has to be
// exact: if Marshal and Parse disagree by so much as a note, regenerating a
// corpus produces a diff that is noise and reviewers stop reading the diffs.
func TestCorpusRoundTripsExactly(t *testing.T) {
	want := &Corpus{
		Cell:     "compose.client-ss.yml",
		Peer:     "strongSwan 6.0.0",
		Captured: "2026-08-22",
		Notes:    []string{"Direction A: veepin initiator, strongSwan responder."},
		Records: []Record{
			{Dir: FromVeepin, Label: "ike_sa_init_request", Bytes: bytes.Repeat([]byte{0xab}, 70)},
			{
				Dir:   FromPeer,
				Label: "ike_sa_init_response",
				Bytes: []byte{0x00, 0x01, 0x02, 0xff},
				Note:  "strongSwan answers without a cookie.\nThe notify chain is what item 1 cares about.",
			},
		},
	}

	enc, err := want.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Parse(enc)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, enc)
	}

	again, err := got.Marshal()
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(enc, again) {
		t.Fatalf("a corpus does not survive a second round trip:\n--- first ---\n%s\n--- second ---\n%s", enc, again)
	}
	if len(got.Records) != len(want.Records) {
		t.Fatalf("got %d records, want %d", len(got.Records), len(want.Records))
	}
	for i, r := range got.Records {
		w := want.Records[i]
		if r.Dir != w.Dir || r.Label != w.Label || r.Note != w.Note || !bytes.Equal(r.Bytes, w.Bytes) {
			t.Errorf("record %d differs:\n got %+v\nwant %+v", i, r, w)
		}
	}
	if got.Cell != want.Cell || got.Peer != want.Peer || got.Captured != want.Captured {
		t.Errorf("metadata differs: %+v", got)
	}
	if len(got.Notes) != 1 || got.Notes[0] != want.Notes[0] {
		t.Errorf("notes differ: %q", got.Notes)
	}
}

// The banner Marshal writes is regenerated every time. If Parse kept it as a
// note it would be written twice on the next Marshal, four times after that,
// and the file would grow a copy of its own warning per regeneration.
func TestTheBannerDoesNotAccumulate(t *testing.T) {
	c := &Corpus{Cell: "c", Peer: "p", Captured: "2026-08-22"}
	enc, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		parsed, err := Parse(enc)
		if err != nil {
			t.Fatal(err)
		}
		if enc, err = parsed.Marshal(); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(string(enc), "This is NOT a substitute"); n != 1 {
		t.Fatalf("the warning banner appears %d times after three round trips, want 1:\n%s", n, enc)
	}
}

// Cell, peer and capture date are what stop a recording becoming folklore: a
// corpus without them cannot be rerun, attributed or aged out. Refusing to
// write one is the only moment the machine that knows the answers is still up.
func TestACorpusWithoutProvenanceIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta string
		mut  func(*Corpus)
	}{
		{"no peer", "cell = c\ncaptured = 2026-08-22\n", func(c *Corpus) { c.Peer = "" }},
		{"no cell", "peer = p\ncaptured = 2026-08-22\n", func(c *Corpus) { c.Cell = "" }},
		{"no captured", "cell = c\npeer = p\n", func(c *Corpus) { c.Captured = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Corpus{Cell: "c", Peer: "p", Captured: "2026-08-22"}
			tc.mut(&c)
			if _, err := c.Marshal(); err == nil {
				t.Fatal("marshalled a corpus with no provenance")
			}
			// And the same on the way in, so a hand-edited file cannot smuggle
			// one past the writer's check.
			if _, err := Parse([]byte(tc.meta)); err == nil {
				t.Fatalf("parsed a corpus with no provenance:\n%s", tc.meta)
			}
		})
	}
}

// A malformed corpus must name its line. The alternative is a parser that
// guesses, which turns a corrupt file into a byte mismatch several frames later
// and sends the reader hunting through a codec that is fine.
func TestMalformedLinesAreRejectedByLineNumber(t *testing.T) {
	const head = "cell = c\npeer = p\ncaptured = 2026-08-22\n"
	for _, tc := range []struct{ name, body, want string }{
		{"bad direction", "> sideways label\n00\n", "unknown direction"},
		{"missing label", "> peer\n00\n", "want `> <peer|veepin> <label>`"},
		{"extra field", "> peer a b\n00\n", "want `> <peer|veepin> <label>`"},
		{"odd hex", "> peer x\n000\n", "odd length"},
		{"not hex", "> peer x\nzz\n", "invalid byte"},
		{"unknown key", "colour = blue\n", "unknown metadata key"},
		{"metadata without =", "nonsense\n", "want `key = value`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(head + tc.body))
			if err == nil {
				t.Fatalf("accepted %q", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Every prefix of a valid corpus must either parse or be rejected -- never
// panic. The house rule for codecs, applied to the codec that holds the
// evidence for all the others.
func TestEveryTruncationOfACorpusIsHandled(t *testing.T) {
	c := &Corpus{
		Cell: "c", Peer: "p", Captured: "2026-08-22",
		Records: []Record{{Dir: FromPeer, Label: "hello", Bytes: bytes.Repeat([]byte{0x5a}, 100)}},
	}
	enc, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for i := range len(enc) {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on the first %d octets: %v", i, r)
				}
			}()
			_, _ = Parse(enc[:i])
		}()
	}
}

// PeerRecords is the whole point of the Direction field: a peer record is an
// oracle somebody else wrote, and a veepin record is only a witness to what
// veepin did that day. A test that confuses the two proves nothing.
func TestPeerRecordsExcludeVeepinsOwnTraffic(t *testing.T) {
	c := &Corpus{Records: []Record{
		{Dir: FromVeepin, Label: "a"},
		{Dir: FromPeer, Label: "b"},
		{Dir: FromVeepin, Label: "c"},
		{Dir: FromPeer, Label: "d"},
	}}
	got := c.PeerRecords()
	if len(got) != 2 || got[0].Label != "b" || got[1].Label != "d" {
		t.Fatalf("PeerRecords returned %+v", got)
	}
}

func FuzzParseCorpus(f *testing.F) {
	c := &Corpus{
		Cell: "c", Peer: "p", Captured: "2026-08-22",
		Notes:   []string{"a note"},
		Records: []Record{{Dir: FromPeer, Label: "hello", Bytes: []byte{1, 2, 3}}},
	}
	enc, err := c.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc)
	f.Add([]byte("cell = c\npeer = p\ncaptured = x\n> peer l\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Parse(data)
		if err != nil {
			return
		}
		// Anything that parses must round-trip, or a regenerated corpus would
		// silently differ from the one a reviewer approved.
		enc, err := got.Marshal()
		if err != nil {
			t.Fatalf("parsed but would not marshal: %v", err)
		}
		again, err := Parse(enc)
		if err != nil {
			t.Fatalf("marshalled output does not parse: %v\n%s", err, enc)
		}
		if len(again.Records) != len(got.Records) {
			t.Fatalf("record count changed across a round trip: %d -> %d", len(got.Records), len(again.Records))
		}
		for i := range got.Records {
			if !bytes.Equal(again.Records[i].Bytes, got.Records[i].Bytes) {
				t.Fatalf("record %d bytes changed across a round trip", i)
			}
		}
	})
}
