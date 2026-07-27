package livingreadme

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseThroughputJSON(t *testing.T) {
	// Wrap two markers the way go test -json does: as Output events with go
	// test's "    file.go:NN: " framing.
	mk := func(payload string) string {
		b, _ := json.Marshal(struct {
			Action string
			Output string
		}{"output", payload})
		return string(b)
	}
	in := strings.Join([]string{
		mk("    interop_test.go:120: " + IperfLine("TestInteropSelf", 1.94e9) + "\n"),
		mk("    interop_test.go:120: " + IperfLine("TestInteropWireguardSelf", 8.5e8) + "\n"),
		mk("some unrelated line\n"),
		`{"Action":"pass","Test":"TestInteropSelf"}`,
	}, "\n")

	tp := ParseThroughput(in)
	if got := tp["TestInteropSelf"].BitsPerSec; got != 1.94e9 {
		t.Errorf("TestInteropSelf = %v, want 1.94e9", got)
	}
	if got := tp["TestInteropWireguardSelf"].BitsPerSec; got != 8.5e8 {
		t.Errorf("TestInteropWireguardSelf = %v, want 8.5e8", got)
	}
}

func TestParseThroughputRaw(t *testing.T) {
	// A raw (non-JSON) stream should also yield markers.
	in := "noise\n" + IperfLine("TestInteropSelf", 1000) + "\nmore noise\n"
	tp := ParseThroughput(in)
	if tp["TestInteropSelf"].BitsPerSec != 1000 {
		t.Errorf("raw parse failed: %v", tp)
	}
}

func TestParseThroughputKeepsMax(t *testing.T) {
	in := IperfLine("T", 0) + "\n" + IperfLine("T", 500) + "\n" + IperfLine("T", 200) + "\n"
	tp := ParseThroughput(in)
	if tp["T"].BitsPerSec != 500 {
		t.Errorf("expected max 500, got %v", tp["T"])
	}
}

func TestFormatBits(t *testing.T) {
	cases := map[float64]string{
		1.94e9: "1.94 Gbit/s",
		2.5e9:  "2.5 Gbit/s",
		8.5e8:  "850 Mbit/s",
		12.3e6: "12.3 Mbit/s",
		9.6e5:  "960 kbit/s",
		500:    "500 bit/s",
	}
	for in, want := range cases {
		if got := formatBits(in); got != want {
			t.Errorf("formatBits(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderInteropBench(t *testing.T) {
	tp := Throughput{
		"TestInteropSelf":                         {BitsPerSec: 1.9e9},
		"TestInteropVeepinClientStrongswanServer": {BitsPerSec: 1.2e9},
	}
	out := RenderInteropBench(tp, Meta{})

	if !strings.Contains(out, "1.9 Gbit/s") {
		t.Errorf("self throughput missing:\n%s", out)
	}
	if !strings.Contains(out, "1.2 Gbit/s") {
		t.Errorf("client throughput missing:\n%s", out)
	}
	// A cell with no measurement is an em dash; Fortinet's untested client too.
	if !strings.Contains(out, "—") {
		t.Errorf("expected em dashes for unmeasured cells:\n%s", out)
	}
	// Every protocol row is present.
	for _, row := range interopMatrix {
		if !strings.Contains(out, row.Protocol) {
			t.Errorf("protocol %q missing", row.Protocol)
		}
	}
}

// TestParseThroughputFailedMarker covers the distinction the table exists to
// make. The failed marker has the successful one as a prefix, so a parser that
// checked the wrong one first would read a failure as a malformed success and
// drop it — leaving the cell indistinguishable from one never measured.
func TestParseThroughputFailedMarker(t *testing.T) {
	in := "noise\n" + IperfFailedLine("TestInteropVeepinClientSSHServer") + "\n"
	tp := ParseThroughput(in)

	m, ok := tp["TestInteropVeepinClientSSHServer"]
	if !ok {
		t.Fatalf("failed marker not recorded: %v", tp)
	}
	if !m.Failed {
		t.Errorf("Failed = false, want true (%+v)", m)
	}
	if m.BitsPerSec != 0 {
		t.Errorf("BitsPerSec = %v, want 0", m.BitsPerSec)
	}
}

// TestParseThroughputSuccessBeatsFailure: a cell that failed once and then
// measured is a working cell. Order must not decide it.
func TestParseThroughputSuccessBeatsFailure(t *testing.T) {
	for _, in := range []string{
		IperfFailedLine("T") + "\n" + IperfLine("T", 700) + "\n",
		IperfLine("T", 700) + "\n" + IperfFailedLine("T") + "\n",
	} {
		tp := ParseThroughput(in)
		if tp["T"].Failed || tp["T"].BitsPerSec != 700 {
			t.Errorf("input %q gave %+v, want a 700 measurement", in, tp["T"])
		}
	}
}

// TestBenchCellStates pins the three-way distinction directly, since it is the
// whole point of the change: an absent measurement and a broken one are
// different facts about a cell.
func TestBenchCellStates(t *testing.T) {
	measured := interopCell{Tests: []string{"measured"}}
	broke := interopCell{Tests: []string{"broke"}}
	never := interopCell{Tests: []string{"never"}}
	noTest := interopCell{}

	tp := Throughput{
		"measured": {BitsPerSec: 5e8},
		"broke":    {Failed: true},
	}

	if got := benchCell(measured, tp); got != "500 Mbit/s" {
		t.Errorf("measured cell = %q, want 500 Mbit/s", got)
	}
	if got := benchCell(broke, tp); got != "✗" {
		t.Errorf("attempted-and-failed cell = %q, want ✗ — a broken measurement "+
			"must not read as a deliberate omission", got)
	}
	if got := benchCell(never, tp); got != "—" {
		t.Errorf("never-measured cell = %q, want —", got)
	}
	if got := benchCell(noTest, tp); got != "—" {
		t.Errorf("cell with no test = %q, want —", got)
	}
}
