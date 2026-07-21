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
	if got := tp["TestInteropSelf"]; got != 1.94e9 {
		t.Errorf("TestInteropSelf = %v, want 1.94e9", got)
	}
	if got := tp["TestInteropWireguardSelf"]; got != 8.5e8 {
		t.Errorf("TestInteropWireguardSelf = %v, want 8.5e8", got)
	}
}

func TestParseThroughputRaw(t *testing.T) {
	// A raw (non-JSON) stream should also yield markers.
	in := "noise\n" + IperfLine("TestInteropSelf", 1000) + "\nmore noise\n"
	tp := ParseThroughput(in)
	if tp["TestInteropSelf"] != 1000 {
		t.Errorf("raw parse failed: %v", tp)
	}
}

func TestParseThroughputKeepsMax(t *testing.T) {
	in := IperfLine("T", 0) + "\n" + IperfLine("T", 500) + "\n" + IperfLine("T", 200) + "\n"
	tp := ParseThroughput(in)
	if tp["T"] != 500 {
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
		"TestInteropSelf":                         1.9e9,
		"TestInteropVeepinClientStrongswanServer": 1.2e9,
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
