package livingreadme

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// iperfMarker is the token an interop benchmark test prints (via t.Log) to carry
// a throughput measurement out through `go test -json`. The line that follows it
// is "<test-name> <bits-per-second>", so a single test run feeds both the interop
// matrix (pass/fail) and the interop-benchmark table (speed).
const iperfMarker = "livingreadme:iperf3"

// IperfLine formats the marker line a test logs after measuring a tunnel. Keeping
// the format in this package means the producer (the interop harness) and the
// consumer (ParseThroughput) cannot drift apart.
func IperfLine(testName string, bitsPerSec float64) string {
	return fmt.Sprintf("%s %s %.0f", iperfMarker, testName, bitsPerSec)
}

// Throughput maps an interop test name to its measured tunnel throughput in bits
// per second.
type Throughput map[string]float64

// ParseThroughput reads `go test -json` output and extracts every iperf3 marker
// a test logged. Markers arrive inside "output" events, prefixed by go test's
// "    file.go:NN: " framing, so it scans each output payload for the token
// rather than matching a whole line.
func ParseThroughput(jsonOut string) Throughput {
	out := Throughput{}
	sc := bufio.NewScanner(strings.NewReader(jsonOut))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			// Tolerate a raw (non-JSON) stream too: parse the marker directly.
			recordMarker(out, line)
			continue
		}
		var ev struct {
			Output string `json:"Output"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		recordMarker(out, ev.Output)
	}
	return out
}

// recordMarker parses one text fragment for an iperf3 marker and, if found,
// stores the highest value seen for that test (a test may measure once, but a
// retry that logs twice should not lose the successful number to a later 0).
func recordMarker(out Throughput, text string) {
	_, after, found := strings.Cut(text, iperfMarker)
	if !found {
		return
	}
	fields := strings.Fields(after)
	if len(fields) < 2 {
		return
	}
	bps, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return
	}
	if bps > out[fields[0]] {
		out[fields[0]] = bps
	}
}

// benchCell renders one interop-benchmark cell: the measured throughput of the
// cell's primary test, or an em dash when the cell is untested-by-design or has
// no measurement (e.g. a datagram-forwarding cell that iperf3 does not cover).
func benchCell(c interopCell, tp Throughput) string {
	if len(c.Tests) == 0 {
		return "—"
	}
	bps, ok := tp[c.Tests[0]]
	if !ok || bps <= 0 {
		return "—"
	}
	return formatBits(bps)
}

// RenderInteropBench renders the interop throughput table: the same protocol ×
// direction shape as the interop matrix, each cell carrying an iperf3 figure
// measured across that live tunnel. Cells without a measurement show an em dash.
func RenderInteropBench(tp Throughput, meta Meta) string {
	var b strings.Builder
	b.WriteString("| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |\n")
	b.WriteString("|------------|----------------------------:|----------------------------:|-----------------------:|\n")
	for _, row := range interopMatrix {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			row.Protocol,
			benchCell(row.Client, tp),
			benchCell(row.Server, tp),
			benchCell(row.Self, tp),
		)
	}
	b.WriteString("\n")
	b.WriteString(meta.footer())
	return b.String()
}

// formatBits renders a bits-per-second rate in the largest unit that keeps the
// value >= 1, with three significant figures, e.g. 1.94 Gbit/s or 850 Mbit/s.
func formatBits(bps float64) string {
	switch {
	case bps >= 1e9:
		return trimSig(bps/1e9) + " Gbit/s"
	case bps >= 1e6:
		return trimSig(bps/1e6) + " Mbit/s"
	case bps >= 1e3:
		return trimSig(bps/1e3) + " kbit/s"
	default:
		return trimSig(bps) + " bit/s"
	}
}

// trimSig formats a value to three significant figures, dropping a trailing
// ".0"/".00" so whole numbers read cleanly.
func trimSig(v float64) string {
	prec := 2
	switch {
	case v >= 100:
		prec = 0
	case v >= 10:
		prec = 1
	}
	s := strconv.FormatFloat(v, 'f', prec, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	return s
}
