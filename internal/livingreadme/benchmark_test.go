package livingreadme

import (
	"strings"
	"testing"
)

const sampleBenchOut = `goos: linux
goarch: amd64
pkg: github.com/xen0bit/veepin/internal/ikev2/esp
cpu: Intel(R) Xeon(R)
BenchmarkEncap/1400-8   	  512345	      1640 ns/op	 853.66 MB/s	     512 B/op	       2 allocs/op
BenchmarkDecap/1400-8   	  700000	      1230 ns/op	1138.21 MB/s	     256 B/op	       1 allocs/op
PASS
ok  	github.com/xen0bit/veepin/internal/ikev2/esp	2.100s
pkg: github.com/xen0bit/veepin/internal/nebula
BenchmarkAESGCMEncrypt/64-8   	 2000000	       320.0 ns/op	     0 B/op	       1 allocs/op
ok  	github.com/xen0bit/veepin/internal/nebula	1.000s
`

func TestParseBenchmarks(t *testing.T) {
	benches := ParseBenchmarks(sampleBenchOut)
	if len(benches) != 3 {
		t.Fatalf("got %d benchmarks, want 3: %+v", len(benches), benches)
	}

	first := benches[0]
	if first.Pkg != "internal/ikev2/esp" {
		t.Errorf("pkg = %q, want internal/ikev2/esp", first.Pkg)
	}
	if first.Name != "BenchmarkEncap/1400" {
		t.Errorf("name = %q, want BenchmarkEncap/1400 (procs stripped)", first.Name)
	}
	if first.NsOp != 1640 {
		t.Errorf("ns/op = %v, want 1640", first.NsOp)
	}
	if first.MBs != 853.66 {
		t.Errorf("MB/s = %v, want 853.66", first.MBs)
	}
	if first.Allocs != 2 {
		t.Errorf("allocs = %d, want 2", first.Allocs)
	}

	// The nebula benchmark has no MB/s.
	last := benches[2]
	if last.Pkg != "internal/nebula" {
		t.Errorf("pkg = %q, want internal/nebula", last.Pkg)
	}
	if last.MBs != 0 {
		t.Errorf("MB/s = %v, want 0 (no SetBytes)", last.MBs)
	}
}

func TestStripProcs(t *testing.T) {
	cases := map[string]string{
		"BenchmarkFoo-8":        "BenchmarkFoo",
		"BenchmarkFoo/1400-16":  "BenchmarkFoo/1400",
		"BenchmarkFoo":          "BenchmarkFoo",
		"BenchmarkFoo/case-abc": "BenchmarkFoo/case-abc",
	}
	for in, want := range cases {
		if got := stripProcs(in); got != want {
			t.Errorf("stripProcs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderBenchmarks(t *testing.T) {
	benches := ParseBenchmarks(sampleBenchOut)
	out := RenderBenchmarks(benches, Meta{})

	if !strings.Contains(out, "| Package | Benchmark |") {
		t.Error("missing table header")
	}
	if !strings.Contains(out, "`internal/ikev2/esp`") {
		t.Error("missing esp package cell")
	}
	if !strings.Contains(out, "853.7 MB/s") {
		t.Errorf("throughput not rendered/rounded:\n%s", out)
	}
	// The nebula row has no throughput, shown as an em dash.
	if !strings.Contains(out, "| —") {
		t.Errorf("missing em-dash for a no-throughput row:\n%s", out)
	}
}

func TestRenderBenchmarksEmpty(t *testing.T) {
	if got := RenderBenchmarks(nil, Meta{}); got != "" {
		t.Errorf("empty render should be empty with no meta, got %q", got)
	}
}

func TestTrim(t *testing.T) {
	cases := map[float64]string{
		1640.0:  "1640",
		853.66:  "853.7",
		0.5:     "0.5",
		1000.04: "1000",
	}
	for in, want := range cases {
		if got := trim(in); got != want {
			t.Errorf("trim(%v) = %q, want %q", in, got, want)
		}
	}
}
