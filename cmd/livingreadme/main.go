// Command livingreadme regenerates one machine-managed region of the project
// README from a CI job's results and writes it back in place.
//
// It reads the raw output of the job on stdin (or -in), parses it according to
// the region, renders the Markdown table, and swaps it between that region's
// marker comments in the README. With -check it writes nothing and exits 1 if
// the region is stale — the signal a pull-request run uses to preview the diff
// without committing.
//
// Usage:
//
//	go test -bench=. -benchmem ./... | livingreadme -region benchmark -sha "$SHA"
//	go test -tags interop -json ./tests/interop/... | livingreadme -region interop -sha "$SHA"
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xen0bit/veepin/internal/livingreadme"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "livingreadme:", err)
		os.Exit(1)
	}
}

func run() error {
	region := flag.String("region", "", "region to update: benchmark | interop | interop-benchmark")
	readmePath := flag.String("readme", "README.md", "path to the README file")
	inPath := flag.String("in", "", "input file to read results from (default stdin)")
	sha := flag.String("sha", "", "git commit SHA for the provenance footer")
	ref := flag.String("ref", "", "git ref for the provenance footer")
	workflow := flag.String("workflow", "", "CI workflow name for the provenance footer")
	check := flag.Bool("check", false, "do not write; exit 1 if the region would change")
	flag.Parse()

	if *region == "" {
		return fmt.Errorf("-region is required")
	}

	input, err := readInput(*inPath)
	if err != nil {
		return err
	}

	meta := livingreadme.Meta{
		SHA:      *sha,
		Ref:      *ref,
		Workflow: *workflow,
		When:     time.Now(),
	}

	var body string
	switch *region {
	case livingreadme.RegionBenchmark:
		body = livingreadme.RenderBenchmarks(livingreadme.ParseBenchmarks(input), meta)
	case livingreadme.RegionInterop:
		body = livingreadme.RenderInterop(livingreadme.ParseTestResults(input), meta)
	case livingreadme.RegionInteropBench:
		body = livingreadme.RenderInteropBench(livingreadme.ParseThroughput(input), meta)
	default:
		return fmt.Errorf("unknown or unsupported region %q", *region)
	}

	doc, err := os.ReadFile(*readmePath)
	if err != nil {
		return err
	}
	updated, err := livingreadme.ReplaceRegion(doc, *region, body)
	if err != nil {
		return err
	}

	if bytes.Equal(doc, updated) {
		fmt.Fprintf(os.Stderr, "livingreadme: %s region already up to date\n", *region)
		return nil
	}
	if *check {
		return fmt.Errorf("%s region is stale; regenerate with livingreadme -region %s", *region, *region)
	}
	if err := os.WriteFile(*readmePath, updated, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "livingreadme: updated %s region in %s\n", *region, *readmePath)
	return nil
}

func readInput(path string) (string, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}
