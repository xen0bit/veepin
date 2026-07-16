package main

import (
	"flag"
	"io"
)

// newTestFlagSet returns a silent flag set for tests that only need flags bound.
func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}
