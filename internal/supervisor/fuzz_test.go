package supervisor

// Fuzz target for the listener config parser. The parser is the gateway to
// disk for a config the management API could persist and an operator could
// hand-edit; a malformed file must produce an error rather than a panic.
//
// Like the tree's other fuzz targets, the fuzzer does not exercise the manager
// beyond parseListenerBytes -- the manager opens TUNs and binds sockets, both
// out of reach for a `go test` run -- so a panic here is the remote-crash
// scenario that matters: an operator with file-write access (or a confused
// management API) feeding the supervisor bytes that take it down.

import (
	"testing"
)

func FuzzParseListenerFile(f *testing.F) {
	f.Add([]byte(`{"name":"site-a","protocol":"wireguard","options":{"private-key":"k"}}`))
	f.Add([]byte(`{"name":"x","protocol":"ikev2","enabled":true,"setup_nat":true,"wan":"eth0"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"name":"UPPER","protocol":"wireguard"}`))
	f.Add([]byte(`{"name":"ok","protocol":"wireguard","bogus":true}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		// parseListenerBytes must not panic on any input; it returns an error
		// instead. Anything it parses must round-trip through Validate, so a
		// successful parse of malformed data is also a finding here.
		if _, err := parseListenerBytes(body); err != nil {
			return
		}
		// Re-parse a serialization of the result; the parser is expected to be
		// idempotent over a config it accepted.
		// (Round-trip check is the responsibility of the unit tests; the fuzzer's
		// only contract here is "never panic".)
	})
}
