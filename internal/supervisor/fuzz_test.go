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
	"bytes"
	"encoding/json"
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
		// Never panic is the first contract, and it is the whole of what this
		// used to check: the body was one `if err != nil { return }` followed by
		// two comments, the first claiming a round-trip check that did not exist
		// and the second saying it was somebody else's job.
		cfg, err := parseListenerBytes(body)
		if err != nil {
			return
		}
		// A parse that succeeded has made two promises worth holding it to.
		//
		// First, that what it returned is valid -- the store calls Validate on
		// every read for exactly this reason, so a config that parses and does
		// not validate is a config that reached the fleet through a door nobody
		// is watching.
		if err := cfg.Validate(); err != nil {
			t.Fatalf("parsed a config that does not validate: %v\ninput: %q", err, body)
		}
		// Second, that the name is one we could have written, since it is about
		// to become a filename and an iptables comment.
		if !ValidName(cfg.Name) {
			t.Fatalf("parsed a config whose name cannot be a filename: %q\ninput: %q", cfg.Name, body)
		}
		// And the parse is idempotent over what it accepted: re-encoding and
		// re-parsing must give the same config back. A field that survives one
		// direction and not the other is how a setting silently reverts.
		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshalling a parsed config: %v", err)
		}
		again, err := parseListenerBytes(encoded)
		if err != nil {
			t.Fatalf("a config we just wrote does not parse: %v\nencoded: %s", err, encoded)
		}
		// Compared as encoded documents, not with reflect.DeepEqual on the
		// structs. An absent "options" and an "options":{} are the same
		// listener and differ as Go values (nil map versus empty map), so
		// DeepEqual reports a difference that does not exist -- the fuzzer
		// found that within a second, and it is not the property worth pinning.
		// What is: writing a config and reading it back gives that config.
		reencoded, err := json.Marshal(again)
		if err != nil {
			t.Fatalf("marshalling a re-parsed config: %v", err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("round trip changed the config:\n first: %s\nsecond: %s", encoded, reencoded)
		}
	})
}
