package goldens

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// seedDirs are the fuzz seed corpora grown from these captures. Go runs every
// file in testdata/fuzz/<Target>/ on an ordinary `go test`, so committing real
// peer traffic there costs nothing and gives the fuzzer somewhere to start that
// is not a buffer of zeroes.
var seedDirs = []string{
	filepath.Join("..", "..", "ikev2", "payload", "testdata", "fuzz", "FuzzParseMessage"),
	filepath.Join("..", "..", "ikev2", "payload", "testdata", "fuzz", "FuzzParseBodies"),
	filepath.Join("..", "..", "wireguard", "wire", "testdata", "fuzz", "FuzzParseMessages"),
}

// Every committed fuzz seed has to be traceable to a capture, byte for byte.
//
// The value of a seed corpus is entirely in its provenance: bytes a real
// strongSwan sent put the fuzzer one mutation away from a valid message, where
// bytes somebody typed put it back where it started. A seed that drifted — a
// hand-edit to "fix" a failure, a stale file left after a recapture — would look
// identical and be worth nothing, and no amount of fuzzing would say so.
func TestEveryFuzzSeedComesFromACapture(t *testing.T) {
	known := map[string]string{} // bytes -> where they came from
	for name := range Registry {
		c, err := Load(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c.Records {
			known[string(r.Bytes)] = name + "/" + r.Label
			// A body is a subslice of its message, and the body targets are
			// seeded with them.
			if m, err := payload.ParseMessage(r.Bytes); err == nil {
				for _, p := range m.Payloads {
					known[string(p.Body)] = name + "/" + r.Label + "/" + p.Type.String()
				}
			}
		}
	}

	total := 0
	for _, dir := range seedDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("reading %s: %v", dir, err)
			continue
		}
		if len(entries) == 0 {
			t.Errorf("%s is empty; the target it seeds still starts from nothing", dir)
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("reading %s: %v", path, err)
				continue
			}
			b, err := parseFuzzSeed(string(raw))
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if _, ok := known[string(b)]; !ok {
				t.Errorf("%s holds bytes that appear in no committed corpus; a seed whose "+
					"provenance is gone is worth no more than a buffer of zeroes", path)
				continue
			}
			total++
		}
	}
	if total == 0 {
		t.Fatal("no seeds were checked, so this guard covers nothing")
	}
}

// parseFuzzSeed reads the corpus-entry format `go test -fuzz` writes: a version
// line, then one Go literal per fuzz argument. Every target seeded here takes a
// single []byte.
func parseFuzzSeed(s string) ([]byte, error) {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) != 2 || lines[0] != "go test fuzz v1" {
		return nil, errBadSeed
	}
	lit, ok := strings.CutPrefix(lines[1], "[]byte(")
	if !ok {
		return nil, errBadSeed
	}
	lit, ok = strings.CutSuffix(lit, ")")
	if !ok {
		return nil, errBadSeed
	}
	unquoted, err := strconv.Unquote(lit)
	if err != nil {
		return nil, err
	}
	return []byte(unquoted), nil
}

var errBadSeed = errors.New("not a single-[]byte `go test fuzz v1` corpus entry")
