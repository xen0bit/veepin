package keygen

import (
	"fmt"
	"os"
	"path/filepath"
)

// Generate creates key material for a protocol option declared with `Generate` on
// its OptSpec. It receives the listener name, config directory, the Generate
// string from the OptSpec, the option key the spec targets, and the current
// (possibly partial) options map so it can see what other keys are already
// filled. It returns the set of key→value pairs to merge into the listener's
// options map, which will persist as file paths or inline strings.
//
// Generation is skipped for any option whose value is already non-empty in the
// current options map (the operator supplied their own). Multi-file generators
// (TLS, OpenVPN) return all the keys they touch, so the handler updates every
// option the generator affected rather than just the one it was dispatched for.
func Generate(name, configDir, genType, optKey string, existing map[string]string) (map[string]string, error) {
	dir := listenerDir(configDir, name)
	switch genType {
	case "tls":
		return genTLS(dir)
	case "psk":
		return genPSK(optKey)
	case "wg-keypair":
		return genWireGuardKeypair()
	case "ed25519-key":
		return genEd25519(dir, optKey)
	case "x509-chain":
		return genX509Chain(dir)
	default:
		return nil, fmt.Errorf("keygen: unknown generate type %q", genType)
	}
}

// listenerDir returns the per-listener subdirectory where generated key material
// is stored. The caller (the management API) is responsible for cleaning it up
// when the listener is deleted.
func listenerDir(configDir, name string) string {
	return filepath.Join(configDir, name)
}

// ensureDir creates the directory if it does not exist, returning an error
// suitable for the management API error path.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keygen: creating %s: %w", dir, err)
	}
	return nil
}
