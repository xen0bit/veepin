package keygen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xen0bit/veepin/internal/confstore"
)

// Generate creates key material for a protocol option declared with `Generate` on
// its OptSpec. It receives the listener name, config directory, the Generate
// string from the OptSpec, and the option key the spec targets. It returns the
// set of key→value pairs to merge into the listener's options map, which will
// persist as file paths or inline strings.
//
// Generation is skipped by the caller for any option whose value is already
// non-empty in the current options map (the operator supplied their own).
// Multi-file generators (TLS, OpenVPN) return all the keys they touch, so the
// handler updates every option the generator affected rather than just the one
// it was dispatched for.
//
// hostnames become the SANs of a generated leaf certificate and are ignored by
// the generators that produce no certificate. An empty slice means the loopback
// defaults -- see DefaultHostnames.
func Generate(name, configDir, genType, optKey string, hostnames []string) (map[string]string, error) {
	dir, err := listenerDir(configDir, name)
	if err != nil {
		return nil, err
	}
	if len(hostnames) == 0 {
		hostnames = DefaultHostnames(name)
	}
	switch genType {
	case "tls":
		return genChain(dir, hostnames, tlsSpec)
	case "psk":
		return genPSK(optKey)
	case "wg-keypair":
		return genWireGuardKeypair()
	case "ed25519-key":
		return genEd25519(dir, optKey)
	case "x509-chain":
		return genChain(dir, hostnames, openVPNSpec)
	default:
		return nil, fmt.Errorf("keygen: unknown generate type %q", genType)
	}
}

// DefaultHostnames is what a generated certificate covers when the operator
// named nothing: loopback, plus the listener's own name.
//
// Loopback is there so the out-of-the-box flow works -- generate a listener on
// a laptop, dial it at 127.0.0.1, and the certificate verifies. The listener
// name is there because that is what a container or an /etc/hosts entry
// usually calls it. Neither covers a listener an operator will dial by its
// public name, which is what the hostnames field is for, and what the
// client-config endpoint warns about when the two disagree.
func DefaultHostnames(name string) []string {
	return []string{"localhost", name, "127.0.0.1", "::1"}
}

// listenerDir returns the per-listener subdirectory where generated key material
// is stored. The caller (the management API) is responsible for cleaning it up
// when the listener is deleted.
//
// The name is checked here rather than trusted from the caller: Generate is
// exported, this is where a name becomes a path, and the one other place in the
// tree that joins a name into a path makes the same check for the same reason.
func listenerDir(configDir, name string) (string, error) {
	if !confstore.ValidName(name) {
		return "", fmt.Errorf("keygen: refusing to generate for %q: %s", name, confstore.NameRefusal(name))
	}
	return filepath.Join(configDir, name), nil
}

// ensureDir creates the directory if it does not exist, returning an error
// suitable for the management API error path.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keygen: creating %s: %w", dir, err)
	}
	return nil
}
