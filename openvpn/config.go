package openvpn

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is a parsed OpenVPN client profile: where to connect, the TLS identity,
// and the data cipher. It is filled from an .ovpn file, from individual options,
// or both. The PEM material may be given inline (from an .ovpn <ca>/<cert>/<key>
// block) or as a file path the parser reads.
type Config struct {
	Remote string // server host (required)
	Port   int    // server UDP port (default 1194)

	// CA, Cert and Key are PEM blocks: the CA that signs the server (and this
	// client), and this client's certificate and private key for mutual TLS.
	CA   []byte
	Cert []byte
	Key  []byte

	// Cipher is the data-channel cipher. Only AES-256-GCM is implemented; a
	// profile naming anything else is rejected at dial.
	Cipher string

	// Username and Password are sent in the key exchange for servers that want
	// --auth-user-pass; both empty means none.
	Username string
	Password string

	// TUNName is the desired interface name; empty lets the kernel pick.
	TUNName string

	// Logger receives progress logs; nil discards them.
	Logger *log.Logger
}

// Option keys accepted by client.Dial(ctx, "openvpn", opts). OptConfig points at
// an .ovpn file; the rest override individual fields.
const (
	OptConfig   = "config"   // path to an .ovpn file
	OptRemote   = "remote"   // server host
	OptPort     = "port"     // server UDP port
	OptCA       = "ca"       // path to the CA PEM
	OptCert     = "cert"     // path to the client certificate PEM
	OptKey      = "key"      // path to the client private key PEM
	OptCipher   = "cipher"   // data cipher (AES-256-GCM)
	OptUsername = "username" // auth-user-pass username
	OptPassword = "password" // auth-user-pass password
	OptTUNName  = "tun"      // desired TUN interface name
)

// defaultCipher is the only data cipher this client implements.
const defaultCipher = "AES-256-GCM"

// defaultPort is OpenVPN's assigned UDP port.
const defaultPort = 1194

// ParseConfigFile reads an .ovpn profile, resolving ca/cert/key file references
// relative to the profile's directory.
func ParseConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := parseConfig(f, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// parseConfig reads the subset of the OpenVPN config format a UDP client needs:
// remote, proto, dev, cipher, and the ca/cert/key material (inline blocks or
// file paths resolved against baseDir). Unknown directives are ignored, as
// OpenVPN's own parser tolerates options it does not use in a given mode.
func parseConfig(r io.Reader, baseDir string) (*Config, error) {
	cfg := &Config{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // PEM blocks can be large
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		// Inline block: <ca> ... </ca>, and cert/key.
		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") && !strings.HasPrefix(text, "</") {
			tag := strings.Trim(text, "<>")
			body, err := readInlineBlock(sc, tag)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			if err := cfg.setPEM(tag, []byte(body)); err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			continue
		}
		if err := cfg.setDirective(text, baseDir); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
	}
	return cfg, sc.Err()
}

// readInlineBlock consumes lines until the matching </tag>, returning the body.
func readInlineBlock(sc *bufio.Scanner, tag string) (string, error) {
	end := "</" + tag + ">"
	var b strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == end {
			return b.String(), nil
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return "", fmt.Errorf("unterminated <%s> block", tag)
}

// setDirective applies one whitespace-separated config line.
func (c *Config) setDirective(text, baseDir string) error {
	fields := strings.Fields(text)
	key, args := fields[0], fields[1:]
	switch key {
	case "remote":
		if len(args) < 1 {
			return fmt.Errorf("remote needs a host")
		}
		c.Remote = args[0]
		if len(args) >= 2 {
			p, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("remote port %q: %w", args[1], err)
			}
			c.Port = p
		}
	case "port":
		if len(args) < 1 {
			return fmt.Errorf("port needs a value")
		}
		p, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("port %q: %w", args[0], err)
		}
		c.Port = p
	case "proto":
		if len(args) >= 1 && !strings.HasPrefix(strings.ToLower(args[0]), "udp") {
			return fmt.Errorf("proto %q: only UDP is supported", args[0])
		}
	case "cipher", "data-ciphers":
		// Record the first named cipher; validation happens at dial.
		if len(args) >= 1 && c.Cipher == "" {
			c.Cipher = strings.Split(args[0], ":")[0]
		}
	case "ca":
		return c.setPEMFile("ca", args, baseDir)
	case "cert":
		return c.setPEMFile("cert", args, baseDir)
	case "key":
		return c.setPEMFile("key", args, baseDir)
	case "auth-user-pass":
		// Credentials from a file are out of scope; they come from options.
	default:
		// Ignored: dev, nobind, resolv-retry, verb, and the many directives that
		// configure a kernel client rather than the tunnel itself.
	}
	return nil
}

// setPEMFile reads a ca/cert/key file argument into the config.
func (c *Config) setPEMFile(kind string, args []string, baseDir string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s needs a file path", kind)
	}
	path := args[0]
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", kind, err)
	}
	return c.setPEM(kind, pem)
}

// setPEM stores PEM material under its directive name.
func (c *Config) setPEM(kind string, pem []byte) error {
	switch kind {
	case "ca":
		c.CA = pem
	case "cert":
		c.Cert = pem
	case "key":
		c.Key = pem
	default:
		return fmt.Errorf("unknown inline block <%s>", kind)
	}
	return nil
}

// applyOverrides layers non-empty options over a parsed config, so flags win over
// an .ovpn file. Keys match the Opt* constants.
func (c *Config) applyOverrides(opts map[string]string) error {
	if v := opts[OptRemote]; v != "" {
		c.Remote = v
	}
	if v := opts[OptPort]; v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%s %q: %w", OptPort, v, err)
		}
		c.Port = p
	}
	for _, f := range []struct {
		opt  string
		dest *[]byte
	}{
		{OptCA, &c.CA}, {OptCert, &c.Cert}, {OptKey, &c.Key},
	} {
		if path := opts[f.opt]; path != "" {
			pem, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("%s: %w", f.opt, err)
			}
			*f.dest = pem
		}
	}
	if v := opts[OptCipher]; v != "" {
		c.Cipher = v
	}
	if v := opts[OptUsername]; v != "" {
		c.Username = v
	}
	if v := opts[OptPassword]; v != "" {
		c.Password = v
	}
	if v := opts[OptTUNName]; v != "" {
		c.TUNName = v
	}
	return nil
}

// validate checks the config has what a dial needs and normalises defaults.
func (c *Config) validate() error {
	if c.Remote == "" {
		return fmt.Errorf("%s is required", OptRemote)
	}
	if len(c.CA) == 0 {
		return fmt.Errorf("%s is required", OptCA)
	}
	if len(c.Cert) == 0 || len(c.Key) == 0 {
		return fmt.Errorf("%s and %s are required", OptCert, OptKey)
	}
	if c.Port == 0 {
		c.Port = defaultPort
	}
	if c.Cipher == "" {
		c.Cipher = defaultCipher
	}
	if !strings.EqualFold(c.Cipher, defaultCipher) {
		return fmt.Errorf("unsupported cipher %q (only %s)", c.Cipher, defaultCipher)
	}
	return nil
}
