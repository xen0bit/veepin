// Package amneziawg implements the AmneziaWG protocol, a DPI-resistant fork of
// WireGuard that applies obfuscation to defeat packet-signature classification.
// It reuses the noise handshake, transport encryption, and cryptokey routing from
// internal/wireguard wholesale, wrapping only the wire format: message type
// constants are replaced, and random padding is prepended to each message.
//
// Both ends must be configured with identical obfuscation parameters. There is
// no negotiation — which is the point, since a negotiation would itself be a
// signature.
package amneziawg

import (
	"context"
	"fmt"
	"strconv"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/wireguard"
)

const (
	OptPrivateKey   = "private-key"
	OptPublicKey    = "public-key"
	OptEndpoint     = "endpoint"
	OptAddress      = "address"
	OptAllowedIPs   = "allowed-ips"
	OptPresharedKey = "preshared-key"
	OptDNS          = "dns"
	OptMTU          = "mtu"
	OptTUNName      = "tun"
	OptShape        = "shape"

	// H1..H4 and S1..S4, in AmneziaWG's own naming.
	OptTypeInit   = "type-init"
	OptTypeResp   = "type-resp"
	OptTypeCookie = "type-cookie"
	OptTypeTrans  = "type-trans"
	OptPadInit    = "pad-init"
	OptPadResp    = "pad-resp"
	OptPadCookie  = "pad-cookie"
	OptPadTrans   = "pad-trans"
	// Jc / Jmin / Jmax.
	OptJunkCount = "junk-count"
	OptJunkMin   = "junk-min"
	OptJunkMax   = "junk-max"
)

const (
	// Spelled as literals, not as references to the wireguard constants they
	// mirror: cmd/veepin/flags_test.go reads these values straight out of the
	// source, so a cross-package reference reads as "no constant declared".
	OptServerConfig     = "config"
	OptServerPrivateKey = "private-key"
	OptServerListenIP   = "listen"
	OptServerListenPort = "listen-port"
	OptServerAddress    = "address"
	OptServerMTU        = "mtu"
	OptServerTUNName    = "tun"
	OptServerShape      = "shape"

	OptServerPeerPublicKey    = "peer-public-key"
	OptServerPeerPresharedKey = "peer-preshared-key"
	OptServerPeerAllowedIPs   = "peer-allowed-ips"

	// The obfuscation keys are deliberately spelled the same on both sides:
	// the two ends must be configured identically, and divergent names invite
	// the mismatch that produces a silent total failure.
)

// parseObfuscation reads the shared obfuscation options. Client and server use
// the same spellings deliberately: the two must be configured identically, and
// divergent names invite the mismatch that produces a silent total failure.
func parseObfuscation(opts map[string]string) wireguard.ObfuscationConfig {
	var o wireguard.ObfuscationConfig
	u8 := func(key string, dst *uint8) {
		if v := opts[key]; v != "" {
			if n, err := strconv.ParseUint(v, 10, 8); err == nil {
				*dst = uint8(n)
			}
		}
	}
	num := func(key string, dst *int) {
		if v := opts[key]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	u8(OptTypeInit, &o.TypeInitiation)
	u8(OptTypeResp, &o.TypeResponse)
	u8(OptTypeCookie, &o.TypeCookie)
	u8(OptTypeTrans, &o.TypeTransport)
	num(OptPadInit, &o.PadInitiation)
	num(OptPadResp, &o.PadResponse)
	num(OptPadCookie, &o.PadCookie)
	num(OptPadTrans, &o.PadTransport)
	num(OptJunkCount, &o.JunkCount)
	num(OptJunkMin, &o.JunkMin)
	num(OptJunkMax, &o.JunkMax)
	return o
}

// Config is the AmneziaWG client config.
type Config struct {
	wireguard.Config
	Obfuscation wireguard.ObfuscationConfig
}

func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	cfg.Config.Obfuscation = cfg.Obfuscation
	return wireguard.Dial(ctx, cfg.Config)
}

// ServerConfig configures an AmneziaWG server.
type ServerConfig struct {
	wireguard.ServerConfig
	Obfuscation wireguard.ObfuscationConfig
}

func NewServer(cfg ServerConfig) (client.Server, error) {
	cfg.ServerConfig.Obfuscation = cfg.Obfuscation
	return wireguard.NewServer(cfg.ServerConfig)
}

type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	var cfg Config
	// Directly wire up options to wireguard.Config (reuse the struct directly).
	cfg.PrivateKey = opts[OptPrivateKey]
	cfg.Address = splitList(opts[OptAddress])
	cfg.DNS = splitList(opts[OptDNS])
	cfg.TUNName = opts[OptTUNName]
	if v := opts[OptMTU]; v != "" {
		cfg.MTU, _ = strconv.Atoi(v)
	}
	if v := opts[OptShape]; v != "" {
		cfg.Shape, _ = strconv.Atoi(v)
	}
	// Set up a single peer.
	pub := opts[OptPublicKey]
	endpoint := opts[OptEndpoint]
	allowed := opts[OptAllowedIPs]
	if allowed == "" {
		allowed = "0.0.0.0/0"
	}
	if pub != "" || endpoint != "" {
		cfg.Peers = []wireguard.Peer{{
			PublicKey:  pub,
			Endpoint:   endpoint,
			AllowedIPs: splitList(allowed),
		}}
	}
	// Guarded: a preshared key with no peer to attach it to is a config error,
	// not a panic on Peers[0].
	if v := opts[wireguard.OptPresharedKey]; v != "" {
		if len(cfg.Peers) == 0 {
			return nil, fmt.Errorf("amneziawg: %s needs a peer (%s or %s)",
				wireguard.OptPresharedKey, OptPublicKey, OptEndpoint)
		}
		cfg.Peers[0].PresharedKey = v
	}

	cfg.Obfuscation = parseObfuscation(opts)
	return dialer{cfg: cfg}, nil
}

func parseServerOptions(opts map[string]string) (client.Server, error) {
	// The tunnel half is byte-for-byte WireGuard, so the option surface is
	// shared rather than re-parsed here. Only the obfuscation is ours.
	sc, err := wireguard.ServerConfigFromOptions(opts)
	if err != nil {
		return nil, err
	}
	// Without this the server runs stock WireGuard and cannot read a single
	// datagram from an obfuscated client.
	sc.Obfuscation = parseObfuscation(opts)
	return wireguard.NewServer(sc)
}

func splitList(val string) []string {
	if val == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(val); i++ {
		if i == len(val) || val[i] == ',' || val[i] == ' ' {
			if i > start {
				out = append(out, val[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func init() {
	client.Register("amneziawg", parseOptions)
	client.RegisterServer("amneziawg", parseServerOptions)
}
