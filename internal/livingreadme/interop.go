package livingreadme

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
)

// interopCell is one cell of the interoperability matrix: the set of interop
// test functions that together prove it, and the peer label shown beside the
// pass/fail mark.
//
// A cell with no tests is untested-by-design (e.g. Fortinet has no open-source
// gateway to run the veepin client against); its Label is emitted verbatim, so
// it can carry a fixed string such as "—†".
type interopCell struct {
	Tests []string
	Label string // peer implementation, or the whole cell for an untested one
}

// interopRow is one protocol's row: the three directional cells.
type interopRow struct {
	Protocol string
	Client   interopCell // veepin client ↔ real server
	Server   interopCell // real client ↔ veepin server
	Self     interopCell // veepin ↔ veepin
}

// interopMatrix is the manifest that maps every protocol/direction cell to the
// interop test functions that back it. It is the single source of truth for the
// matrix's shape; the pass/fail marks come from a live test run. Keep this in
// step with tests/interop/interop_test.go — a test named here that no longer
// exists reads as a permanent failure, which is the intended loud signal.
var interopMatrix = []interopRow{
	{
		Protocol: "IKEv2",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinClientStrongswanServer",
			"TestInteropVeepinClientStrongswanServerCert",
			"TestInteropVeepinClientStrongswanServerChaCha20",
			"TestInteropVeepinClientStrongswanServerIPv6",
			"TestInteropVeepinClientStrongswanServerV6Underlay",
			"TestInteropVeepinClientStrongswanServerPQ",
		}, Label: "strongSwan (PSK + pubkey, AES-GCM + ChaCha20, dual-stack, v6 underlay, ML-KEM-768)"},
		Server: interopCell{Tests: []string{
			"TestInteropStrongswanClientVeepinServer",
			"TestInteropStrongswanClientVeepinServerEAP",
			"TestInteropStrongswanClientVeepinServerFragmented",
			"TestInteropStrongswanClientVeepinServerV6Underlay",
			"TestInteropStrongswanClientVeepinServerShaped",
			"TestInteropStrongswanClientVeepinServerPQ",
		}, Label: "strongSwan (+ EAP-MSCHAPv2, RFC 7383 frag, v6 underlay, TFC-padded, ML-KEM-768)"},
		Self: interopCell{Tests: []string{
			"TestInteropSelf",
			"TestInteropIKEv2ChildRekey",
			"TestInteropIKEv2IKERekey",
		}},
	},
	{
		Protocol: "WireGuard",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientWireguardServer"}, Label: "wireguard-go"},
		Server: interopCell{Tests: []string{
			"TestInteropWireguardClientVeepinServer",
			"TestInteropWireguardClientVeepinServerShaped",
		}, Label: "wireguard-go (+ padded)"},
		Self: interopCell{Tests: []string{"TestInteropWireguardSelf", "TestInteropWireguardRekey"}},
	},
	{
		Protocol: "OpenVPN",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinClientOpenVPNServer",
			"TestInteropOpenVPNTLSAuth",
			"TestInteropOpenVPNTLSCrypt",
			"TestInteropOpenVPNCBC",
		}, Label: "`openvpn` (×4 variants)"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenVPNClientVeepinServer",
			"TestInteropOpenVPNClientVeepinServerTLSAuth",
			"TestInteropOpenVPNClientVeepinServerTLSCrypt",
			"TestInteropOpenVPNClientVeepinServerShaped",
		}, Label: "`openvpn` (+ tls-auth, tls-crypt, padded)"},
		Self: interopCell{Tests: []string{"TestInteropOpenVPNSelf"}},
	},
	{
		Protocol: "SSTP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientSSTPServer"}, Label: "SoftEther"},
		Server: interopCell{Tests: []string{
			"TestInteropSSTPClientVeepinServer",
			"TestInteropSSTPClientVeepinServerShaped",
		}, Label: "`sstpc`/pppd (+ PPP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropSSTPSelf"}},
	},
	{
		Protocol: "SSH",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientSSHServer"}, Label: "`sshd` (PermitTunnel)"},
		Server:   interopCell{Tests: []string{"TestInteropSSHClientVeepinServer"}, Label: "`ssh -w`"},
		Self:     interopCell{Tests: []string{"TestInteropSSHSelf"}},
	},
	{
		Protocol: "L2TP/IPsec",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientL2TPServer"}, Label: "strongSwan + xl2tpd"},
		Server: interopCell{Tests: []string{
			"TestInteropL2TPClientVeepinServer",
			"TestInteropL2TPClientVeepinServerShaped",
		}, Label: "strongSwan + xl2tpd (+ PPP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropL2TPSelf"}},
	},
	{
		Protocol: "AnyConnect",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientAnyConnectServer"}, Label: "ocserv"},
		Server: interopCell{Tests: []string{
			"TestInteropAnyConnectClientVeepinServer",
			"TestInteropAnyConnectClientVeepinServerDTLS",
			"TestInteropAnyConnectClientVeepinServerShaped",
		}, Label: "openconnect (TLS, DTLS, CSTP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropAnyConnectSelf"}},
	},
	{
		Protocol: "Nebula",
		Client:   interopCell{Tests: []string{"TestInteropVeepinNebulaHostReferenceLighthouse"}, Label: "`nebula` (lighthouse)"},
		Server:   interopCell{Tests: []string{"TestInteropNebulaHostVeepinLighthouse"}, Label: "`nebula` (host)"},
		Self:     interopCell{Tests: []string{"TestInteropNebulaSelf"}, Label: "(via lighthouse)"},
	},
	{
		Protocol: "MASQUE-IP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinMasqueClientAioquicProxy"}, Label: "aioquic CONNECT-IP"},
		Server:   interopCell{Tests: []string{"TestInteropAioquicClientVeepinProxy"}, Label: "aioquic CONNECT-IP"},
		Self:     interopCell{Tests: []string{"TestInteropMasqueSelf"}},
	},
	{
		Protocol: "MASQUE-UDP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinUDPClientAioquicProxy"}, Label: "aioquic CONNECT-UDP"},
		Server:   interopCell{Tests: []string{"TestInteropAioquicUDPClientVeepinProxy"}, Label: "aioquic CONNECT-UDP"},
		Self:     interopCell{Tests: []string{"TestInteropMasqueUDPSelf"}},
	},
	{
		Protocol: "Fortinet",
		Client:   interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenconnectFortinetClientVeepinServer",
			"TestInteropOpenconnectFortinetDTLS",
			"TestInteropOpenconnectFortinet2FA",
			"TestInteropOpenconnectFortinetClientVeepinServerShaped",
		}, Label: "openconnect (TLS, DTLS, 2FA, PPP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropFortinetSelf"}, Label: "(over DTLS)"},
	},
	{
		Protocol: "GlobalProtect",
		Client:   interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenconnectGPClientVeepinServer",
			"TestInteropOpenconnectGPClientVeepinServerESP",
			"TestInteropOpenconnectGPClientVeepinServerShaped",
		}, Label: "openconnect (SSL tunnel, ESP, padded)"},
		Self: interopCell{Tests: []string{"TestInteropGPSelf"}, Label: "(over ESP)"},
	},
	{
		Protocol: "Cisco IPsec",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinCiscoClientStrongSwanServer",
		}, Label: "strongSwan (aggressive + XAuth)"},
		Server: interopCell{Tests: []string{
			"TestInteropStrongSwanCiscoClientVeepinServer",
			"TestInteropStrongSwanCiscoClientVeepinServerShaped",
		}, Label: "strongSwan (Mode-Config, TFC-padded)"},
		Self: interopCell{Tests: []string{"TestInteropCiscoSelf"}},
	},
	{
		Protocol: "Ivanti Connect Secure",
		Client:   interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenconnectPulseClientVeepinServer",
			"TestInteropOpenconnectPulseClientVeepinServerESP",
			"TestInteropOpenconnectPulseClientVeepinServerShaped",
		}, Label: "openconnect (IF-T/TLS, ESP, padded)"},
		Self: interopCell{Tests: []string{"TestInteropPulseSelf"}, Label: "(over ESP)"},
	},
	// SoftEther's two cross-implementation cells are not built. They carry "‡",
	// not "†": the dagger means *no open-source peer exists*, which is true of
	// FortiOS and false here — SoftEther VPN Server is Apache-2.0. Marking it
	// "†" would state in the README that no peer was available, when the truth
	// is that nobody has built the cells.
	//
	// They no longer wait on anything structural. This comment used to say the
	// blocker was internal/softether's own caveat — "the server switches frames
	// between connected clients rather than bridging them to the host's network"
	// — and that stopped being true when local.go put the server's interface on
	// its own switch, which the Self cell now proves. The remaining caveats are
	// real (every client is told the same 10.70.0.2, so a two-client cell is not
	// possible) but neither blocks a single-client cell in either direction.
	//
	// The Self column is no longer a dash, and getting it there is what found
	// the reason the others are. Neither end pumped frames: softether.Dial
	// opened a TAP and started nothing, and the server's switch forwarded
	// between sessions only, with the host's own interface not on the switch.
	// The sentence this comment used to carry — "a veepin↔veepin test is always
	// possible, so a dash there is never earned" — was right, and the dash was
	// hiding a missing data path rather than a missing afternoon.
	//
	// TestNoRowCarriesADashInTheSelfColumn is now the check, because a comment
	// is not one.
	{
		Protocol: "SoftEther VPN",
		Client:   interopCell{Label: "—‡"},
		Server:   interopCell{Label: "—‡"},
		Self:     interopCell{Tests: []string{"TestInteropSoftEtherSelf"}, Label: "(layer 2, switched)"},
	},
	{
		Protocol: "AmneziaWG",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientAmneziaWGServer"}, Label: "amneziawg-go"},
		Server:   interopCell{Tests: []string{"TestInteropAmneziaWGClientVeepinServer"}, Label: "amneziawg-go"},
		Self:     interopCell{Tests: []string{"TestInteropAmneziaWGSelf"}, Label: "(H1-H4, S1-S4, junk)"},
	},
	{
		Protocol: "L2TPv3",
		// The peer for both kernel cells IS the Linux kernel, so they need
		// l2tp_eth on the HOST. GitHub runners ship a kernel without it and the
		// cells skip there, which reads as not-passed in a CI-generated table --
		// hence the caveat in the label rather than a bare peer name.
		Client: interopCell{Tests: []string{"TestInteropVeepinClientKernelL2TPv3Server"},
			Label: "Linux kernel (`ip l2tp`, 8-octet asymmetric cookies) — needs `l2tp_eth` on the host"},
		Server: interopCell{Tests: []string{"TestInteropKernelL2TPv3ClientVeepinServer"},
			Label: "Linux kernel (`ip l2tp`) — needs `l2tp_eth` on the host"},
		Self: interopCell{Tests: []string{"TestInteropL2TPv3Self"}, Label: "(shaped)"},
	},
	{
		Protocol: "TOY*",
		Client:   interopCell{Tests: []string{"TestInteropVeepinToyClientReferencePeer"}, Label: "independent Python peer"},
		Server:   interopCell{Tests: []string{"TestInteropToyClientVeepinServer"}, Label: "independent Python peer"},
		Self:     interopCell{Tests: []string{"TestInteropToySelf"}},
	},
}

// TestResults maps an interop test function name to whether it passed. A test
// that failed, was skipped, or never ran is false (absent).
type TestResults map[string]bool

// ParseTestResults reads the newline-delimited JSON that `go test -json` emits
// and returns the pass/fail verdict for every top-level test. A test passes only
// if its final action is "pass"; "fail" and "skip" both count as not-passed. Sub
// tests (names containing "/") are ignored — the matrix keys on the parent.
func ParseTestResults(jsonOut string) TestResults {
	results := TestResults{}
	sc := bufio.NewScanner(strings.NewReader(jsonOut))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		switch ev.Action {
		case "pass":
			results[ev.Test] = true
		case "fail", "skip":
			if _, ok := results[ev.Test]; !ok {
				results[ev.Test] = false
			}
		}
	}
	return results
}

// renderCell renders one matrix cell against the results. An untested cell (no
// tests) emits its Label verbatim. A tested cell shows ✓ when every backing test
// passed and ✗ otherwise, followed by the peer label if any.
func renderCell(c interopCell, results TestResults) string {
	if len(c.Tests) == 0 {
		if c.Label == "" {
			return "—"
		}
		return c.Label
	}
	mark := "✓"
	for _, name := range c.Tests {
		if !results[name] {
			mark = "✗"
			break
		}
	}
	if c.Label == "" {
		return mark
	}
	return mark + " " + c.Label
}

// RenderInterop renders the interoperability matrix from a live set of test
// results, followed by a provenance footer. The manifest fixes the rows and peer
// labels; only the ✓/✗ marks come from results.
func RenderInterop(results TestResults, meta Meta) string {
	var b strings.Builder
	b.WriteString("| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |\n")
	b.WriteString("|------------|-----------------------------|-----------------------------|------------------------|\n")
	for _, row := range interopMatrix {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			row.Protocol,
			renderCell(row.Client, results),
			renderCell(row.Server, results),
			renderCell(row.Self, results),
		)
	}
	b.WriteString("\n")
	b.WriteString(meta.footer())
	return b.String()
}

// InteropShard is one parallel slice of the interop suite: a name usable as a
// GitHub Actions job and artifact identifier, and the -run regexp that selects
// exactly the tests backing one protocol's row.
type InteropShard struct {
	Name string `json:"name"`
	Run  string `json:"run"`
}

// InteropShards derives the suite's parallel split from the manifest above, one
// shard per protocol.
//
// Deriving the split rather than listing it separately is what keeps it honest.
// Cells still run serially within a shard, so the suite is bounded by its
// slowest protocol instead of the sum of all of them; but a hand-written shard
// list that drifted from the manifest would quietly stop running whatever it had
// missed, and a test that never runs is indistinguishable from one that passes.
// Adding a protocol row here adds a shard, and there is no way to add one
// without.
//
// A row whose cells are all empty — untested by design — yields no shard.
func InteropShards() []InteropShard {
	shards := make([]InteropShard, 0, len(interopMatrix))
	for _, row := range interopMatrix {
		var tests []string
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			tests = append(tests, c.Tests...)
		}
		if len(tests) == 0 {
			continue
		}
		shards = append(shards, InteropShard{
			Name: shardName(row.Protocol),
			Run:  "^(" + strings.Join(tests, "|") + ")$",
		})
	}
	return shards
}

// shardName slugs a protocol name into an identifier a workflow can use for a
// job label and an artifact file. "L2TP/IPsec" and "TOY*" are neither.
func shardName(protocol string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(protocol) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
