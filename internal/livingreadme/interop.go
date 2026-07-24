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
		}, Label: "strongSwan (PSK + pubkey, AES-GCM + ChaCha20)"},
		Server: interopCell{Tests: []string{
			"TestInteropStrongswanClientVeepinServer",
			"TestInteropStrongswanClientVeepinServerFragmented",
		}, Label: "strongSwan (+ RFC 7383 frag)"},
		Self: interopCell{Tests: []string{
			"TestInteropSelf",
			"TestInteropIKEv2ChildRekey",
			"TestInteropIKEv2IKERekey",
		}},
	},
	{
		Protocol: "WireGuard",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientWireguardServer"}, Label: "wireguard-go"},
		Server:   interopCell{Tests: []string{"TestInteropWireguardClientVeepinServer"}, Label: "wireguard-go"},
		Self:     interopCell{Tests: []string{"TestInteropWireguardSelf", "TestInteropWireguardRekey"}},
	},
	{
		Protocol: "OpenVPN",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinClientOpenVPNServer",
			"TestInteropOpenVPNTLSAuth",
			"TestInteropOpenVPNTLSCrypt",
			"TestInteropOpenVPNCBC",
		}, Label: "`openvpn` (×4 variants)"},
		Server: interopCell{Tests: []string{"TestInteropOpenVPNClientVeepinServer"}, Label: "`openvpn`"},
		Self:   interopCell{Tests: []string{"TestInteropOpenVPNSelf"}},
	},
	{
		Protocol: "SSTP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientSSTPServer"}, Label: "SoftEther"},
		Server:   interopCell{Tests: []string{"TestInteropSSTPClientVeepinServer"}, Label: "`sstpc`/pppd"},
		Self:     interopCell{Tests: []string{"TestInteropSSTPSelf"}},
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
		Server:   interopCell{Tests: []string{"TestInteropL2TPClientVeepinServer"}, Label: "strongSwan + xl2tpd"},
		Self:     interopCell{Tests: []string{"TestInteropL2TPSelf"}},
	},
	{
		Protocol: "AnyConnect",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientAnyConnectServer"}, Label: "ocserv"},
		Server:   interopCell{Tests: []string{"TestInteropAnyConnectClientVeepinServer"}, Label: "openconnect"},
		Self:     interopCell{Tests: []string{"TestInteropAnyConnectSelf"}},
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
		}, Label: "openconnect (TLS, DTLS, 2FA)"},
		Self: interopCell{Tests: []string{"TestInteropFortinetSelf"}, Label: "(over DTLS)"},
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
