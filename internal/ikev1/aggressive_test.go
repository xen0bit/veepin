package ikev1

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/vlog"
)

// pair wires two sessions to each other over in-memory "sockets", so a whole
// exchange runs without a UDP stack. Each side's Send hands the message to the
// other's HandleInbound on a fresh goroutine, which is what a real transport
// does — the session lock must never be held across a send.
type pair struct {
	initiator, responder *Session

	mu      sync.Mutex
	initRes *Result
	respRes *Result
	initErr error
	respErr error
	settled chan struct{}
	closed  bool
}

type sideHandler struct {
	p    *pair
	self bool // true for the initiator
}

func (h sideHandler) Established(r Result) {
	h.p.mu.Lock()
	if h.self {
		h.p.initRes = &r
	} else {
		h.p.respRes = &r
	}
	done := h.p.initRes != nil && h.p.respRes != nil
	h.p.settle(done)
	h.p.mu.Unlock()
}

func (h sideHandler) Failed(err error) {
	h.p.mu.Lock()
	if h.self {
		h.p.initErr = err
	} else {
		h.p.respErr = err
	}
	h.p.settle(true)
	h.p.mu.Unlock()
}

// settle closes the completion channel once, with the pair's lock held.
func (p *pair) settle(now bool) {
	if now && !p.closed {
		p.closed = true
		close(p.settled)
	}
}

func newPair(t *testing.T, initCfg, respCfg Config) *pair {
	t.Helper()
	p := &pair{settled: make(chan struct{})}
	logger := vlog.Plain(testWriter{t})

	initCfg.Role = Initiator
	initCfg.Handler = sideHandler{p, true}
	initCfg.Logger = logger
	respCfg.Role = Responder
	respCfg.Handler = sideHandler{p, false}
	respCfg.Logger = logger

	initCfg.Send = func(msg []byte, _ bool) error {
		cp := append([]byte(nil), msg...)
		go p.responder.HandleInbound(cp)
		return nil
	}
	respCfg.Send = func(msg []byte, _ bool) error {
		cp := append([]byte(nil), msg...)
		go p.initiator.HandleInbound(cp)
		return nil
	}
	p.initiator = NewSession(initCfg)
	p.responder = NewSession(respCfg)
	return p
}

// testWriter routes session logs into the test output.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Logf("%s", bytes.TrimRight(b, "\n"))
	return len(b), nil
}

func (p *pair) run(t *testing.T) {
	t.Helper()
	p.initiator.Start()
	select {
	case <-p.settled:
	case <-time.After(10 * time.Second):
		t.Fatal("the exchange neither completed nor failed")
	}
}

// remoteAccessConfigs is the profile internal/cisco runs: Aggressive Mode with a
// group key, XAuth, Mode-Config and a tunnel-mode SA.
func remoteAccessConfigs(user, password string, groupKey []byte) (Config, Config) {
	local := net.IPv4(198, 51, 100, 2)
	peer := net.IPv4(198, 51, 100, 1)
	assigned := net.IPv4(10, 60, 0, 9).To4()

	initiator := Config{
		Mode:      ModeAggressive,
		Phase2:    Phase2RemoteAccess,
		PSK:       groupKey,
		GroupName: "engineering",
		XAuth:     &XAuthConfig{Username: user, Password: password},
		ModeCfg:   true,
		LocalIP:   local,
		PeerIP:    peer,
		LocalPort: 500,
		PeerPort:  500,
	}
	responder := Config{
		Mode:   ModeAggressive,
		Phase2: Phase2RemoteAccess,
		PSKFor: func(g string) ([]byte, bool) {
			if g == "engineering" {
				return groupKey, true
			}
			return nil, false
		},
		XAuth: &XAuthConfig{Authenticate: func(u, pw string) bool {
			return u == "alice" && pw == "password"
		}},
		ModeCfg: true,
		Assign: func() (ModeCfgReply, error) {
			return ModeCfgReply{
				Address: assigned,
				Netmask: net.IP{255, 255, 255, 0},
				DNS:     []net.IP{net.IPv4(10, 60, 0, 1).To4()},
				Banner:  "hello",
			}, nil
		},
		LocalIP:   peer,
		PeerIP:    local,
		LocalPort: 500,
		PeerPort:  500,
	}
	return initiator, responder
}

func TestAggressiveModeRemoteAccess(t *testing.T) {
	initCfg, respCfg := remoteAccessConfigs("alice", "password", []byte("group-secret"))
	p := newPair(t, initCfg, respCfg)
	p.run(t)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.initErr != nil || p.respErr != nil {
		t.Fatalf("exchange failed: initiator=%v responder=%v", p.initErr, p.respErr)
	}
	if p.initRes == nil || p.respRes == nil {
		t.Fatal("one side did not establish")
	}

	// The two ends must have mirrored SPIs and matching keys, or the data path
	// would encrypt into nothing the peer can open.
	if p.initRes.OutSPI != p.respRes.InSPI || p.initRes.InSPI != p.respRes.OutSPI {
		t.Errorf("SPIs do not mirror: %+v / %+v", p.initRes, p.respRes)
	}
	if !bytes.Equal(p.initRes.OutEncKey, p.respRes.InEncKey) ||
		!bytes.Equal(p.initRes.InEncKey, p.respRes.OutEncKey) ||
		!bytes.Equal(p.initRes.OutIntegKey, p.respRes.InIntegKey) ||
		!bytes.Equal(p.initRes.InIntegKey, p.respRes.OutIntegKey) {
		t.Error("the two ends derived different ESP keys")
	}
	if !p.initRes.Tunnel || !p.respRes.Tunnel {
		t.Error("the SA is not tunnel mode")
	}
	if !p.initRes.NATT || !p.respRes.NATT {
		t.Error("the exchange did not float to the NAT-T port")
	}
	if p.respRes.User != "alice" {
		t.Errorf("responder attributed the session to %q, want alice", p.respRes.User)
	}
	if p.initRes.ModeCfg == nil || !p.initRes.ModeCfg.Address.Equal(net.IPv4(10, 60, 0, 9)) {
		t.Errorf("initiator was assigned %+v", p.initRes.ModeCfg)
	}
	if p.initRes.ModeCfg.Banner != "hello" {
		t.Errorf("banner = %q", p.initRes.ModeCfg.Banner)
	}
	if p.respRes.ModeCfg == nil || !p.respRes.ModeCfg.Address.Equal(net.IPv4(10, 60, 0, 9)) {
		t.Errorf("responder recorded %+v", p.respRes.ModeCfg)
	}
}

func TestAggressiveModeWrongGroupKey(t *testing.T) {
	initCfg, respCfg := remoteAccessConfigs("alice", "password", []byte("group-secret"))
	initCfg.PSK = []byte("wrong")
	p := newPair(t, initCfg, respCfg)
	p.run(t)

	p.mu.Lock()
	defer p.mu.Unlock()
	// The initiator is the side that can tell: it verifies HASH_R first.
	if !errors.Is(p.initErr, ErrAuth) {
		t.Fatalf("initiator failed with %v, want ErrAuth", p.initErr)
	}
}

func TestAggressiveModeWrongPassword(t *testing.T) {
	initCfg, respCfg := remoteAccessConfigs("alice", "wrong", []byte("group-secret"))
	p := newPair(t, initCfg, respCfg)
	p.run(t)

	p.mu.Lock()
	defer p.mu.Unlock()
	if !errors.Is(p.respErr, ErrAuth) {
		t.Fatalf("responder failed with %v, want ErrAuth", p.respErr)
	}
	if p.respRes != nil {
		t.Error("the responder established an SA for a rejected password")
	}
}

func TestAggressiveModeUnknownGroup(t *testing.T) {
	initCfg, respCfg := remoteAccessConfigs("alice", "password", []byte("group-secret"))
	initCfg.GroupName = "nonesuch"
	p := newPair(t, initCfg, respCfg)
	p.run(t)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.respErr == nil {
		t.Fatal("the responder accepted an unknown group")
	}
	if p.respRes != nil || p.initRes != nil {
		t.Error("an SA was established for an unknown group")
	}
}

// TestGroupIdentityIsKeyID pins the identity Aggressive Mode presents: an opaque
// ID_KEY_ID carrying the group name, which is what a Cisco-style gateway matches
// its group key on. Sending an address instead would authenticate against the
// wrong key everywhere.
func TestGroupIdentityIsKeyID(t *testing.T) {
	s := NewSession(Config{GroupName: "engineering", LocalIP: net.IPv4(10, 0, 0, 1)})
	body := buildID(s.localIdentity())
	if body[0] != idKeyID {
		t.Errorf("ID type = %d, want ID_KEY_ID (%d)", body[0], idKeyID)
	}
	if got := groupNameOf(body); got != "engineering" {
		t.Errorf("group name round-tripped as %q", got)
	}

	// Without a group name the identity stays what Main Mode has always sent.
	plain := NewSession(Config{LocalIP: net.IPv4(10, 0, 0, 1)})
	if buildID(plain.localIdentity())[0] != idIPv4Addr {
		t.Error("a session with no group did not present its address")
	}
}

func TestGroupNameOfRejectsShortBodies(t *testing.T) {
	for i := range 4 {
		if got := groupNameOf(make([]byte, i)); got != "" {
			t.Errorf("%d octets yielded %q", i, got)
		}
	}
}

// TestAnySubnetSelector pins the gateway-side phase-2 traffic selector:
// 0.0.0.0/0 as an ID_IPV4_ADDR_SUBNET, which is a network followed by its mask.
func TestAnySubnetSelector(t *testing.T) {
	body := buildID(anySubnetID())
	if body[0] != idIPv4AddrSubnet {
		t.Fatalf("ID type = %d, want ID_IPV4_ADDR_SUBNET (%d)", body[0], idIPv4AddrSubnet)
	}
	if len(body) != 4+2*net.IPv4len {
		t.Fatalf("body is %d octets, want %d", len(body), 4+2*net.IPv4len)
	}
	for i, b := range body[4:] {
		if b != 0 {
			t.Errorf("selector octet %d = %#x, want zero", i, b)
		}
	}
}

// TestPhase2SelectorsFollowTheProfile: L2TP names the UDP/1701 flow between the
// outer addresses, remote access names the assigned inner address against
// everything. Getting this wrong produces an SA whose packets the peer's policy
// refuses.
func TestPhase2SelectorsFollowTheProfile(t *testing.T) {
	l2tp := NewSession(Config{
		LocalIP: net.IPv4(198, 51, 100, 2), PeerIP: net.IPv4(198, 51, 100, 1),
	})
	local, remote, err := l2tp.phase2Selectors()
	if err != nil {
		t.Fatal(err)
	}
	if local.proto != ipProtoUDP || local.port != l2tpPort || remote.port != l2tpPort {
		t.Errorf("L2TP selectors = %+v / %+v", local, remote)
	}

	ra := NewSession(Config{Phase2: Phase2RemoteAccess})
	if _, _, err := ra.phase2Selectors(); err == nil {
		t.Error("remote access produced a selector before an address was assigned")
	}
	ra.assigned = &ModeCfgReply{Address: net.IPv4(10, 60, 0, 9).To4()}
	local, remote, err = ra.phase2Selectors()
	if err != nil {
		t.Fatal(err)
	}
	if local.idType != idIPv4Addr || !net.IP(local.data).Equal(net.IPv4(10, 60, 0, 9)) {
		t.Errorf("remote-access local selector = %+v", local)
	}
	if remote.idType != idIPv4AddrSubnet {
		t.Errorf("remote-access peer selector = %+v", remote)
	}
}

// TestAuthMethodTracksXAuth: the number in the SA proposal is the only thing
// that says whether extended authentication follows, and both ends must agree
// before phase 1 keys anything.
func TestAuthMethodTracksXAuth(t *testing.T) {
	plain := NewSession(Config{})
	if plain.authMethod() != authPSK {
		t.Errorf("a profile without XAuth offered %d", plain.authMethod())
	}
	if !plain.supportedIKE(ikeProposal{
		encr: encrAES, keyBits: 256, hash: hashSHA2256, group: groupMODP2048, auth: authPSK,
	}) {
		t.Error("a plain PSK proposal was refused by a plain PSK profile")
	}
	if plain.supportedIKE(ikeProposal{
		encr: encrAES, keyBits: 256, hash: hashSHA2256, group: groupMODP2048, auth: authXAuthInitPSK,
	}) {
		t.Error("an XAuth proposal was accepted by a profile with no credentials to give")
	}

	x := NewSession(Config{XAuth: &XAuthConfig{}})
	if x.authMethod() != authXAuthInitPSK {
		t.Errorf("an XAuth profile offered %d", x.authMethod())
	}
	if x.supportedIKE(ikeProposal{
		encr: encrAES, keyBits: 256, hash: hashSHA2256, group: groupMODP2048, auth: authPSK,
	}) {
		t.Error("a plain PSK proposal was accepted by an XAuth profile, which would skip XAuth")
	}
}

// TestSupportedESPFollowsTheProfile: transport mode for L2TP, tunnel mode for
// remote access, and never the other one.
func TestSupportedESPFollowsTheProfile(t *testing.T) {
	base := espProposal{transformID: espTransformAES, keyBits: 256, authAlg: authHMACSHA2256}
	l2tp := NewSession(Config{})
	ra := NewSession(Config{Phase2: Phase2RemoteAccess})

	for _, tc := range []struct {
		encap            uint16
		wantL2TP, wantRA bool
	}{
		{encapUDPTransport, true, false},
		{encapTransport, true, false},
		{encapUDPTransportDraft, true, false},
		{encapUDPTunnel, false, true},
		{encapTunnel, false, true},
		{encapUDPTunnelDraft, false, true},
	} {
		p := base
		p.encap = tc.encap
		if got := l2tp.supportedESP(p); got != tc.wantL2TP {
			t.Errorf("L2TP encap %d: accepted=%v, want %v", tc.encap, got, tc.wantL2TP)
		}
		if got := ra.supportedESP(p); got != tc.wantRA {
			t.Errorf("remote access encap %d: accepted=%v, want %v", tc.encap, got, tc.wantRA)
		}
	}
}
