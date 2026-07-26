package openvpn

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/internal/openvpn/tlswrap"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
)

// staticKeyPEM builds a deterministic OpenVPN static key file, so both sides of
// these tests derive from the same material without one living in the repo.
func staticKeyPEM(seed byte) []byte {
	raw := make([]byte, tlswrap.StaticKeyLen)
	for i := range raw {
		raw[i] = byte(i)*7 + seed
	}
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	h := hex.EncodeToString(raw)
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return []byte(b.String())
}

// clientOpener builds the datagram a real client sends first: a
// P_CONTROL_HARD_RESET_CLIENT_V2, wrapped the way that client is configured.
func clientOpener(t *testing.T, wrap tlswrap.Wrapper) []byte {
	t.Helper()
	p := &wire.ControlPacket{
		Opcode:    wire.PControlHardResetClientV2,
		SessionID: wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8},
		PacketID:  0,
	}
	buf := make([]byte, p.MarshalLen())
	out, err := p.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if wrap == nil {
		return out
	}
	wrapped, err := wrap.Wrap(out)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

// serverFor builds just enough Server to exercise authenticateOpener: the
// wrapper factory is the only field it reads.
func serverFor(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	f, err := serverWrapperFactory(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{newWrapper: f}
}

// TestOpenerAuthenticationTLSCrypt is the property this change exists for: with
// --tls-crypt configured, an opener from a peer that does not hold the key is
// rejected before any session state is created, so an active prober gets
// silence instead of a server hard reset and the certificate flight.
func TestOpenerAuthenticationTLSCrypt(t *testing.T) {
	keyPEM := staticKeyPEM(0)
	srv := serverFor(t, ServerConfig{TLSCrypt: keyPEM})

	key, err := tlswrap.ParseStaticKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// The client direction is fixed at Inverse for tls-crypt; the server takes
	// Normal, which serverWrapperFactory picks.
	clientWrap, err := tlswrap.NewCrypt(key, tlswrap.Inverse)
	if err != nil {
		t.Fatal(err)
	}
	if !srv.authenticateOpener(clientOpener(t, clientWrap)) {
		t.Error("a correctly wrapped opener must be accepted")
	}

	// A prober that knows the protocol but not the key.
	if srv.authenticateOpener(clientOpener(t, nil)) {
		t.Error("an unwrapped opener must be rejected")
	}
	wrongKey, err := tlswrap.ParseStaticKey(staticKeyPEM(1))
	if err != nil {
		t.Fatal(err)
	}
	wrongWrap, err := tlswrap.NewCrypt(wrongKey, tlswrap.Inverse)
	if err != nil {
		t.Fatal(err)
	}
	if srv.authenticateOpener(clientOpener(t, wrongWrap)) {
		t.Error("an opener under the wrong key must be rejected")
	}
	// Garbage of a plausible length must not be accepted either.
	if srv.authenticateOpener(make([]byte, 64)) {
		t.Error("a garbage opener must be rejected")
	}
}

func TestOpenerAuthenticationTLSAuth(t *testing.T) {
	keyPEM := staticKeyPEM(0)
	// key-direction 0 on the client means the server takes Inverse.
	srv := serverFor(t, ServerConfig{TLSAuth: keyPEM, KeyDirection: 0})

	key, err := tlswrap.ParseStaticKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tlswrap.ParseDigest("")
	if err != nil {
		t.Fatal(err)
	}
	clientWrap := tlswrap.NewAuth(key, tlswrap.Normal, digest)
	if !srv.authenticateOpener(clientOpener(t, clientWrap)) {
		t.Error("a correctly wrapped opener must be accepted")
	}
	if srv.authenticateOpener(clientOpener(t, nil)) {
		t.Error("an unwrapped opener must be rejected")
	}
}

// The plain profile has nothing to check, so it must keep accepting openers —
// this change must not break a server configured without a static key.
func TestOpenerAuthenticationPlainProfileAcceptsAll(t *testing.T) {
	srv := serverFor(t, ServerConfig{})
	if srv.newWrapper != nil {
		t.Fatal("the plain profile should have no wrapper factory")
	}
	if !srv.authenticateOpener(clientOpener(t, nil)) {
		t.Error("the plain profile must accept an unwrapped opener")
	}
}

// Each client needs its own wrapper: one shared anti-replay window would reject
// the second client's packet ID 1 as a replay of the first's.
func TestWrapperFactoryMintsIndependentWrappers(t *testing.T) {
	keyPEM := staticKeyPEM(0)
	srv := serverFor(t, ServerConfig{TLSCrypt: keyPEM})

	key, err := tlswrap.ParseStaticKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Two clients, each sending their own first packet (both packet ID 1).
	for i := range 2 {
		clientWrap, cerr := tlswrap.NewCrypt(key, tlswrap.Inverse)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if !srv.authenticateOpener(clientOpener(t, clientWrap)) {
			t.Fatalf("client %d's opener was rejected; the replay window is being shared", i)
		}
	}
}

func TestServerConfigRejectsBothWrappings(t *testing.T) {
	cfg := ServerConfig{
		CA:       []byte("x"),
		Cert:     []byte("x"),
		Key:      []byte("x"),
		TLSAuth:  staticKeyPEM(0),
		TLSCrypt: staticKeyPEM(1),
	}
	if err := cfg.validate(); err == nil {
		t.Error("tls-auth and tls-crypt together must be rejected")
	}
}
