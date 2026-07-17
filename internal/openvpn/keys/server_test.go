package keys

import (
	"bytes"
	"testing"
)

// TestClientMarshalServerParseRoundTrip runs a client-marshalled key message
// through the server parser and checks every field survives.
func TestClientMarshalServerParseRoundTrip(t *testing.T) {
	ck, err := NewClientKeySource()
	if err != nil {
		t.Fatal(err)
	}
	msg := ck.MarshalClient("V4,cipher AES-256-GCM", "alice", "s3cret", "IV_PROTO=2\n")

	h, err := ParseClient(msg)
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if h.KeySource.PreMaster != ck.PreMaster || h.KeySource.Random1 != ck.Random1 || h.KeySource.Random2 != ck.Random2 {
		t.Error("key source did not round-trip")
	}
	if h.Options != "V4,cipher AES-256-GCM" {
		t.Errorf("options = %q", h.Options)
	}
	if h.Username != "alice" || h.Password != "s3cret" {
		t.Errorf("credentials = %q/%q", h.Username, h.Password)
	}
	if h.PeerInfo != "IV_PROTO=2\n" {
		t.Errorf("peer-info = %q", h.PeerInfo)
	}
}

// TestParseClientMinimal accepts a client message with empty credentials and no
// peer-info.
func TestParseClientMinimal(t *testing.T) {
	ck, _ := NewClientKeySource()
	msg := ck.MarshalClient("V4", "", "", "")
	h, err := ParseClient(msg)
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if h.Username != "" || h.Password != "" || h.PeerInfo != "" {
		t.Errorf("expected empty trailing fields, got %q/%q/%q", h.Username, h.Password, h.PeerInfo)
	}
}

// TestParseClientZeroLengthCredentials accepts the real-OpenVPN encoding of
// absent credentials: username and password as zero-length fields (a uint16 0
// with no trailing null), which is what a cert-only client sends. veepin's own
// client writes empty strings as length-1, so this guards the interop case its
// self-test would miss.
func TestParseClientZeroLengthCredentials(t *testing.T) {
	ck, _ := NewClientKeySource()
	var b []byte
	b = append(b, 0, 0, 0, 0, keyMethod2)
	b = append(b, ck.PreMaster[:]...)
	b = append(b, ck.Random1[:]...)
	b = append(b, ck.Random2[:]...)
	b = appendString(b, "V4,cipher AES-256-GCM") // options: length-prefixed with null
	b = append(b, 0, 0)                          // username: zero-length field
	b = append(b, 0, 0)                          // password: zero-length field
	peerInfo := "IV_VER=2.6.0\nIV_PROTO=2\n"
	b = appendUint16(b, len(peerInfo))
	b = append(b, peerInfo...)

	h, err := ParseClient(b)
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if h.Username != "" || h.Password != "" {
		t.Errorf("credentials = %q/%q, want empty", h.Username, h.Password)
	}
	if h.Options != "V4,cipher AES-256-GCM" {
		t.Errorf("options = %q", h.Options)
	}
	if h.PeerInfo != peerInfo {
		t.Errorf("peer-info = %q", h.PeerInfo)
	}
}

// TestServerMarshalParseRoundTrip runs a server-marshalled message through the
// client parser (ParseServer) and checks the randoms and options survive.
func TestServerMarshalParseRoundTrip(t *testing.T) {
	sk, err := NewServerKeySource()
	if err != nil {
		t.Fatal(err)
	}
	msg := sk.MarshalServer("V4,cipher AES-256-GCM")

	got, opts, err := ParseServer(msg)
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if got.Random1 != sk.Random1 || got.Random2 != sk.Random2 {
		t.Error("server randoms did not round-trip")
	}
	if opts != "V4,cipher AES-256-GCM" {
		t.Errorf("options = %q", opts)
	}
}

// TestDeriveMirrorsBetweenRoles is the crux: the client's encrypt key must equal
// the server's decrypt key and vice versa, so the two ends can talk. It derives
// both roles from one shared KeySource2 and session IDs and checks the GCM keys
// and IVs line up.
func TestDeriveMirrorsBetweenRoles(t *testing.T) {
	ck, _ := NewClientKeySource()
	sk, _ := NewServerKeySource()
	ks2 := &KeySource2{Client: *ck, Server: *sk}

	var clientSID, serverSID SessionID
	for i := range clientSID {
		clientSID[i] = byte(i + 1)
		serverSID[i] = byte(0x80 + i)
	}

	cd := ks2.Derive(clientSID, serverSID, false)
	sd := ks2.Derive(clientSID, serverSID, true)

	if !bytes.Equal(cd.EncryptKey[:], sd.DecryptKey[:]) {
		t.Error("client encrypt key != server decrypt key")
	}
	if !bytes.Equal(cd.DecryptKey[:], sd.EncryptKey[:]) {
		t.Error("client decrypt key != server encrypt key")
	}
	if !bytes.Equal(cd.EncryptIV[:], sd.DecryptIV[:]) {
		t.Error("client encrypt IV != server decrypt IV")
	}
	if !bytes.Equal(cd.DecryptIV[:], sd.EncryptIV[:]) {
		t.Error("client decrypt IV != server encrypt IV")
	}
}

// TestDeriveCBCMirrorsBetweenRoles is the same mirror check for the CBC keys.
func TestDeriveCBCMirrorsBetweenRoles(t *testing.T) {
	ck, _ := NewClientKeySource()
	sk, _ := NewServerKeySource()
	ks2 := &KeySource2{Client: *ck, Server: *sk}
	var clientSID, serverSID SessionID
	for i := range clientSID {
		clientSID[i] = byte(i + 1)
		serverSID[i] = byte(0x80 + i)
	}

	cd := ks2.DeriveCBC(clientSID, serverSID, false)
	sd := ks2.DeriveCBC(clientSID, serverSID, true)
	if !bytes.Equal(cd.EncryptKey[:], sd.DecryptKey[:]) || !bytes.Equal(cd.DecryptKey[:], sd.EncryptKey[:]) {
		t.Error("CBC cipher keys do not mirror between roles")
	}
	if !bytes.Equal(cd.EncryptHMAC[:], sd.DecryptHMAC[:]) || !bytes.Equal(cd.DecryptHMAC[:], sd.EncryptHMAC[:]) {
		t.Error("CBC HMAC keys do not mirror between roles")
	}
}
