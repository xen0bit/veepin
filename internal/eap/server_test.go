package eap

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

// simulateClient plays the EAP-MSCHAPv2 peer: it answers a Challenge with a
// correct Response and returns its own MSK for comparison.
func simulateClient(t *testing.T, challengeReq Packet, username, password string) (Packet, []byte) {
	t.Helper()
	if challengeReq.Type != TypeMSCHAPv2 {
		t.Fatalf("expected MSCHAPv2 challenge, got type %d", challengeReq.Type)
	}
	data := challengeReq.Data
	if mschapOpcode(data[0]) != opChallenge {
		t.Fatalf("expected challenge opcode, got %d", data[0])
	}
	var authChallenge [16]byte
	copy(authChallenge[:], data[5:21])

	var peerChallenge [16]byte
	_, _ = rand.Read(peerChallenge[:])

	ntHash := ntPasswordHash(password)
	ntResp := generateNTResponse(authChallenge, peerChallenge, username, ntHash)

	// Build the MSCHAPv2 Response type-data.
	resp := make([]byte, 5)
	resp[0] = byte(opResponse)
	resp[1] = data[1] // echo MSCHAPv2 ID
	resp[4] = 49
	resp = append(resp, peerChallenge[:]...)
	resp = append(resp, make([]byte, 8)...) // reserved
	resp = append(resp, ntResp[:]...)
	resp = append(resp, 0x00) // flags
	resp = append(resp, []byte(username)...)
	msLen := len(resp)
	resp[2] = byte(msLen >> 8)
	resp[3] = byte(msLen)

	clientMSK := deriveMSK(ntHash, ntResp)
	return Packet{Code: CodeResponse, Identifier: challengeReq.Identifier, Type: TypeMSCHAPv2, Data: resp}, clientMSK
}

func creds(users map[string]string) CredentialLookup {
	return func(u string) (string, bool) { p, ok := users[u]; return p, ok }
}

func TestMSCHAPv2SuccessfulAuth(t *testing.T) {
	srv := NewServer(creds(map[string]string{"alice": "s3cr3t-pass"}), "vpn.example")

	challenge, err := srv.Begin(1)
	if err != nil {
		t.Fatal(err)
	}
	clientResp, clientMSK := simulateClient(t, challenge, "alice", "s3cr3t-pass")

	// Server verifies and issues an MSCHAPv2 Success request.
	successReq, done, err := srv.HandlePeer(clientResp)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("should not be done before success ack")
	}
	if successReq.Type != TypeMSCHAPv2 || mschapOpcode(successReq.Data[0]) != opSuccess {
		t.Fatalf("expected MSCHAPv2 success request, got %+v", successReq)
	}

	// Client acknowledges; server emits EAP-Success and finishes.
	ack := Packet{Code: CodeResponse, Identifier: successReq.Identifier, Type: TypeMSCHAPv2, Data: []byte{byte(opSuccess)}}
	final, done, err := srv.HandlePeer(ack)
	if err != nil {
		t.Fatal(err)
	}
	if !done || final.Code != CodeSuccess {
		t.Fatalf("expected EAP-Success, got %+v done=%v", final, done)
	}

	out := srv.Outcome()
	if !out.Success || out.Username != "alice" {
		t.Fatalf("bad outcome: %+v", out)
	}
	if len(out.MSK) != 64 {
		t.Fatalf("MSK length = %d, want 64", len(out.MSK))
	}
	if !bytes.Equal(out.MSK, clientMSK) {
		t.Fatal("server and client derived different MSKs")
	}
}

func TestMSCHAPv2WrongPassword(t *testing.T) {
	srv := NewServer(creds(map[string]string{"alice": "correct-pass"}), "vpn.example")
	challenge, _ := srv.Begin(7)
	clientResp, _ := simulateClient(t, challenge, "alice", "WRONG-pass")

	failReq, done, err := srv.HandlePeer(clientResp)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("failure request should not mark done yet")
	}
	if failReq.Type != TypeMSCHAPv2 || mschapOpcode(failReq.Data[0]) != opFailure {
		t.Fatalf("expected MSCHAPv2 failure, got %+v", failReq)
	}
	if srv.Outcome().Success {
		t.Fatal("wrong password should not authenticate")
	}
}

func TestMSCHAPv2UnknownUser(t *testing.T) {
	srv := NewServer(creds(map[string]string{"alice": "x"}), "vpn.example")
	challenge, _ := srv.Begin(1)
	clientResp, _ := simulateClient(t, challenge, "bob", "whatever")
	failReq, _, err := srv.HandlePeer(clientResp)
	if err != nil {
		t.Fatal(err)
	}
	if mschapOpcode(failReq.Data[0]) != opFailure {
		t.Fatal("unknown user should get a failure")
	}
	if srv.Outcome().Success {
		t.Fatal("unknown user must not authenticate")
	}
}

func TestEAPPacketRoundTrip(t *testing.T) {
	p := Packet{Code: CodeRequest, Identifier: 42, Type: TypeMSCHAPv2, Data: []byte("hello")}
	got, err := Parse(p.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != p.Code || got.Identifier != 42 || got.Type != p.Type || !bytes.Equal(got.Data, p.Data) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	// Success packets carry no type/data.
	s := Packet{Code: CodeSuccess, Identifier: 9}
	gs, err := Parse(s.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if gs.Code != CodeSuccess || gs.Identifier != 9 {
		t.Fatalf("success round trip: %+v", gs)
	}
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/creds"
	content := "# comment\nalice:wonderland\nbob:p@ss:word\n\n  carol  :spaces\n"
	if err := osWriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Count() != 3 {
		t.Fatalf("count = %d, want 3", st.Count())
	}
	if p, ok := st.Lookup("alice"); !ok || p != "wonderland" {
		t.Fatalf("alice = %q %v", p, ok)
	}
	// Password containing a colon is preserved.
	if p, ok := st.Lookup("bob"); !ok || p != "p@ss:word" {
		t.Fatalf("bob = %q %v", p, ok)
	}
	// Username whitespace trimmed.
	if p, ok := st.Lookup("carol"); !ok || p != "spaces" {
		t.Fatalf("carol = %q %v", p, ok)
	}
	if _, ok := st.Lookup("mallory"); ok {
		t.Fatal("unknown user should not be found")
	}
}

func osWriteFile(path string, b []byte, perm os.FileMode) error {
	return os.WriteFile(path, b, perm)
}
