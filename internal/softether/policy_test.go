package softether

import "testing"

// TestPolicyNamesAreThePolicyPrefixedFieldNames pins the wire spelling against
// PackAddPolicy's own list. A name that drifts does not fail anywhere else: a
// peer reads the missing element back as zero, and zero is the permissive value
// for every restriction flag, so a drifted name looks exactly like a working
// tunnel.
func TestPolicyNamesAreThePolicyPrefixedFieldNames(t *testing.T) {
	p := NewPack()
	addPolicy(p, defaultPolicy(1))

	// One per PackAddPolicy line: 1 Access + the restriction bools + 2 named
	// uints + the zero uints + VLanId + Ver3.
	want := 1 + len(policyBoolNames) + 2 + len(policyZeroUintNames) + 1 + 1
	if got := len(p.elems); got != want {
		t.Errorf("policy wrote %d elements, want %d", got, want)
	}
	// The reference's PackAddPolicy emits 27 booleans and 10 integers; the
	// counts are asserted rather than derived so a name dropped from a list
	// above fails here instead of quietly shrinking the policy.
	if len(policyBoolNames) != 27 {
		t.Errorf("policyBoolNames has %d names, want 27 (PackAddPolicy's, less Access)",
			len(policyBoolNames))
	}
	if len(policyZeroUintNames) != 7 {
		t.Errorf("policyZeroUintNames has %d names, want 7 (PackAddPolicy's ten, less MaxConnection, TimeOut and VLanId)",
			len(policyZeroUintNames))
	}

	for _, name := range append(append([]string{}, policyBoolNames...), policyZeroUintNames...) {
		if p.Get("policy:"+name) == nil {
			t.Errorf("policy:%s is missing", name)
		}
	}
	for _, name := range []string{"Access", "MaxConnection", "TimeOut", "VLanId", "Ver3"} {
		if p.Get("policy:"+name) == nil {
			t.Errorf("policy:%s is missing", name)
		}
	}
}

// TestPolicyGrantsAccessAndImposesNoRestriction. Access is the one flag whose
// wrong value costs a working session: false is how the reference disables an
// account without deleting it. Every other flag is a restriction veepin's
// switch does not implement, so claiming one would be a lie the peer might act
// on.
func TestPolicyGrantsAccessAndImposesNoRestriction(t *testing.T) {
	p := NewPack()
	addPolicy(p, defaultPolicy(1))

	if p.GetInt("policy:Access") != 1 {
		t.Error("policy:Access is not 1: the session is granted no access")
	}
	for _, name := range policyBoolNames {
		if got := p.GetInt("policy:" + name); got != 0 {
			t.Errorf("policy:%s = %d, want 0 — veepin enforces no such restriction", name, got)
		}
	}
	for _, name := range policyZeroUintNames {
		if got := p.GetInt("policy:" + name); got != 0 {
			t.Errorf("policy:%s = %d, want 0 (the reference's own no-limit)", name, got)
		}
	}
	if got := p.GetInt("policy:Ver3"); got != 1 {
		t.Errorf("policy:Ver3 = %d, want 1 — the Ver 3 fields were written, so it must say so", got)
	}
}

// TestPolicyTimeoutIsSecondsWhileTheWelcomesIsMilliseconds. The two sit three
// lines apart in PackWelcome and carry different units. Conflating them makes a
// session claim a 20-millisecond idle timeout, or a 20000-second one, and
// neither shows up until a peer acts on it.
func TestPolicyTimeoutIsSecondsWhileTheWelcomesIsMilliseconds(t *testing.T) {
	if got := defaultPolicy(1).TimeOut; got != 20 {
		t.Errorf("policy TimeOut = %d, want 20 (seconds, per GetDefaultPolicy)", got)
	}
	if sessionTimeoutMillis < 1000 {
		t.Errorf("sessionTimeoutMillis = %d, which is too small to be milliseconds",
			sessionTimeoutMillis)
	}
}

// TestGetPolicyTellsAbsenceFromDenial is the claim that makes the second return
// value necessary. A welcome with no policy and a welcome that grants no access
// decode to the same struct, because the wire has no way to say "absent". A
// reader that acted on Access alone would refuse every server that omits the
// policy — which is any Ver 2 server, and was veepin's own until policy.go.
func TestGetPolicyTellsAbsenceFromDenial(t *testing.T) {
	absent := NewPack()
	absent.Add("session_name", TypeStr, StrValue("SID-X-1"))
	y, ok := getPolicy(absent)
	if ok {
		t.Error("getPolicy reported a policy in a welcome that carries none")
	}
	if y.Access {
		t.Error("an absent policy decoded to Access=true")
	}

	denied := NewPack()
	addPolicy(denied, Policy{Access: false, MaxConnection: 1})
	y, ok = getPolicy(denied)
	if !ok {
		t.Error("getPolicy reported no policy in a welcome that carries one")
	}
	if y.Access {
		t.Error("Access=false decoded as true")
	}
}

// TestPolicyRoundTrips through the encoder the server uses and the decoder the
// client uses, since those are the two halves that must agree.
func TestPolicyRoundTrips(t *testing.T) {
	want := Policy{Access: true, MaxConnection: 4, TimeOut: 30, VLANID: 7}
	p := NewPack()
	addPolicy(p, want)

	got, ok := getPolicy(p)
	if !ok {
		t.Fatal("getPolicy found no policy in one addPolicy just wrote")
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}
