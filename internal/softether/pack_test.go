package softether

import (
	"bytes"
	"testing"
	"unsafe"
)

// encodeAndBack is a round-trip helper: encode, decode, verify.
func encodeAndBack(t *testing.T, p *Pack, check func(*Pack)) {
	t.Helper()
	data, err := p.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	p2, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v (len=%d)", err, len(data))
	}
	check(p2)
}

func TestIntRoundTrip(t *testing.T) {
	p := NewPack()
	p.Add("port", TypeInt, IntValue(443))
	p.Add("version", TypeInt, IntValue(2))
	encodeAndBack(t, p, func(p2 *Pack) {
		if got := p2.GetInt("port"); got != 443 {
			t.Errorf("port = %d, want 443", got)
		}
		if got := p2.GetInt("version"); got != 2 {
			t.Errorf("version = %d, want 2", got)
		}
	})
}

func TestStrRoundTrip(t *testing.T) {
	p := NewPack()
	p.Add("method", TypeStr, StrValue("login"))
	p.Add("hubname", TypeStr, StrValue("VPN"))
	encodeAndBack(t, p, func(p2 *Pack) {
		if got := p2.GetStr("method"); got != "login" {
			t.Errorf("method = %q, want %q", got, "login")
		}
		if got := p2.GetStr("hubname"); got != "VPN" {
			t.Errorf("hubname = %q, want %q", got, "VPN")
		}
	})
}

func TestDataRoundTrip(t *testing.T) {
	p := NewPack()
	p.Add("secure_password", TypeData, DataValue([]byte{1, 2, 3, 4, 5}))
	encodeAndBack(t, p, func(p2 *Pack) {
		data := p2.GetData("secure_password")
		if len(data) != 5 || data[0] != 1 || data[4] != 5 {
			t.Errorf("secure_password = %v, want [1 2 3 4 5]", data)
		}
	})
}

func TestInt64RoundTrip(t *testing.T) {
	p := NewPack()
	p.Add("session_id", TypeInt64, Int64Value(0xdeadbeefcafe))
	encodeAndBack(t, p, func(p2 *Pack) {
		e := p2.Get("session_id")
		if e == nil || len(e.Values) == 0 {
			t.Fatal("session_id not found")
		}
		if e.Values[0].Int64 != 0xdeadbeefcafe {
			t.Errorf("session_id = %x, want deadbeefcafe", e.Values[0].Int64)
		}
	})
}

func TestUniStrRoundTrip(t *testing.T) {
	p := NewPack()
	p.Add("product", TypeUniStr, UniStrValue("SoftEther VPN"))
	encodeAndBack(t, p, func(p2 *Pack) {
		e := p2.Get("product")
		if e == nil || len(e.Values) == 0 {
			t.Fatal("product not found")
		}
		if e.Values[0].UniStr != "SoftEther VPN" {
			t.Errorf("product = %q, want %q", e.Values[0].UniStr, "SoftEther VPN")
		}
	})
}

func TestMultiValueRoundTrip(t *testing.T) {
	p := NewPack()
	p.AddMulti("routes", TypeStr, []Value{StrValue("10.0.0.0/8"), StrValue("172.16.0.0/12")})
	encodeAndBack(t, p, func(p2 *Pack) {
		e := p2.Get("routes")
		if e == nil {
			t.Fatal("routes not found")
		}
		if len(e.Values) != 2 {
			t.Fatalf("routes has %d values, want 2", len(e.Values))
		}
		if e.Values[0].Str != "10.0.0.0/8" {
			t.Errorf("routes[0] = %q, want %q", e.Values[0].Str, "10.0.0.0/8")
		}
		if e.Values[1].Str != "172.16.0.0/12" {
			t.Errorf("routes[1] = %q, want %q", e.Values[1].Str, "172.16.0.0/12")
		}
	})
}

func TestEmptyPack(t *testing.T) {
	p := NewPack()
	encodeAndBack(t, p, func(p2 *Pack) {
		if len(p2.elems) != 0 {
			t.Errorf("expected empty pack, got %d elements", len(p2.elems))
		}
	})
}

// Reject every truncation: loop over every prefix of a valid message.
func TestRejectTruncatedInt(t *testing.T) {
	p := NewPack()
	p.Add("a", TypeInt, IntValue(1))
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := range data[:len(data)-1] {
		_, err := Decode(data[:i+1])
		if err == nil {
			t.Fatalf("expected error for prefix length %d", i+1)
		}
	}
	// Full data must decode correctly.
	_, err = Decode(data)
	if err != nil {
		t.Fatalf("full decode: %v", err)
	}
}

func TestRejectTruncatedStr(t *testing.T) {
	p := NewPack()
	p.Add("name", TypeStr, StrValue("hello"))
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data)-1; i++ {
		_, err := Decode(data[:i+1])
		if err == nil {
			t.Fatalf("expected error for prefix length %d", i+1)
		}
	}
	_, err = Decode(data)
	if err != nil {
		t.Fatalf("full decode: %v", err)
	}
}

func TestRejectTruncatedData(t *testing.T) {
	p := NewPack()
	p.Add("key", TypeData, DataValue(make([]byte, 100)))
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data)-1; i++ {
		_, err := Decode(data[:i+1])
		if err == nil {
			t.Fatalf("expected error for prefix length %d", i+1)
		}
	}
	_, err = Decode(data)
	if err != nil {
		t.Fatalf("full decode: %v", err)
	}
}

func TestRejectTooManyElements(t *testing.T) {
	p := NewPack()
	for i := 0; i < MaxElementNum+1; i++ {
		p.Add("a", TypeInt, IntValue(0))
	}
	_, err := p.Encode()
	if err != ErrTooManyElements {
		t.Errorf("expected ErrTooManyElements, got %v", err)
	}
}

func TestRejectTooManyValues(t *testing.T) {
	p := NewPack()
	vals := make([]Value, MaxValueNum+1)
	for i := range vals {
		vals[i] = IntValue(0)
	}
	p.AddMulti("x", TypeInt, vals)
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(data)
	if err != ErrTooManyValues {
		t.Errorf("expected ErrTooManyValues, got %v", err)
	}
}

func TestRejectUnknownType(t *testing.T) {
	// Construct bytes with an unknown element type manually.
	b := []byte{
		1, 0, 0, 0, // 1 element
		'x', 0, // name "x" + NUL
		99, 0, 0, 0, // type 99 (unknown)
		1, 0, 0, 0, // 1 value
		0, 0, 0, 0, // INT value 0
	}
	_, err := Decode(b)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestDecodeSubslice(t *testing.T) {
	// Verify parsers return subslices of the input (not copies).
	p := NewPack()
	p.Add("data", TypeData, DataValue([]byte{1, 2, 3}))
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Sandwich between padding so a copy would land outside the intended range.
	full := make([]byte, 4+len(data)+4)
	copy(full[4:], data)
	p2, err := Decode(full[4 : 4+len(data)])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	e := p2.Get("data")
	if e == nil || len(e.Values) == 0 {
		t.Fatal("data not found")
	}
	// The data pointer must be within the full backing array.
	dataPtr := uintptr(unsafe.Pointer(&e.Values[0].Data[0]))
	basePtr := uintptr(unsafe.Pointer(&full[0]))
	endPtr := uintptr(unsafe.Pointer(&full[len(full)-1]))
	if dataPtr < basePtr || dataPtr > endPtr {
		t.Error("Data slice does not point into the input buffer")
	}
}

func BenchmarkEncodeSmall(b *testing.B) {
	p := NewPack()
	p.Add("method", TypeStr, StrValue("login"))
	p.Add("hubname", TypeStr, StrValue("VPN"))
	p.Add("port", TypeInt, IntValue(443))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Encode()
	}
}

func BenchmarkDecodeSmall(b *testing.B) {
	p := NewPack()
	p.Add("method", TypeStr, StrValue("login"))
	p.Add("hubname", TypeStr, StrValue("VPN"))
	p.Add("port", TypeInt, IntValue(443))
	data, _ := p.Encode()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(data)
	}
}

// TestKnownVector tests a known PACK encoding to ensure wire compatibility.
func TestKnownVector(t *testing.T) {
	// A pack with one INT element named "port" with value 443.
	// Wire: [count=1] [name="port\0"] [type=0] [count=1] [value=443]
	p := NewPack()
	p.Add("port", TypeInt, IntValue(443))
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		1, 0, 0, 0, // element count = 1
		'p', 'o', 'r', 't', 0, // name + NUL
		0, 0, 0, 0, // type = INT (0)
		1, 0, 0, 0, // value count = 1
		187, 1, 0, 0, // value = 443 (0x1BB)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("wire mismatch:\ngot  %x\nwant %x", data, want)
	}
}
