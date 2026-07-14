package dataplane

import (
	"net"
	"testing"
)

func TestAddrPoolAllocateRelease(t *testing.T) {
	pool, gw, err := NewAddrPool("10.10.10.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !gw.Equal(net.ParseIP("10.10.10.1")) {
		t.Fatalf("gateway = %v, want 10.10.10.1", gw)
	}
	// First client address should be .2.
	ip1, err := pool.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if !ip1.Equal(net.ParseIP("10.10.10.2")) {
		t.Fatalf("first alloc = %v, want 10.10.10.2", ip1)
	}
	ip2, _ := pool.Allocate()
	if ip2.Equal(ip1) {
		t.Fatal("pool handed out a duplicate")
	}
	// Release ip1 and confirm it can be reused.
	pool.Release(ip1)
	got, _ := pool.Allocate()
	if !got.Equal(ip1) {
		t.Fatalf("released address not reused: got %v", got)
	}
}

func TestAddrPoolExhaustion(t *testing.T) {
	// /30 has 4 addresses: network, .1 gateway, .2 client, broadcast => 1 usable.
	pool, _, err := NewAddrPool("192.168.5.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Allocate(); err != nil {
		t.Fatalf("first allocation should succeed: %v", err)
	}
	if _, err := pool.Allocate(); err == nil {
		t.Fatal("expected exhaustion on a /30 pool")
	}
}

func TestAddrPoolNetmask(t *testing.T) {
	pool, _, err := NewAddrPool("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	nm := pool.Netmask()
	if nm[0] != 255 || nm[1] != 255 || nm[2] != 255 || nm[3] != 0 {
		t.Fatalf("netmask = %v, want 255.255.255.0", nm)
	}
}
