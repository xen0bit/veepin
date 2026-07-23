package ike

import (
	"context"
	"io"
	"log"
	"testing"
	"time"
)

// pumpInbox mimics the data-path read loop: it reads IKE datagrams off the
// client's socket, strips the NAT-T non-ESP marker, and delivers them to the
// client's control channel. It runs until the socket is closed.
func pumpInbox(c *Client) {
	conn := c.DataConn()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
			if len(pkt) > 4 {
				msg := make([]byte, len(pkt)-4)
				copy(msg, pkt[4:])
				c.Deliver(msg)
			}
			continue
		}
	}
}

// TestClientDPD is the liveness proof: a connected, attached client runs a
// dead-peer-detection exchange that the live server answers, and SendDPD
// returns nil and advances the message-ID window.
func TestClientDPD(t *testing.T) {
	p500, p4500, srv, _ := mobikeServer(t)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("mobike-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	if _, err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	client.Attach()
	go pumpInbox(client)

	before := client.sendMsgID
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.SendDPD(ctx); err != nil {
		t.Fatalf("DPD against a live server failed: %v", err)
	}
	if client.sendMsgID != before+1 {
		t.Fatalf("DPD did not advance message ID: got %d, want %d", client.sendMsgID, before+1)
	}

	// A second probe must also succeed (message-ID window keeps advancing).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if err := client.SendDPD(ctx2); err != nil {
		t.Fatalf("second DPD failed: %v", err)
	}
}

// TestClientDPDTimesOutOnDeadPeer confirms SendDPD returns an error (rather than
// hanging) when the peer never answers — the signal the liveness monitor turns
// into a teardown.
func TestClientDPDTimesOutOnDeadPeer(t *testing.T) {
	p500, p4500, srv, _ := mobikeServer(t)

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("mobike-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	if _, err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	client.Attach()
	go pumpInbox(client)

	// Kill the server: no response will come.
	srv.Close()
	// Give the listener a moment to actually stop.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := client.SendDPD(ctx); err == nil {
		t.Fatal("DPD against a dead peer should have failed")
	}
}

// TestSendDPDRequiresAttach confirms the exchange refuses to run before Attach.
func TestSendDPDRequiresAttach(t *testing.T) {
	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: 500,
		PSK:     []byte("x"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.SendDPD(ctx); err == nil {
		t.Fatal("SendDPD should fail before Attach")
	}
}
