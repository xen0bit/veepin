package anyconnect

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestConnectResponseDoesNotSwallowTunnelData reproduces the condition a slower,
// busier machine produces and a workstation almost never does: the server's
// CONNECT response headers and the first CSTP packets arriving in one TCP
// segment.
//
// Nothing may consume past the header block, because everything after it is the
// tunnel. Handing the response to net/http and closing its Body risks exactly
// that — an HTTP body with no Content-Length reads to EOF, and draining it eats
// the packets — after which the stream is misaligned and the very next read
// fails on bad magic, killing a tunnel that had just come up.
func TestConnectResponseDoesNotSwallowTunnelData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	first := marshal(typeData, []byte("the first packet through the tunnel"))
	second := marshal(typeKeepalive, nil)

	go func() {
		br := bufio.NewReader(server)
		// Consume the client's CONNECT request line and headers.
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		// Reply and immediately append tunnel data, in a single write.
		resp := "HTTP/1.1 200 Connection established\r\n" +
			"X-CSTP-Address: 10.11.0.2\r\n" +
			"X-CSTP-Netmask: 255.255.255.0\r\n" +
			"X-CSTP-MTU: 1400\r\n" +
			"Connection: keep-alive\r\n\r\n"
		out := append([]byte(resp), first...)
		out = append(out, second...)
		_, _ = server.Write(out)
	}()

	c := NewClient(client, newFakeTUN(), ClientConfig{Host: "example", Username: "u", Password: "p"})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	cfg, err := c.connect("cookie")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := cfg.Address.String(); got != "10.11.0.2" {
		t.Fatalf("address = %s, want 10.11.0.2", got)
	}

	// The packets that shared the segment with the headers must still be readable.
	typ, payload, err := readPacket(c.br)
	if err != nil {
		t.Fatalf("first packet after CONNECT was lost: %v", err)
	}
	if typ != typeData || string(payload) != "the first packet through the tunnel" {
		t.Fatalf("first packet = (%#x, %q), want the data packet", typ, payload)
	}
	typ, _, err = readPacket(c.br)
	if err != nil || typ != typeKeepalive {
		t.Fatalf("second packet = (%#x, %v), want the keepalive", typ, err)
	}
}
