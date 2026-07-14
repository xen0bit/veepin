package ike

import (
	"net"
)

// nonESPMarker is the 4-octet zero prefix that distinguishes an IKE message
// from an ESP packet on the NAT-T port 4500 (RFC 3948 section 2.2). ESP packets
// begin with a non-zero SPI, so a zero prefix means "this is IKE".
var nonESPMarker = []byte{0, 0, 0, 0}

// espSocketHandler is called for ESP datagrams received on port 4500 (after the
// non-ESP marker check). The bytes are the raw ESP packet (SPI first).
type espSocketHandler func(esp []byte, from *net.UDPAddr)

// transport owns the two UDP sockets an IKEv2/NAT-T responder needs: port 500
// for the initial exchange and port 4500 for post-NAT-detection traffic and
// UDP-encapsulated ESP.
type transport struct {
	conn500  *net.UDPConn
	conn4500 *net.UDPConn
	onESP    espSocketHandler
}

// sendIKE transmits an IKE message to a peer. When the peer is on port 4500 the
// non-ESP marker is prepended.
func (t *transport) sendIKE(pkt []byte, to *net.UDPAddr, on4500 bool) error {
	if on4500 {
		framed := make([]byte, 0, len(nonESPMarker)+len(pkt))
		framed = append(framed, nonESPMarker...)
		framed = append(framed, pkt...)
		_, err := t.conn4500.WriteToUDP(framed, to)
		return err
	}
	_, err := t.conn500.WriteToUDP(pkt, to)
	return err
}

// sendESP transmits an encapsulated ESP datagram. With NAT-T (udpEncap) the ESP
// bytes go out on port 4500 as-is (a non-zero SPI is its own marker). Without
// NAT-T there is no raw-IP ESP path in this userspace build, so ESP is always
// UDP-encapsulated on 4500 when a tunnel is up.
func (t *transport) sendESP(esp []byte, to *net.UDPAddr) error {
	_, err := t.conn4500.WriteToUDP(esp, to)
	return err
}

// serve runs the read loops for both sockets, dispatching IKE messages to
// handleIKE and ESP datagrams to the ESP handler. It returns when both sockets
// are closed.
func (t *transport) serve(handleIKE func(pkt []byte, from *net.UDPAddr, on4500 bool), closing func() bool) {
	done := make(chan struct{}, 2)

	// Port 500: only IKE, no marker.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := t.conn500.ReadFromUDP(buf)
			if err != nil {
				if closing() {
					done <- struct{}{}
					return
				}
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			handleIKE(pkt, from, false)
		}
	}()

	// Port 4500: non-ESP marker => IKE; otherwise ESP.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := t.conn4500.ReadFromUDP(buf)
			if err != nil {
				if closing() {
					done <- struct{}{}
					return
				}
				continue
			}
			if n >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 {
				// Non-ESP marker: the rest is an IKE message.
				pkt := make([]byte, n-4)
				copy(pkt, buf[4:n])
				handleIKE(pkt, from, true)
				continue
			}
			// ESP datagram (non-zero SPI).
			if t.onESP != nil {
				esp := make([]byte, n)
				copy(esp, buf[:n])
				t.onESP(esp, from)
			}
		}
	}()

	<-done
	<-done
}

func (t *transport) close() {
	if t.conn500 != nil {
		t.conn500.Close()
	}
	if t.conn4500 != nil {
		t.conn4500.Close()
	}
}
