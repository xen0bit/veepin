//go:build linux

package dataplane

// The GSO egress loop: doc/scaling-the-data-path.md's "TUN half".
//
// On a vnet TUN every read carries a virtio-net header and may be a TCP
// super-frame standing in for dozens of wire-sized packets. This loop cuts a
// super-frame into segments (offload_linux.go), routes once — every segment
// shares the inner destination — encapsulates each, and flushes the burst
// through the pump's batch sender (one sendmmsg) when the protocol registered
// one. That is the moment the two batching halves meet: one TUN read becomes
// one UDP syscall, instead of N reads and N sends.

// runVnet is Run for a GSO device. It blocks until the TUN is closed.
func (p *Pump) runVnet() {
	buf := make([]byte, virtioNetHdrLen+65535)
	var segs [][]byte             // segment scratch, reused across super-frames
	outs := make([][]byte, 0, 64) // encapsulated burst awaiting flush
	for {
		n, err := p.tun.Read(buf)
		if err != nil {
			p.mu.RLock()
			closing := p.closing
			p.mu.RUnlock()
			if closing {
				return
			}
			if p.log != nil {
				p.log.Printf("dataplane: TUN read error: %v", err)
			}
			return
		}
		if n < virtioNetHdrLen {
			continue
		}
		hdr := parseVirtioNetHdr(buf[:virtioNetHdrLen])
		pkt := buf[virtioNetHdrLen:n]

		switch hdr.gsoType {
		case vnetGSONone:
			// One ordinary packet — but TUN_F_CSUM means its transport
			// checksum may be partial, left for "the device" to finish.
			if hdr.flags&vnetFlagNeedsCsum != 0 {
				completePartialChecksum(pkt, int(hdr.csumStart), int(hdr.csumOffset))
			}
			p.routeOutbound(pkt)
		case vnetGSOTCPv4:
			nseg, err := segmentTSO4(pkt, hdr, &segs)
			if err != nil {
				if p.log != nil {
					p.log.Printf("dataplane: dropping TSO super-frame: %v", err)
				}
				continue
			}
			outs = p.sendSegments(segs[:nseg], outs)
		default:
			// Not negotiated in TUNSETOFFLOAD (TSO6, USO, ECN), so the kernel
			// should never send it; drop rather than corrupt.
			if p.log != nil {
				p.log.Printf("dataplane: dropping unnegotiated GSO type %#x", hdr.gsoType)
			}
		}
	}
}

// sendSegments routes one super-frame's segments — one lookup, they share a
// destination — encapsulates each, and flushes the burst: one batched send
// when the transport has one, per-packet sends otherwise. It returns outs
// reset to length zero so the caller keeps the burst's capacity.
func (p *Pump) sendSegments(segs [][]byte, outs [][]byte) [][]byte {
	dst, ok := ipv4Dest(segs[0])
	if !ok {
		return outs[:0]
	}
	p.mu.RLock()
	t := p.routes.lookup(dst)
	p.mu.RUnlock()
	if t == nil {
		return outs[:0] // no tunnel carries this destination
	}

	// The kernel sizes segments to the interface MTU, but path MTU discovery
	// may have learned a smaller inner MTU. One fragmentation-needed answers
	// the whole super-frame — every segment is the same flow.
	if mtu := p.innerMTU(); mtu > 0 && NeedsFragmentation(segs[0], mtu) {
		if reply := FragNeeded(segs[0], mtu); reply != nil {
			if _, err := p.writeTUN(reply); err != nil && p.log != nil {
				p.log.Printf("dataplane: writing ICMP frag-needed: %v", err)
			}
		}
		return outs[:0]
	}

	outs = outs[:0]
	for _, seg := range segs {
		// Encapsulate returns a freshly owned buffer (the data paths' one
		// seal allocation), so the burst can hold every output at once.
		out, err := t.Encapsulate(seg)
		if err != nil {
			if p.log != nil {
				p.log.Printf("dataplane: encap failed: %v", err)
			}
			continue
		}
		outs = append(outs, out)
	}
	if len(outs) == 0 {
		return outs[:0]
	}
	if p.batchSend != nil {
		p.batchSend(outs, t.PeerAddr())
		return outs[:0]
	}
	for _, out := range outs {
		p.send(out, t.PeerAddr())
	}
	return outs[:0]
}
