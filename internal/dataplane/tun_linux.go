//go:build linux

// Package dataplane implements the userspace VPN data path: a TUN device plus
// the ESP encapsulation pump that moves IP packets between the tunnel and the
// network.
package dataplane

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux TUN/TAP ioctl constants (from <linux/if_tun.h> and <linux/if.h>).
const (
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
	cTUNSETIFF = 0x400454ca
	cIFNAMSIZ  = 16
)

// ifReq mirrors struct ifreq for the TUNSETIFF ioctl.
type ifReq struct {
	Name  [cIFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// TUN is an open TUN network device operating in IFF_NO_PI mode, so reads and
// writes are bare IP packets with no 4-byte packet-info prefix.
type TUN struct {
	f    *os.File
	name string
}

// OpenTUN opens /dev/net/tun and configures a TUN interface. If name is empty
// the kernel picks one (tunN). Requires CAP_NET_ADMIN (run as root, or grant
// the binary the capability with: sudo setcap cap_net_admin+ep ./ikev2d).
func OpenTUN(name string) (*TUN, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("dataplane: TUNSETIFF: %v (need CAP_NET_ADMIN)", errno)
	}

	// The kernel writes back the assigned name.
	assigned := string(req.Name[:])
	if i := indexZero(req.Name[:]); i >= 0 {
		assigned = string(req.Name[:i])
	}

	return &TUN{f: f, name: assigned}, nil
}

// Name returns the interface name (e.g. "tun0").
func (t *TUN) Name() string { return t.name }

// Read reads one IP packet from the tunnel into buf.
func (t *TUN) Read(buf []byte) (int, error) { return t.f.Read(buf) }

// Write writes one IP packet to the tunnel.
func (t *TUN) Write(pkt []byte) (int, error) { return t.f.Write(pkt) }

// Close closes the device.
func (t *TUN) Close() error { return t.f.Close() }

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
