//go:build linux

// Package dataplane implements the userspace VPN data path: a TUN device plus
// the ESP encapsulation pump that moves IP packets between the tunnel and the
// network.
package dataplane

import (
	"fmt"
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
//
// The device is held as a raw, blocking file descriptor and read/written with
// direct syscalls rather than an *os.File. A TUN fd registered with Go's runtime
// netpoller returns "not pollable" from a blocking Read on an idle interface
// (the poller cannot deliver readiness for the character device), which would
// kill the data-path read loop. A dedicated goroutine doing blocking reads is
// exactly what the pump wants, so bypassing the poller is both correct and lean.
type TUN struct {
	fd   int
	name string
}

// OpenTUN opens /dev/net/tun and configures a TUN interface. If name is empty
// the kernel picks one (tunN). Requires CAP_NET_ADMIN (run as root, or grant
// the binary the capability with: sudo setcap cap_net_admin+ep ./ikev2d).
func OpenTUN(name string) (*TUN, error) {
	// A raw syscall.Open fd is blocking and is never handed to the netpoller.
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("dataplane: TUNSETIFF: %v (need CAP_NET_ADMIN)", errno)
	}

	// The kernel writes back the assigned name.
	assigned := string(req.Name[:])
	if i := indexZero(req.Name[:]); i >= 0 {
		assigned = string(req.Name[:i])
	}

	return &TUN{fd: fd, name: assigned}, nil
}

// Name returns the interface name (e.g. "tun0").
func (t *TUN) Name() string { return t.name }

// Read reads one IP packet from the tunnel into buf. EINTR (e.g. from Go's
// asynchronous goroutine preemption signal interrupting the blocking read) is
// retried transparently.
func (t *TUN) Read(buf []byte) (int, error) {
	for {
		n, err := syscall.Read(t.fd, buf)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

// Write writes one IP packet to the tunnel.
func (t *TUN) Write(pkt []byte) (int, error) {
	for {
		n, err := syscall.Write(t.fd, pkt)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

// Close closes the device.
func (t *TUN) Close() error { return syscall.Close(t.fd) }

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
