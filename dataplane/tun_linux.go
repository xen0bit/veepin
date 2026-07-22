//go:build linux

// Package dataplane implements the userspace VPN data path: a TUN device plus
// the ESP encapsulation pump that moves IP packets between the tunnel and the
// network.
package dataplane

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux TUN/TAP ioctl constants (from <linux/if_tun.h> and <linux/if.h>).
const (
	cIFF_TUN         = 0x0001
	cIFF_NO_PI       = 0x1000
	cIFF_VNET_HDR    = 0x4000
	cTUNSETIFF       = 0x400454ca
	cTUNSETOFFLOAD   = 0x400454d0
	cTUNSETVNETHDRSZ = 0x400454d8
	cIFNAMSIZ        = 16
	cTUN_F_CSUM      = 0x01
	cTUN_F_TSO4      = 0x02
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
	// vnet is true when the device was opened with IFF_VNET_HDR: every read
	// carries a 10-byte virtio-net header (and may be a GSO super-frame), and
	// every write must carry one. Only the pump's vnet-aware loop drives a TUN
	// in this mode.
	vnet bool
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

// OpenTUNGSO opens a TUN like OpenTUN, but negotiates the virtio-net header
// path (IFF_VNET_HDR) with TCP segmentation offload (TUN_F_CSUM|TUN_F_TSO4):
// the kernel's local stack may then hand one read a TCP super-frame of up to
// 64 KB in place of dozens of MTU-sized packets, which the pump cuts into
// wire-sized segments itself (offload_linux.go) and flushes with one batched
// send.
//
// A kernel that refuses any of the ioctls gets the plain device instead —
// same contract as OpenTUN, and GSO reports which case is in effect. Only
// dataplane.Pump knows how to drive a GSO device; a protocol with its own TUN
// loop must keep OpenTUN.
func OpenTUNGSO(name string) (*TUN, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI | cIFF_VNET_HDR

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		// No vnet-header support at all: fall back to the plain device.
		_ = syscall.Close(fd)
		return OpenTUN(name)
	}

	vnetHdrSz := int32(virtioNetHdrLen)
	_, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&vnetHdrSz)))
	offloads := uintptr(cTUN_F_CSUM | cTUN_F_TSO4)
	_, _, e2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETOFFLOAD), offloads)
	if e1 != 0 || e2 != 0 {
		// Header without offloads would be all cost and no batching: reopen
		// plain rather than pay 10 bytes per packet for nothing.
		_ = syscall.Close(fd)
		return OpenTUN(name)
	}

	assigned := string(req.Name[:])
	if i := indexZero(req.Name[:]); i >= 0 {
		assigned = string(req.Name[:i])
	}
	return &TUN{fd: fd, name: assigned, vnet: true}, nil
}

// Name returns the interface name (e.g. "tun0").
func (t *TUN) Name() string { return t.name }

// GSO reports whether the device is in virtio-net-header mode, in which case
// reads and writes carry the 10-byte header and reads may be GSO super-frames.
// Nil-safe, because tests hand pumps a nil *TUN they never run.
func (t *TUN) GSO() bool { return t != nil && t.vnet }

// zeroVnetHdr is the header a plain (non-GSO, checksums-complete) packet
// written to a vnet TUN carries: all fields zero.
var zeroVnetHdr [virtioNetHdrLen]byte

// writeVnet writes one IP packet to a vnet-mode tunnel, prepending the zero
// virtio-net header with writev so the packet is not copied.
func (t *TUN) writeVnet(pkt []byte) (int, error) {
	for {
		n, err := unix.Writev(t.fd, [][]byte{zeroVnetHdr[:], pkt})
		if err == unix.EINTR {
			continue
		}
		if n >= virtioNetHdrLen {
			n -= virtioNetHdrLen
		}
		return n, err
	}
}

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
