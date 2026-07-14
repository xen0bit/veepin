//go:build !linux

package dataplane

import (
	"fmt"
	"runtime"
)

// TUN is not supported on this platform; the Linux implementation uses the
// kernel TUN driver directly. On other platforms OpenTUN returns an error.
type TUN struct{}

// OpenTUN is unsupported off Linux.
func OpenTUN(name string) (*TUN, error) {
	return nil, fmt.Errorf("dataplane: TUN device not supported on %s (Linux only)", runtime.GOOS)
}

// Name is unsupported off Linux.
func (t *TUN) Name() string { return "" }

// Read is unsupported off Linux.
func (t *TUN) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("dataplane: TUN not supported on this platform")
}

// Write is unsupported off Linux.
func (t *TUN) Write(pkt []byte) (int, error) {
	return 0, fmt.Errorf("dataplane: TUN not supported on this platform")
}

// Close is unsupported off Linux.
func (t *TUN) Close() error { return nil }
