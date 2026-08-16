package main

import "golang.org/x/sys/unix"

// The BSD spelling of the same pair; see the Linux file for why this is a
// compile-time split.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
