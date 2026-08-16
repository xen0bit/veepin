package main

import "golang.org/x/sys/unix"

// The termios get/set pair, which x/sys/unix spells differently per platform:
// Linux's are TCGETS/TCSETS. Named here rather than switched on at run time
// because the constants do not exist on the other platform's build, so this has
// to be a compile-time split whatever it looks like.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
