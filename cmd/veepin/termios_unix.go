//go:build linux || darwin

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Turning terminal echo off, so that a password typed at a prompt is not left
// on the screen and in the scrollback of whoever is watching.
//
// golang.org/x/term is the obvious answer and is not available: the module
// depends on golang.org/x/{crypto,net,sys} and nothing else, and that contract
// is the reason there are no third-party protocol libraries here either. The
// mechanism x/term uses is two ioctls that x/sys/unix already exposes, so this
// is the same call it would have made.

// echoOff stops the terminal on fd from displaying what is typed, returning the
// function that puts it back exactly as it was.
//
// Only the ECHO bit is touched. x/term additionally forces ICANON and ISIG on,
// defensively; doing that here would mean handing back a terminal in a state it
// was not in, and the restore path already covers the case those flags exist
// for. Canonical mode and signals are on in every terminal that has a shell in
// it, which is the only place this prompt appears.
func echoOff(fd uintptr) (restore func(), err error) {
	t, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios)
	if err != nil {
		// ENOTTY on Linux, and EINVAL is what a BSD returns for the same
		// question, so both mean "this is not a terminal" rather than a failure
		// worth reporting.
		if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EINVAL) {
			return nil, errNotATerminal
		}
		return nil, err
	}
	original := *t
	t.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(fd), ioctlWriteTermios, t); err != nil {
		return nil, err
	}
	// The whole original is written back, not the ECHO bit flipped again: if
	// anything else changed the terminal in between, restoring the state we
	// found is the behaviour that cannot leave it worse than we found it.
	return func() { _ = unix.IoctlSetTermios(int(fd), ioctlWriteTermios, &original) }, nil
}
