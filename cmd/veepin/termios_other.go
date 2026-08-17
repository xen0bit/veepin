//go:build !linux && !darwin

package main

import "errors"

// Terminal echo cannot be controlled on this platform; see termios_unix.go for
// what the supported ones do and why x/term is not used.
//
// This is not fatal and must not be: `veepin passwd` is pure computation and
// works anywhere. What changes is that the caller says out loud, before the
// operator types anything, that the password will be visible -- which is the
// same information the missing feature would have carried silently.

// errNoEchoControl is what runPasswd turns into the warning it prints before
// the prompt. It lives here rather than beside errNotATerminal because this is
// the only file that produces it, and a sentinel declared where nothing on the
// build can raise it reads to the linter -- correctly -- as dead.
var errNoEchoControl = errors.New("terminal echo cannot be turned off on this platform")

func echoOff(uintptr) (func(), error) { return nil, errNoEchoControl }
