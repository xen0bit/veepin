package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xen0bit/veepin/internal/userdb"
)

// errNotATerminal reports that stdin is a pipe or a file rather than a terminal.
// It is not a failure: `echo hunter2 | veepin passwd` is a supported way to run
// this, and there is no echo to turn off.
var errNotATerminal = errors.New("not a terminal")

// runPasswd prints a bcrypt verifier for a password, in the form a users-file
// holds. It exists so the feature is self-contained: a credentials file that
// can hold a hash is no use to an operator with no way to produce one, and
// "install apache2-utils and run htpasswd -B" is a poor answer for a binary
// with no runtime dependencies.
//
// The output is the same $2a$ string htpasswd -B emits, deliberately: the
// format is not veepin's, and an operator who already has a hash from
// somewhere else should be able to paste it in.
//
// The password is read from the terminal rather than taken as an argument.
// Taking it as an argument would put it in the process table and the shell
// history, which is the whole of item 7 — and a tool whose purpose is to keep
// the password off disk should not be the thing that leaks it. For the same
// reason the terminal's echo is turned off while it is typed: a command that
// exists to keep a secret out of `ps` and out of `~/.bash_history`, and then
// prints it into the scrollback of a shared screen, has moved the leak rather
// than closed it.
func runPasswd(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: veepin passwd  (the password is read from stdin, not the command line, " +
			"so it does not land in the process table or the shell history)")
	}

	restore, err := echoOff(os.Stdin.Fd())
	interactive := err == nil
	switch {
	case interactive:
		defer restore()
		// A Ctrl-C at the prompt must not leave a terminal that no longer shows
		// what is typed -- the operator's next command is then invisible and the
		// fix is `stty sane`, which is not something they should have to know.
		// The handler restores and exits rather than returning, because a signal
		// during a blocking read has no return path to run a defer on.
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sig)
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-sig:
				restore()
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			case <-done:
			}
		}()
	case errors.Is(err, errNotATerminal):
		// Piped in. Nothing is displayed, so there is nothing to suppress.
	default:
		// Said BEFORE the prompt, so the operator can stop and pipe it in
		// instead. A warning printed afterwards would arrive once the password
		// was already on the screen, which is the moment it stops being useful.
		fmt.Fprintf(os.Stderr, "warning: %v; the password will be visible as you type "+
			"(pipe it in instead: echo <password> | veepin passwd)\n", err)
	}

	in := bufio.NewReader(os.Stdin)
	password, err := readLine(in, "password: ", interactive)
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("passwd: the password is empty")
	}

	// Confirmed only when it was typed, and for the reason the confirmation
	// exists: with echo off there is nothing on the screen to check a typo
	// against, and a mistyped verifier is not a visible error -- it is a login
	// that never succeeds, discovered later by the person who cannot get in.
	// A piped password came from something that can be read back, so asking
	// twice there would only break the pipe.
	if interactive {
		again, err := readLine(in, "password (again): ", interactive)
		if err != nil {
			return err
		}
		if again != password {
			return fmt.Errorf("passwd: the two entries do not match")
		}
	}

	hash, err := userdb.Hash(password)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}

// readLine writes a prompt to stderr and reads one line from in. echoSuppressed
// says whether the terminal is showing what is typed.
//
// The prompt goes to stderr so that `veepin passwd > users-line` captures the
// verifier alone. The trailing newline is printed only when echo is off: the
// Return the operator pressed then produced no visible line break, and without
// this the next prompt lands on the same line as the last. Printing it in the
// echoing case instead leaves a blank line under every prompt.
func readLine(in *bufio.Reader, prompt string, echoSuppressed bool) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := in.ReadString('\n')
	if echoSuppressed {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil && line == "" {
		return "", fmt.Errorf("passwd: reading the password: %w", err)
	}
	// Only the line terminator comes off. A password with leading or trailing
	// spaces is a password, and trimming it here would hash something the user
	// will never type again.
	return strings.TrimRight(line, "\r\n"), nil
}
