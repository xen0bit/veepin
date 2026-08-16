package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/internal/userdb"
)

// runPasswdWith runs the command with stdin fed from in, returning what it
// wrote to stdout. Both handles are package-level state in os, so they are put
// back before returning whatever happened.
func runPasswdWith(t *testing.T, in string) (string, error) {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin, os.Stdout, os.Stderr = stdinR, stdoutW, devNull
	defer func() {
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
		devNull.Close()
	}()

	go func() {
		_, _ = stdinW.WriteString(in)
		stdinW.Close()
	}()
	runErr := runPasswd(nil)
	stdoutW.Close()
	out, _ := io.ReadAll(stdoutR)
	stdinR.Close()
	stdoutR.Close()
	return string(out), runErr
}

// A pipe is a supported way to run this, and the confirmation prompt must not
// break it: a piped password came from something that can be read back, and
// asking for it twice would consume a second line that is not there. This is
// the test that would have caught the confirmation being asked unconditionally.
func TestPasswdAcceptsAPipedPasswordWithoutAskingTwice(t *testing.T) {
	out, err := runPasswdWith(t, "hunter2\n")
	if err != nil {
		t.Fatalf("piped password refused: %v", err)
	}
	hash := strings.TrimSpace(out)
	if !userdb.IsHash(hash) {
		t.Fatalf("output is not a verifier: %q", hash)
	}
	if !userdb.Verify(hash, "hunter2") {
		t.Error("the verifier does not accept the password it was made from")
	}
	if userdb.Verify(hash, "hunter3") {
		t.Error("the verifier accepts a different password")
	}
}

// The line terminator comes off and nothing else does. A password with trailing
// spaces is a password, and hashing something the operator will never type again
// is a login that fails with no explanation anywhere.
func TestPasswdKeepsSpacesAndDropsOnlyTheTerminator(t *testing.T) {
	out, err := runPasswdWith(t, "  spaced  \r\n")
	if err != nil {
		t.Fatal(err)
	}
	if !userdb.Verify(strings.TrimSpace(out), "  spaced  ") {
		t.Error("the spaces around the password were not preserved")
	}
}

// An empty password is refused rather than hashed. A verifier for "" is a
// verifier that an empty login satisfies.
func TestPasswdRefusesAnEmptyPassword(t *testing.T) {
	if _, err := runPasswdWith(t, "\n"); err == nil {
		t.Fatal("an empty password was hashed")
	}
}

// The password is never an argument, whatever else changes. On the command line
// it lands in the process table and the shell history, which is the leak this
// command exists to close.
func TestPasswdRefusesAPasswordOnTheCommandLine(t *testing.T) {
	err := runPasswd([]string{"hunter2"})
	if err == nil {
		t.Fatal("a password given as an argument was accepted")
	}
	if !strings.Contains(err.Error(), "process table") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}
