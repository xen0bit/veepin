package dbusplugin

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/veepin/nm/internal/nmconfig"

	// The file-path options come from the protocol's registered OptSpecs.
	_ "github.com/xen0bit/veepin/wireguard"
)

// TestAPrivateConnectionCannotNameAFileItsOwnerCannotRead: the service opens
// file options as root. If this fails, a user's private connection can point
// at a root-only key and bring up a tunnel authenticated as the machine.
func TestAPrivateConnectionCannotNameAFileItsOwnerCannotRead(t *testing.T) {
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skip("no nobody user")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if me.Username == "nobody" {
		t.Skip("running as nobody")
	}
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := nmconfig.Connection{Protocol: "wireguard", Options: map[string]string{"config": path}}
	private := func(owner string) nmconfig.Settings {
		return nmconfig.Settings{"connection": {"permissions": dbus.MakeVariant([]string{"user:" + owner + ":"})}}
	}

	if err := checkFileAccess(private(me.Username), conn); err != nil {
		t.Errorf("the owner's own file was refused: %v", err)
	}
	if err := checkFileAccess(private("nobody"), conn); err == nil {
		t.Error("a private connection named a file its owner cannot read")
	}
	if err := checkFileAccess(nmconfig.Settings{}, conn); err != nil {
		t.Errorf("a system connection was checked: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkFileAccess(private("nobody"), conn); err != nil {
		t.Errorf("a world-readable file was refused: %v", err)
	}
}
