package dbusplugin

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5/introspect"
)

var errAlreadyConnected = errors.New("a VPN connection is already active")

// errNoSecretsPending refuses a NewSecrets that answers no question. NM only
// calls it after SecretsRequired, so an unsolicited one is either a bug or
// another client on the bus trying to start a tunnel through a method that
// looks like it only updates one.
var errNoSecretsPending = errors.New("no secrets were requested")

type nameTakenError struct{ name string }

func (e *nameTakenError) Error() string {
	return fmt.Sprintf("D-Bus name %s already owned (is another instance running?)", e.name)
}

// pluginIntrospect describes the VPN.Plugin interface for `busctl introspect`
// and any NM-side introspection. The signatures match nm-vpn-dbus-interface.h.
func pluginIntrospect() introspect.Interface {
	return introspect.Interface{
		Name: Iface,
		Methods: []introspect.Method{
			{Name: "Connect", Args: []introspect.Arg{
				{Name: "connection", Type: "a{sa{sv}}", Direction: "in"},
			}},
			{Name: "ConnectInteractive", Args: []introspect.Arg{
				{Name: "connection", Type: "a{sa{sv}}", Direction: "in"},
				{Name: "details", Type: "a{sv}", Direction: "in"},
			}},
			{Name: "NeedSecrets", Args: []introspect.Arg{
				{Name: "settings", Type: "a{sa{sv}}", Direction: "in"},
				{Name: "setting_name", Type: "s", Direction: "out"},
			}},
			{Name: "NewSecrets", Args: []introspect.Arg{
				{Name: "connection", Type: "a{sa{sv}}", Direction: "in"},
			}},
			{Name: "Disconnect"},
		},
		Signals: []introspect.Signal{
			{Name: "StateChanged", Args: []introspect.Arg{{Name: "state", Type: "u"}}},
			{Name: "Config", Args: []introspect.Arg{{Name: "config", Type: "a{sv}"}}},
			{Name: "Ip4Config", Args: []introspect.Arg{{Name: "ip4config", Type: "a{sv}"}}},
			{Name: "Ip6Config", Args: []introspect.Arg{{Name: "ip6config", Type: "a{sv}"}}},
			{Name: "SecretsRequired", Args: []introspect.Arg{
				{Name: "message", Type: "s"}, {Name: "secrets", Type: "as"},
			}},
			{Name: "Failure", Args: []introspect.Arg{{Name: "reason", Type: "u"}}},
		},
		Properties: []introspect.Property{
			{Name: "State", Type: "u", Access: "read"},
		},
	}
}
