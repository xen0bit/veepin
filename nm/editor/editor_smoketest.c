/*
 * editor_smoketest.c — loads ONE per-protocol editor plugin exactly as
 * NetworkManager does (dlopen + nm_vpn_editor_plugin_factory) and exercises the
 * real code paths: plugin metadata, pre-filling the widget from a connection,
 * and reading the fields back into a fresh connection. Requires a display (GTK).
 *
 *     editor_smoketest <plugin.so> <protocol> [descriptor.name]
 *
 * The Makefile runs it once per protocol. Given the .name descriptor it also
 * checks the descriptor against the plugin — the pairing libnm enforces at load
 * time and the one that silently removes a VPN type from the OS's list when it
 * drifts: libnm refuses any plugin whose reported service differs from the
 * descriptor's service=, and the GUI then just shows nothing.
 *
 * Build+run via ../Makefile `editor-test`. Exits non-zero on any failure.
 */

#include <gtk/gtk.h>
#include <gmodule.h>
#include <NetworkManager.h>
#include <libnm/nm-vpn-editor-plugin.h>
#include <libnm/nm-vpn-editor.h>

#define SERVICE_BASE "org.freedesktop.NetworkManager.veepin"

typedef NMVpnEditorPlugin *(*FactoryFunc)(GError **);

/* A data item to seed and the value to expect after a round-trip. */
typedef struct {
    const char *key, *val;
    gboolean    secret;
} KV;

/* Deep round-trip fixtures. Only the two protocols that carry the most awkward
 * field shapes are covered item by item; every other protocol still gets the
 * metadata, widget and update_connection checks in main(). */
static const KV ikev2_items[] = {
    { "gateway",   "vpn.example.com", FALSE },
    { "local-id",  "client.example",  FALSE },
    { "server-id", "vpn.example.com", FALSE },
    { "psk",       "s3cret",          TRUE  },
};

static const KV wireguard_items[] = {
    { "public-key",    "cGVlcnB1YmxpY2tleQ==",  FALSE },
    { "endpoint",      "vpn.example.com:51820", FALSE },
    { "address",       "10.0.0.2/32",           FALSE },
    { "allowed-ips",   "0.0.0.0/0",             FALSE },
    { "private-key",   "bXlwcml2YXRla2V5",      TRUE  },
    { "preshared-key", "cHJlc2hhcmVka2V5",      TRUE  },
};

/* make_connection builds a VPN connection carrying the given items. */
static NMConnection *
make_connection(const char *service, const char *protocol, const KV *items, int n)
{
    NMConnection *c = nm_simple_connection_new();
    NMSetting    *sc = nm_setting_connection_new();

    g_object_set(sc, NM_SETTING_CONNECTION_ID, "test-veepin",
                 NM_SETTING_CONNECTION_TYPE, "vpn", NULL);
    nm_connection_add_setting(c, sc);

    NMSettingVpn *vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, service, NULL);
    nm_setting_vpn_add_data_item(vpn, "protocol", protocol);
    nm_setting_vpn_add_data_item(vpn, "full-tunnel", "no");
    nm_setting_vpn_add_data_item(vpn, "mtu", "1380");
    for (int i = 0; i < n; i++) {
        if (items[i].secret)
            nm_setting_vpn_add_secret(vpn, items[i].key, items[i].val);
        else
            nm_setting_vpn_add_data_item(vpn, items[i].key, items[i].val);
    }
    nm_connection_add_setting(c, NM_SETTING(vpn));
    return c;
}

/* round_trip pre-fills the editor from a connection carrying the given items,
 * reads it back, and checks every item survived, that the common fields and the
 * protocol key survived, and that no foreign key (`must_be_absent`, a key from
 * another protocol) leaked in. */
static int
round_trip(NMVpnEditorPlugin *plugin, const char *service, const char *protocol,
           const KV *items, int n, const char *must_be_absent)
{
    GError       *err = NULL;
    NMConnection *c = make_connection(service, protocol, items, n);

    NMVpnEditor *editor = nm_vpn_editor_plugin_get_editor(plugin, c, &err);
    if (!editor) {
        g_printerr("FAIL: get_editor (%s): %s\n", protocol, err ? err->message : "?");
        return 1;
    }
    if (nm_vpn_editor_get_widget(editor) == NULL) {
        g_printerr("FAIL: get_widget returned NULL (%s)\n", protocol);
        return 1;
    }

    NMConnection *out = nm_simple_connection_new();
    if (!nm_vpn_editor_update_connection(editor, out, &err)) {
        g_printerr("FAIL: update_connection (%s): %s\n", protocol, err ? err->message : "?");
        return 1;
    }
    NMSettingVpn *o = nm_connection_get_setting_vpn(out);
    if (!o) {
        g_printerr("FAIL: no vpn setting (%s)\n", protocol);
        return 1;
    }

    for (int i = 0; i < n; i++) {
        const char *got = items[i].secret ? nm_setting_vpn_get_secret(o, items[i].key)
                                          : nm_setting_vpn_get_data_item(o, items[i].key);
        if (g_strcmp0(got, items[i].val) != 0) {
            g_printerr("FAIL: %s[%s] = %s, want %s\n", protocol, items[i].key,
                       got ? got : "(null)", items[i].val);
            return 1;
        }
    }

    /* The service type and protocol key the Go service reads back. */
    if (g_strcmp0(nm_setting_vpn_get_service_type(o), service) != 0) {
        g_printerr("FAIL: service-type = %s, want %s\n",
                   nm_setting_vpn_get_service_type(o), service);
        return 1;
    }
    if (g_strcmp0(nm_setting_vpn_get_data_item(o, "protocol"), protocol) != 0) {
        g_printerr("FAIL: protocol not written (%s)\n", protocol);
        return 1;
    }

    /* Common fields. */
    if (g_strcmp0(nm_setting_vpn_get_data_item(o, "full-tunnel"), "no") != 0) {
        g_printerr("FAIL: full-tunnel not round-tripped (%s)\n", protocol);
        return 1;
    }
    if (g_strcmp0(nm_setting_vpn_get_data_item(o, "mtu"), "1380") != 0) {
        g_printerr("FAIL: mtu not round-tripped (%s)\n", protocol);
        return 1;
    }

    /* Saved-secrets: the first secret must be flagged NONE (system-saved) by
     * default, so the root service gets it at Connect without an auth-dialog. */
    for (int i = 0; i < n; i++) {
        if (!items[i].secret)
            continue;
        NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;
        if (!nm_setting_get_secret_flags(NM_SETTING(o), items[i].key, &flags, &err)
            || flags != NM_SETTING_SECRET_FLAG_NONE) {
            g_printerr("FAIL: %s[%s] secret flag = %d, want NONE(0)\n",
                       protocol, items[i].key, flags);
            return 1;
        }
        break;
    }

    if (must_be_absent && nm_setting_vpn_get_data_item(o, must_be_absent) != NULL) {
        g_printerr("FAIL: %s leaked into a %s connection\n", must_be_absent, protocol);
        return 1;
    }
    g_print("  %s round-trip OK\n", protocol);
    return 0;
}

/* check_descriptor verifies the .name file NM reads against the plugin it
 * points at: the service must match (libnm refuses the load otherwise) and the
 * [libnm] plugin= must name this very .so. */
static int
check_descriptor(const char *path, const char *so_path, const char *service)
{
    GError    *err = NULL;
    GKeyFile  *kf = g_key_file_new();
    int        rc = 1;
    char      *got_service = NULL, *got_plugin = NULL, *got_name = NULL;
    char      *so_base = g_path_get_basename(so_path);

    if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &err)) {
        g_printerr("FAIL: reading %s: %s\n", path, err ? err->message : "?");
        goto out;
    }
    got_service = g_key_file_get_string(kf, "VPN Connection", "service", NULL);
    if (g_strcmp0(got_service, service) != 0) {
        g_printerr("FAIL: %s service=%s, but the plugin reports %s "
                   "(libnm would refuse to load it, and the VPN type would vanish "
                   "from the GUI)\n",
                   path, got_service ? got_service : "(unset)", service);
        goto out;
    }
    got_plugin = g_key_file_get_string(kf, "libnm", "plugin", NULL);
    if (g_strcmp0(got_plugin, so_base) != 0) {
        g_printerr("FAIL: %s [libnm] plugin=%s, want %s\n", path,
                   got_plugin ? got_plugin : "(unset)", so_base);
        goto out;
    }
    got_name = g_key_file_get_string(kf, "VPN Connection", "name", NULL);
    if (!got_name || !*got_name) {
        g_printerr("FAIL: %s has no name= (libnm rejects the file)\n", path);
        goto out;
    }
    g_print("  descriptor OK (name=%s)\n", got_name);
    rc = 0;

out:
    g_free(so_base);
    g_free(got_service);
    g_free(got_plugin);
    g_free(got_name);
    g_clear_error(&err);
    g_key_file_free(kf);
    return rc;
}

int
main(int argc, char **argv)
{
    GError *err = NULL;

    if (argc < 3) {
        g_printerr("usage: %s <plugin.so> <protocol> [descriptor.name]\n", argv[0]);
        return 2;
    }

    if (!gtk_init_check(&argc, &argv)) {
        g_printerr("SKIP: no display available for GTK\n");
        return 77; /* automake-style skip */
    }

    const char *path = argv[1];
    const char *protocol = argv[2];
    const char *descriptor = (argc > 3) ? argv[3] : NULL;
    char       *service = g_strdup_printf(SERVICE_BASE ".%s", protocol);

    g_print("%s (%s):\n", g_path_get_basename(path), protocol);

    GModule *mod = g_module_open(path, G_MODULE_BIND_LOCAL);
    if (!mod) {
        g_printerr("FAIL: g_module_open: %s\n", g_module_error());
        return 1;
    }

    gpointer sym = NULL;
    if (!g_module_symbol(mod, "nm_vpn_editor_plugin_factory", &sym) || !sym) {
        g_printerr("FAIL: factory symbol not found\n");
        return 1;
    }

    FactoryFunc        factory = (FactoryFunc) sym;
    NMVpnEditorPlugin *plugin = factory(&err);
    if (!plugin) {
        g_printerr("FAIL: factory returned NULL: %s\n", err ? err->message : "?");
        return 1;
    }

    /* Metadata. The service is what libnm matches against the descriptor, so an
     * exact comparison here is the check that keeps the VPN type visible. */
    char *name = NULL, *got_service = NULL, *desc = NULL;
    g_object_get(plugin, NM_VPN_EDITOR_PLUGIN_NAME, &name,
                 NM_VPN_EDITOR_PLUGIN_DESCRIPTION, &desc,
                 NM_VPN_EDITOR_PLUGIN_SERVICE, &got_service, NULL);
    if (g_strcmp0(got_service, service) != 0) {
        g_printerr("FAIL: service = %s, want %s\n", got_service ? got_service : "(null)", service);
        return 1;
    }
    if (!name || !*name || !desc || !*desc) {
        g_printerr("FAIL: plugin name/description is empty\n");
        return 1;
    }
    g_print("  name=%s service=%s\n", name, got_service);

    if (descriptor && check_descriptor(descriptor, path, service) != 0)
        return 1;

    /* An editor must build with no connection at all — the "Add VPN" path. */
    NMVpnEditor *fresh = nm_vpn_editor_plugin_get_editor(plugin, NULL, &err);
    if (!fresh) {
        g_printerr("FAIL: get_editor (no connection): %s\n", err ? err->message : "?");
        return 1;
    }
    if (nm_vpn_editor_get_widget(fresh) == NULL) {
        g_printerr("FAIL: get_widget returned NULL (no connection)\n");
        return 1;
    }
    /* With every field empty, update_connection must refuse cleanly rather than
     * crash or silently write a connection that cannot dial. Protocols whose
     * fields are all optional may legitimately succeed. */
    NMConnection *empty_out = nm_simple_connection_new();
    g_clear_error(&err);
    if (!nm_vpn_editor_update_connection(fresh, empty_out, &err)
        && !g_error_matches(err, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY)) {
        g_printerr("FAIL: empty update_connection failed with an unexpected error: %s\n",
                   err ? err->message : "?");
        return 1;
    }
    g_clear_error(&err);

    /* Deep round-trip for the protocols that have a fixture. */
    if (g_strcmp0(protocol, "ikev2") == 0) {
        if (round_trip(plugin, service, protocol, ikev2_items,
                       (int) G_N_ELEMENTS(ikev2_items), "public-key") != 0)
            return 1;
    } else if (g_strcmp0(protocol, "wireguard") == 0) {
        if (round_trip(plugin, service, protocol, wireguard_items,
                       (int) G_N_ELEMENTS(wireguard_items), "gateway") != 0)
            return 1;
    }

    g_print("  OK\n");
    g_free(service);
    return 0;
}
