/*
 * editor_smoketest.c — loads the editor plugin exactly as NetworkManager does
 * (dlopen + nm_vpn_editor_plugin_factory) and exercises the real code paths:
 * plugin metadata, pre-filling the widget from a connection, and reading the
 * fields back into a fresh connection. Requires a display (GTK).
 *
 * Build+run via ../Makefile `editor-test`. Exits non-zero on any failure.
 */

#include <gtk/gtk.h>
#include <gmodule.h>
#include <NetworkManager.h>
#include <libnm/nm-vpn-editor-plugin.h>
#include <libnm/nm-vpn-editor.h>

#define SERVICE "org.freedesktop.NetworkManager.veepin"

typedef NMVpnEditorPlugin *(*FactoryFunc)(GError **);

static NMConnection *
make_source_connection(void)
{
    NMConnection *c = nm_simple_connection_new();
    NMSetting *sc = nm_setting_connection_new();
    g_object_set(sc, NM_SETTING_CONNECTION_ID, "test-veepin",
                 NM_SETTING_CONNECTION_TYPE, "vpn", NULL);
    nm_connection_add_setting(c, sc);

    NMSettingVpn *vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, SERVICE, NULL);
    nm_setting_vpn_add_data_item(vpn, "gateway", "vpn.example.com");
    nm_setting_vpn_add_data_item(vpn, "local-id", "client.example");
    nm_setting_vpn_add_data_item(vpn, "server-id", "vpn.example.com");
    nm_setting_vpn_add_data_item(vpn, "full-tunnel", "no");
    nm_setting_vpn_add_data_item(vpn, "mtu", "1380");
    nm_setting_vpn_add_secret(vpn, "psk", "s3cret");
    nm_connection_add_setting(c, NM_SETTING(vpn));
    return c;
}

static NMConnection *
make_wireguard_connection(void)
{
    NMConnection *c = nm_simple_connection_new();
    NMSetting *sc = nm_setting_connection_new();
    g_object_set(sc, NM_SETTING_CONNECTION_ID, "test-veepin-wg",
                 NM_SETTING_CONNECTION_TYPE, "vpn", NULL);
    nm_connection_add_setting(c, sc);

    NMSettingVpn *vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, SERVICE, NULL);
    nm_setting_vpn_add_data_item(vpn, "protocol", "wireguard");
    nm_setting_vpn_add_data_item(vpn, "public-key", "cGVlcnB1YmxpY2tleQ==");
    nm_setting_vpn_add_data_item(vpn, "endpoint", "vpn.example.com:51820");
    nm_setting_vpn_add_data_item(vpn, "address", "10.0.0.2/32");
    nm_setting_vpn_add_data_item(vpn, "allowed-ips", "0.0.0.0/0");
    nm_setting_vpn_add_secret(vpn, "private-key", "bXlwcml2YXRla2V5");
    nm_setting_vpn_add_secret(vpn, "preshared-key", "cHJlc2hhcmVka2V5");
    nm_connection_add_setting(c, NM_SETTING(vpn));
    return c;
}

/* A data item to seed and the value to expect after a round-trip. */
typedef struct {
    const char *key;
    const char *val;
    gboolean    secret;
} KV;

/* round_trip pre-fills the editor from a connection carrying `protocol` plus the
 * given data/secret items, reads it back, and checks every item survived and no
 * foreign key (`must_be_absent`, e.g. a key from another protocol) leaked in. */
static int
round_trip(NMVpnEditorPlugin *plugin, const char *protocol, const KV *items, int n,
           const char *must_be_absent)
{
    GError *err = NULL;
    NMConnection *c = nm_simple_connection_new();
    NMSetting *sc = nm_setting_connection_new();
    g_object_set(sc, NM_SETTING_CONNECTION_ID, "test", NM_SETTING_CONNECTION_TYPE, "vpn", NULL);
    nm_connection_add_setting(c, sc);

    NMSettingVpn *vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, SERVICE, NULL);
    nm_setting_vpn_add_data_item(vpn, "protocol", protocol);
    for (int i = 0; i < n; i++) {
        if (items[i].secret)
            nm_setting_vpn_add_secret(vpn, items[i].key, items[i].val);
        else
            nm_setting_vpn_add_data_item(vpn, items[i].key, items[i].val);
    }
    nm_connection_add_setting(c, NM_SETTING(vpn));

    NMVpnEditor *editor = nm_vpn_editor_plugin_get_editor(plugin, c, &err);
    if (!editor) {
        g_printerr("FAIL: get_editor (%s): %s\n", protocol, err ? err->message : "?");
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
    if (g_strcmp0(nm_setting_vpn_get_data_item(o, "protocol"), protocol) != 0) {
        g_printerr("FAIL: protocol not preserved (%s)\n", protocol);
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
    if (must_be_absent && nm_setting_vpn_get_data_item(o, must_be_absent) != NULL) {
        g_printerr("FAIL: %s leaked into a %s connection\n", must_be_absent, protocol);
        return 1;
    }
    g_print("%s round-trip OK\n", protocol);
    return 0;
}

int
main(int argc, char **argv)
{
    GError *err = NULL;

    if (!gtk_init_check(&argc, &argv)) {
        g_printerr("SKIP: no display available for GTK\n");
        return 77; /* automake-style skip */
    }

    const char *path = (argc > 1) ? argv[1] : "./libnm-vpn-plugin-veepin.so";
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

    FactoryFunc factory = (FactoryFunc) sym;
    NMVpnEditorPlugin *plugin = factory(&err);
    if (!plugin) {
        g_printerr("FAIL: factory returned NULL: %s\n", err ? err->message : "?");
        return 1;
    }

    char *name = NULL, *service = NULL;
    g_object_get(plugin, NM_VPN_EDITOR_PLUGIN_NAME, &name,
                 NM_VPN_EDITOR_PLUGIN_SERVICE, &service, NULL);
    if (g_strcmp0(service, SERVICE) != 0) {
        g_printerr("FAIL: service = %s, want %s\n", service, SERVICE);
        return 1;
    }
    g_print("plugin name=%s service=%s\n", name, service);

    /* Pre-fill the editor from a connection, then read it back. */
    NMConnection *src = make_source_connection();
    NMVpnEditor *editor = nm_vpn_editor_plugin_get_editor(plugin, src, &err);
    if (!editor) {
        g_printerr("FAIL: get_editor: %s\n", err ? err->message : "?");
        return 1;
    }
    if (nm_vpn_editor_get_widget(editor) == NULL) {
        g_printerr("FAIL: get_widget returned NULL\n");
        return 1;
    }

    NMConnection *out = nm_simple_connection_new();
    if (!nm_vpn_editor_update_connection(editor, out, &err)) {
        g_printerr("FAIL: update_connection: %s\n", err ? err->message : "?");
        return 1;
    }

    NMSettingVpn *ovpn = nm_connection_get_setting_vpn(out);
    if (!ovpn) {
        g_printerr("FAIL: no vpn setting after update_connection\n");
        return 1;
    }
#define CHECK_DATA(k, want)                                                            \
    do {                                                                              \
        const char *got = nm_setting_vpn_get_data_item(ovpn, k);                      \
        if (g_strcmp0(got, want) != 0) {                                              \
            g_printerr("FAIL: data[%s] = %s, want %s\n", k, got ? got : "(null)", want); \
            return 1;                                                                 \
        }                                                                             \
    } while (0)
    CHECK_DATA("gateway", "vpn.example.com");
    CHECK_DATA("local-id", "client.example");
    CHECK_DATA("server-id", "vpn.example.com");
    CHECK_DATA("full-tunnel", "no");
    CHECK_DATA("mtu", "1380");
    if (g_strcmp0(nm_setting_vpn_get_secret(ovpn, "psk"), "s3cret") != 0) {
        g_printerr("FAIL: psk secret not round-tripped\n");
        return 1;
    }
    /* Saved-secrets: the PSK must be flagged NONE (system-saved) by default so
     * the root service gets it at Connect without an auth-dialog. */
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;
    if (!nm_setting_get_secret_flags(NM_SETTING(ovpn), "psk", &flags, &err)
        || flags != NM_SETTING_SECRET_FLAG_NONE) {
        g_printerr("FAIL: psk secret flag = %d, want NONE(0)\n", flags);
        return 1;
    }
    if (g_strcmp0(nm_setting_vpn_get_service_type(ovpn), SERVICE) != 0) {
        g_printerr("FAIL: service-type = %s\n", nm_setting_vpn_get_service_type(ovpn));
        return 1;
    }

    /* Protocol defaults to ikev2 when the key is absent. */
    CHECK_DATA("protocol", "ikev2");

    /* WireGuard round-trip: pre-fill a wireguard connection, read it back, and
     * confirm the wireguard data/secrets survive and the protocol is preserved. */
    NMConnection *wgsrc = make_wireguard_connection();
    NMVpnEditor *wgeditor = nm_vpn_editor_plugin_get_editor(plugin, wgsrc, &err);
    if (!wgeditor) {
        g_printerr("FAIL: get_editor (wireguard): %s\n", err ? err->message : "?");
        return 1;
    }
    NMConnection *wgout = nm_simple_connection_new();
    if (!nm_vpn_editor_update_connection(wgeditor, wgout, &err)) {
        g_printerr("FAIL: update_connection (wireguard): %s\n", err ? err->message : "?");
        return 1;
    }
    NMSettingVpn *wgvpn = nm_connection_get_setting_vpn(wgout);
    if (!wgvpn) {
        g_printerr("FAIL: no vpn setting after wireguard update\n");
        return 1;
    }
#define CHECK_WG_DATA(k, want)                                                            \
    do {                                                                                 \
        const char *got = nm_setting_vpn_get_data_item(wgvpn, k);                        \
        if (g_strcmp0(got, want) != 0) {                                                 \
            g_printerr("FAIL: wg data[%s] = %s, want %s\n", k, got ? got : "(null)", want); \
            return 1;                                                                    \
        }                                                                                \
    } while (0)
    CHECK_WG_DATA("protocol", "wireguard");
    CHECK_WG_DATA("public-key", "cGVlcnB1YmxpY2tleQ==");
    CHECK_WG_DATA("endpoint", "vpn.example.com:51820");
    CHECK_WG_DATA("address", "10.0.0.2/32");
    CHECK_WG_DATA("allowed-ips", "0.0.0.0/0");
    if (g_strcmp0(nm_setting_vpn_get_secret(wgvpn, "private-key"), "bXlwcml2YXRla2V5") != 0) {
        g_printerr("FAIL: wg private-key secret not round-tripped\n");
        return 1;
    }
    if (g_strcmp0(nm_setting_vpn_get_secret(wgvpn, "preshared-key"), "cHJlc2hhcmVka2V5") != 0) {
        g_printerr("FAIL: wg preshared-key secret not round-tripped\n");
        return 1;
    }
    /* An IKEv2-only key must NOT leak into a wireguard connection. */
    if (nm_setting_vpn_get_data_item(wgvpn, "gateway") != NULL) {
        g_printerr("FAIL: gateway leaked into a wireguard connection\n");
        return 1;
    }
    g_print("wireguard round-trip OK\n");

    /* Round-trip a representative spread of the other protocols: a
     * username/password gateway with an optional data field (Fortinet, plus a
     * TOTP secret), a certificate-only mesh with no secrets (Nebula), and one
     * with two required secrets (L2TP). Each also checks a foreign key does not
     * leak into it. */
    const KV fortinet[] = {
        { "server", "fw.example.com", FALSE },
        { "user", "alice", FALSE },
        { "realm", "corp", FALSE },
        { "password", "pw", TRUE },
        { "totp", "JBSWY3DPEHPK3PXP", TRUE },
    };
    if (round_trip(plugin, "fortinet", fortinet, G_N_ELEMENTS(fortinet), "gateway"))
        return 1;

    const KV nebula[] = {
        { "ca", "/etc/nebula/ca.crt", FALSE },
        { "cert", "/etc/nebula/host.crt", FALSE },
        { "key", "/etc/nebula/host.key", FALSE },
        { "lighthouses", "192.168.100.1", FALSE },
    };
    if (round_trip(plugin, "nebula", nebula, G_N_ELEMENTS(nebula), "password"))
        return 1;

    const KV l2tp[] = {
        { "server", "vpn.example.com", FALSE },
        { "user", "bob", FALSE },
        { "psk", "s3cret", TRUE },
        { "password", "pw", TRUE },
    };
    if (round_trip(plugin, "l2tp", l2tp, G_N_ELEMENTS(l2tp), "gateway"))
        return 1;

    /* Validation: an empty connection must be rejected (no gateway). */
    NMVpnEditor *empty = nm_vpn_editor_plugin_get_editor(plugin, NULL, &err);
    NMConnection *out2 = nm_simple_connection_new();
    g_clear_error(&err);
    if (nm_vpn_editor_update_connection(empty, out2, &err)) {
        g_printerr("FAIL: empty editor should not validate\n");
        return 1;
    }
    g_print("validation rejects empty form: %s\n", err ? err->message : "(no message)");

    g_print("PASS: editor round-trip and validation OK\n");
    return 0;
}
