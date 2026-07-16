/*
 * veepin-editor.c — NetworkManager VPN editor plugin for veepin.
 *
 * This is the graphical half of the plugin: a GObject shared library that
 * nm-connection-editor / GNOME Settings dlopen() to draw the "Add VPN" form and
 * translate its fields to/from the connection's vpn.data / vpn.secrets maps that
 * the D-Bus service (nm-veepin-service) consumes.
 *
 * It is written in C against libnm/libnma because NetworkManager loads editor
 * plugins as GObject types — this is the one piece the project cannot express in
 * Go. It is built separately (see ../Makefile) and never linked into any Go
 * binary, so the core veepin binaries stay CGO-free.
 *
 * A protocol chooser at the top switches between two field sets. Keys must match
 * nm/internal/nmconfig:
 *   common   protocol, full-tunnel, mtu
 *   ikev2    gateway, local-id, server-id, user (data); psk, password (secrets)
 *   wireguard public-key, endpoint, address, allowed-ips, dns (data);
 *            private-key, preshared-key (secrets)
 */

#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <libnm/nm-vpn-editor-plugin.h>
#include <libnm/nm-vpn-editor.h>

#define VEEPIN_SERVICE "org.freedesktop.NetworkManager.veepin"

/* Data / secret keys (kept in sync with nm/internal/nmconfig). */
#define KEY_PROTOCOL      "protocol"
#define KEY_FULL_TUNNEL   "full-tunnel"
#define KEY_MTU           "mtu"
/* IKEv2 */
#define KEY_GATEWAY       "gateway"
#define KEY_LOCAL_ID      "local-id"
#define KEY_SERVER_ID     "server-id"
#define KEY_USER          "user"
#define KEY_PSK           "psk"
#define KEY_PASSWORD      "password"
/* WireGuard */
#define KEY_PUBLIC_KEY    "public-key"
#define KEY_ENDPOINT      "endpoint"
#define KEY_ADDRESS       "address"
#define KEY_ALLOWED_IPS   "allowed-ips"
#define KEY_DNS           "dns"
#define KEY_PRIVATE_KEY   "private-key"
#define KEY_PRESHARED_KEY "preshared-key"

#define PROTOCOL_IKEV2     "ikev2"
#define PROTOCOL_WIREGUARD "wireguard"

/*****************************************************************************/
/* Editor widget                                                             */
/*****************************************************************************/

typedef struct {
    GObject parent;
    GtkWidget *widget; /* top-level container returned by get_widget */

    GtkWidget *protocol; /* combo: ikev2 / wireguard */

    /* Field groups, shown one at a time by the protocol combo. */
    GtkWidget *ikev2_box;
    GtkWidget *wireguard_box;

    /* IKEv2 fields. */
    GtkWidget *gateway;
    GtkWidget *local_id;
    GtkWidget *server_id;
    GtkWidget *psk;
    GtkWidget *user;
    GtkWidget *password;

    /* WireGuard fields. */
    GtkWidget *private_key;
    GtkWidget *public_key;
    GtkWidget *endpoint;
    GtkWidget *address;
    GtkWidget *allowed_ips;
    GtkWidget *preshared_key;
    GtkWidget *dns;

    /* Common. */
    GtkWidget *full_tunnel;
    GtkWidget *mtu;
    GtkWidget *save_secrets;
} VeepinEditor;

typedef struct {
    GObjectClass parent;
} VeepinEditorClass;

static void veepin_editor_interface_init(NMVpnEditorInterface *iface);

GType veepin_editor_get_type(void);
G_DEFINE_TYPE_WITH_CODE(VeepinEditor, veepin_editor, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR,
                                              veepin_editor_interface_init))

#define VEEPIN_TYPE_EDITOR (veepin_editor_get_type())
#define VEEPIN_EDITOR(o)   (G_TYPE_CHECK_INSTANCE_CAST((o), VEEPIN_TYPE_EDITOR, VeepinEditor))

static GObject *
get_widget(NMVpnEditor *editor)
{
    VeepinEditor *self = VEEPIN_EDITOR(editor);
    return G_OBJECT(self->widget);
}

/* Emit "changed" so the editor's OK/Apply button tracks validity. */
static void
field_changed(GtkWidget *w, gpointer user_data)
{
    (void) w;
    g_signal_emit_by_name(NM_VPN_EDITOR(user_data), "changed");
}

/* selected_protocol returns "ikev2" or "wireguard" from the combo, defaulting to
 * ikev2 (which is also nmconfig's default). */
static const char *
selected_protocol(VeepinEditor *self)
{
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(self->protocol));
    return id ? id : PROTOCOL_IKEV2;
}

/* update_visibility shows the field group for the selected protocol and hides
 * the other. */
static void
update_visibility(VeepinEditor *self)
{
    gboolean wg = g_strcmp0(selected_protocol(self), PROTOCOL_WIREGUARD) == 0;
    gtk_widget_set_visible(self->ikev2_box, !wg);
    gtk_widget_set_visible(self->wireguard_box, wg);
}

static void
protocol_changed(GtkWidget *w, gpointer user_data)
{
    VeepinEditor *self = VEEPIN_EDITOR(user_data);
    update_visibility(self);
    field_changed(w, user_data);
}

/* require reads an entry and fails with a missing-property error if it is empty.
 * On success the value is added to vpn under key. */
static gboolean
require(NMSettingVpn *vpn, GtkWidget *entry, const char *key, const char *what, GError **error)
{
    const char *s = gtk_entry_get_text(GTK_ENTRY(entry));
    if (!s || !*s) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    "%s is required.", what);
        return FALSE;
    }
    nm_setting_vpn_add_data_item(vpn, key, s);
    return TRUE;
}

/* add_optional_data adds an entry's value under key when non-empty. */
static void
add_optional_data(NMSettingVpn *vpn, GtkWidget *entry, const char *key)
{
    const char *s = gtk_entry_get_text(GTK_ENTRY(entry));
    if (s && *s)
        nm_setting_vpn_add_data_item(vpn, key, s);
}

/* add_secret stores an entry's value as a secret with the chosen storage flag. */
static void
add_secret(NMSettingVpn *vpn, GtkWidget *entry, const char *key, NMSettingSecretFlags flags)
{
    const char *s = gtk_entry_get_text(GTK_ENTRY(entry));
    if (s && *s) {
        nm_setting_vpn_add_secret(vpn, key, s);
        nm_setting_set_secret_flags(NM_SETTING(vpn), key, flags, NULL);
    }
}

static gboolean
update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    VeepinEditor *self = VEEPIN_EDITOR(editor);
    NMSettingVpn *vpn;
    const char *protocol = selected_protocol(self);

    vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, VEEPIN_SERVICE, NULL);
    nm_setting_vpn_add_data_item(vpn, KEY_PROTOCOL, protocol);

    /* Secret storage: NONE means "the system saves this secret with the
     * connection" (the root service reads it at Connect, no prompt needed);
     * NOT_SAVED means "ask every time" (needs the auth-dialog). */
    NMSettingSecretFlags flags =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(self->save_secrets))
            ? NM_SETTING_SECRET_FLAG_NONE
            : NM_SETTING_SECRET_FLAG_NOT_SAVED;

    if (g_strcmp0(protocol, PROTOCOL_WIREGUARD) == 0) {
        if (!require(vpn, self->public_key, KEY_PUBLIC_KEY, "A peer public key", error) ||
            !require(vpn, self->endpoint, KEY_ENDPOINT, "An endpoint (host:port)", error) ||
            !require(vpn, self->address, KEY_ADDRESS, "A tunnel address", error) ||
            !require(vpn, self->allowed_ips, KEY_ALLOWED_IPS, "Allowed IPs", error)) {
            g_object_unref(vpn);
            return FALSE;
        }
        add_optional_data(vpn, self->dns, KEY_DNS);
        add_secret(vpn, self->private_key, KEY_PRIVATE_KEY, flags);
        add_secret(vpn, self->preshared_key, KEY_PRESHARED_KEY, flags);
    } else {
        if (!require(vpn, self->gateway, KEY_GATEWAY, "A gateway (server address)", error) ||
            !require(vpn, self->local_id, KEY_LOCAL_ID, "A local identity", error)) {
            g_object_unref(vpn);
            return FALSE;
        }
        add_optional_data(vpn, self->server_id, KEY_SERVER_ID);
        add_optional_data(vpn, self->user, KEY_USER);
        add_secret(vpn, self->psk, KEY_PSK, flags);
        add_secret(vpn, self->password, KEY_PASSWORD, flags);
    }

    add_optional_data(vpn, self->mtu, KEY_MTU);
    nm_setting_vpn_add_data_item(vpn, KEY_FULL_TUNNEL,
                                 gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(self->full_tunnel))
                                     ? "yes" : "no");

    nm_connection_add_setting(connection, NM_SETTING(vpn));
    return TRUE;
}

/* Populate an entry from an existing connection's vpn data item. */
static void
set_entry_from_data(GtkWidget *entry, NMSettingVpn *vpn, const char *key)
{
    const char *v = vpn ? nm_setting_vpn_get_data_item(vpn, key) : NULL;
    if (v)
        gtk_entry_set_text(GTK_ENTRY(entry), v);
}

/* Populate an entry from an existing connection's stored secret. */
static void
set_entry_from_secret(GtkWidget *entry, NMSettingVpn *vpn, const char *key)
{
    const char *v = vpn ? nm_setting_vpn_get_secret(vpn, key) : NULL;
    if (v)
        gtk_entry_set_text(GTK_ENTRY(entry), v);
}

static GtkWidget *
add_row(GtkGrid *grid, int row, const char *label, GtkWidget *entry)
{
    GtkWidget *l = gtk_label_new(label);
    gtk_widget_set_halign(l, GTK_ALIGN_START);
    gtk_grid_attach(grid, l, 0, row, 1, 1);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_grid_attach(grid, entry, 1, row, 1, 1);
    return entry;
}

static GtkWidget *
make_entry(gboolean secret)
{
    GtkWidget *e = gtk_entry_new();
    if (secret) {
        gtk_entry_set_visibility(GTK_ENTRY(e), FALSE);
        gtk_entry_set_input_purpose(GTK_ENTRY(e), GTK_INPUT_PURPOSE_PASSWORD);
    }
    return e;
}

static GtkGrid *
new_grid(void)
{
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_row_spacing(grid, 6);
    gtk_grid_set_column_spacing(grid, 12);
    return grid;
}

/* connect_changed wires an entry's "changed" to re-validation. */
static void
connect_changed(VeepinEditor *self, GtkWidget *entry)
{
    g_signal_connect(entry, "changed", G_CALLBACK(field_changed), self);
}

static void
build_ui(VeepinEditor *self, NMConnection *connection)
{
    NMSettingVpn *vpn = connection ? nm_connection_get_setting_vpn(connection) : NULL;
    GtkWidget *box;
    GtkGrid *top, *ike, *wg;
    int row;

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);

    /* Protocol chooser. */
    top = new_grid();
    self->protocol = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(self->protocol), PROTOCOL_IKEV2, "IKEv2");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(self->protocol), PROTOCOL_WIREGUARD, "WireGuard");
    add_row(top, 0, "Protocol", self->protocol);
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(top), FALSE, FALSE, 0);

    /* IKEv2 fields. */
    ike = new_grid();
    row = 0;
    self->gateway   = add_row(ike, row++, "Gateway",        make_entry(FALSE));
    self->local_id  = add_row(ike, row++, "Local ID",       make_entry(FALSE));
    self->server_id = add_row(ike, row++, "Server ID",      make_entry(FALSE));
    self->psk       = add_row(ike, row++, "Pre-shared key", make_entry(TRUE));
    self->user      = add_row(ike, row++, "Username",       make_entry(FALSE));
    self->password  = add_row(ike, row++, "Password",       make_entry(TRUE));
    self->ikev2_box = GTK_WIDGET(ike);
    gtk_box_pack_start(GTK_BOX(box), self->ikev2_box, FALSE, FALSE, 0);

    /* WireGuard fields. */
    wg = new_grid();
    row = 0;
    self->private_key   = add_row(wg, row++, "Private key",    make_entry(TRUE));
    self->public_key    = add_row(wg, row++, "Peer public key", make_entry(FALSE));
    self->endpoint      = add_row(wg, row++, "Endpoint",       make_entry(FALSE));
    self->address       = add_row(wg, row++, "Address",        make_entry(FALSE));
    self->allowed_ips   = add_row(wg, row++, "Allowed IPs",    make_entry(FALSE));
    self->preshared_key = add_row(wg, row++, "Pre-shared key", make_entry(TRUE));
    self->dns           = add_row(wg, row++, "DNS (optional)", make_entry(FALSE));
    self->wireguard_box = GTK_WIDGET(wg);
    gtk_box_pack_start(GTK_BOX(box), self->wireguard_box, FALSE, FALSE, 0);

    /* Common fields. */
    GtkGrid *common = new_grid();
    self->mtu = add_row(common, 0, "MTU (optional)", make_entry(FALSE));
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(common), FALSE, FALSE, 0);

    self->full_tunnel = gtk_check_button_new_with_label("Route all traffic through the VPN");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->full_tunnel), TRUE);
    gtk_box_pack_start(GTK_BOX(box), self->full_tunnel, FALSE, FALSE, 0);

    self->save_secrets = gtk_check_button_new_with_label("Save keys and passwords");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->save_secrets), TRUE);
    gtk_box_pack_start(GTK_BOX(box), self->save_secrets, FALSE, FALSE, 0);

    /* Pre-fill from an existing connection. */
    const char *proto = vpn ? nm_setting_vpn_get_data_item(vpn, KEY_PROTOCOL) : NULL;
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(self->protocol),
                                proto ? proto : PROTOCOL_IKEV2);

    set_entry_from_data(self->gateway, vpn, KEY_GATEWAY);
    set_entry_from_data(self->local_id, vpn, KEY_LOCAL_ID);
    set_entry_from_data(self->server_id, vpn, KEY_SERVER_ID);
    set_entry_from_data(self->user, vpn, KEY_USER);
    set_entry_from_secret(self->psk, vpn, KEY_PSK);

    set_entry_from_data(self->public_key, vpn, KEY_PUBLIC_KEY);
    set_entry_from_data(self->endpoint, vpn, KEY_ENDPOINT);
    set_entry_from_data(self->address, vpn, KEY_ADDRESS);
    set_entry_from_data(self->allowed_ips, vpn, KEY_ALLOWED_IPS);
    set_entry_from_data(self->dns, vpn, KEY_DNS);
    set_entry_from_secret(self->private_key, vpn, KEY_PRIVATE_KEY);
    set_entry_from_secret(self->preshared_key, vpn, KEY_PRESHARED_KEY);

    set_entry_from_data(self->mtu, vpn, KEY_MTU);
    if (vpn) {
        const char *ft = nm_setting_vpn_get_data_item(vpn, KEY_FULL_TUNNEL);
        if (ft)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->full_tunnel),
                                         g_strcmp0(ft, "no") != 0);
        /* Reflect the stored PSK/private-key secret flag in the checkbox. */
        const char *skey = (g_strcmp0(proto, PROTOCOL_WIREGUARD) == 0) ? KEY_PRIVATE_KEY : KEY_PSK;
        NMSettingSecretFlags fl = NM_SETTING_SECRET_FLAG_NONE;
        nm_setting_get_secret_flags(NM_SETTING(vpn), skey, &fl, NULL);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->save_secrets),
                                     fl != NM_SETTING_SECRET_FLAG_NOT_SAVED);
    }

    /* Re-validate on any edit. */
    g_signal_connect(self->protocol, "changed", G_CALLBACK(protocol_changed), self);
    connect_changed(self, self->gateway);
    connect_changed(self, self->local_id);
    connect_changed(self, self->server_id);
    connect_changed(self, self->psk);
    connect_changed(self, self->user);
    connect_changed(self, self->password);
    connect_changed(self, self->private_key);
    connect_changed(self, self->public_key);
    connect_changed(self, self->endpoint);
    connect_changed(self, self->address);
    connect_changed(self, self->allowed_ips);
    connect_changed(self, self->preshared_key);
    connect_changed(self, self->dns);
    connect_changed(self, self->mtu);
    g_signal_connect(self->full_tunnel, "toggled", G_CALLBACK(field_changed), self);
    g_signal_connect(self->save_secrets, "toggled", G_CALLBACK(field_changed), self);

    self->widget = g_object_ref_sink(box);
    gtk_widget_show_all(self->widget);
    /* Show only the selected protocol's fields (after show_all). */
    update_visibility(self);
}

static void
veepin_editor_init(VeepinEditor *self)
{
    (void) self;
}

static void
veepin_editor_dispose(GObject *object)
{
    VeepinEditor *self = VEEPIN_EDITOR(object);
    g_clear_object(&self->widget);
    G_OBJECT_CLASS(veepin_editor_parent_class)->dispose(object);
}

static void
veepin_editor_class_init(VeepinEditorClass *klass)
{
    G_OBJECT_CLASS(klass)->dispose = veepin_editor_dispose;
}

static void
veepin_editor_interface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget = get_widget;
    iface->update_connection = update_connection;
}

/* Constructor used by the plugin's get_editor(). */
static NMVpnEditor *
veepin_editor_new(NMConnection *connection, GError **error)
{
    VeepinEditor *self;

    (void) error;
    self = g_object_new(VEEPIN_TYPE_EDITOR, NULL);
    build_ui(self, connection);
    return NM_VPN_EDITOR(self);
}

/*****************************************************************************/
/* Editor plugin                                                             */
/*****************************************************************************/

typedef struct {
    GObject parent;
} VeepinEditorPlugin;

typedef struct {
    GObjectClass parent;
} VeepinEditorPluginClass;

static void veepin_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface);

GType veepin_editor_plugin_get_type(void);
G_DEFINE_TYPE_WITH_CODE(VeepinEditorPlugin, veepin_editor_plugin, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN,
                                              veepin_editor_plugin_interface_init))

#define VEEPIN_TYPE_EDITOR_PLUGIN (veepin_editor_plugin_get_type())

enum { PROP_0, PROP_NAME, PROP_DESC, PROP_SERVICE };

static NMVpnEditor *
get_editor(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    (void) plugin;
    return veepin_editor_new(connection, error);
}

static NMVpnEditorPluginCapability
get_capabilities(NMVpnEditorPlugin *plugin)
{
    (void) plugin;
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static void
plugin_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    (void) object;
    switch (prop_id) {
    case PROP_NAME:
        g_value_set_string(value, "veepin VPN");
        break;
    case PROP_DESC:
        g_value_set_string(value, "IKEv2 or WireGuard via the veepin VPN backend.");
        break;
    case PROP_SERVICE:
        g_value_set_string(value, VEEPIN_SERVICE);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    }
}

static void
veepin_editor_plugin_init(VeepinEditorPlugin *self)
{
    (void) self;
}

static void
veepin_editor_plugin_class_init(VeepinEditorPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    object_class->get_property = plugin_get_property;

    g_object_class_override_property(object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
    g_object_class_override_property(object_class, PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
    g_object_class_override_property(object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
veepin_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor = get_editor;
    iface->get_capabilities = get_capabilities;
}

/*****************************************************************************/
/* Factory                                                                   */
/*****************************************************************************/

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    (void) error;
    return g_object_new(VEEPIN_TYPE_EDITOR_PLUGIN, NULL);
}
