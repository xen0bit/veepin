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
 * Keys must match nm/internal/nmconfig: protocol, gateway, local-id, server-id,
 * user, full-tunnel, mtu (data) and psk, password (secrets).
 */

#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <libnm/nm-vpn-editor-plugin.h>
#include <libnm/nm-vpn-editor.h>

#define VEEPIN_SERVICE "org.freedesktop.NetworkManager.veepin"

/* Data / secret keys (kept in sync with nm/internal/nmconfig). */
#define KEY_PROTOCOL    "protocol"
#define KEY_GATEWAY     "gateway"
#define KEY_LOCAL_ID    "local-id"
#define KEY_SERVER_ID   "server-id"
#define KEY_USER        "user"
#define KEY_FULL_TUNNEL "full-tunnel"
#define KEY_MTU         "mtu"
#define KEY_PSK         "psk"
#define KEY_PASSWORD    "password"

/* The protocol this form configures. nmconfig defaults to ikev2 when the key is
 * absent, but new profiles state it explicitly so they stay unambiguous once
 * veepin speaks more than one protocol. There is no chooser in the form while
 * IKEv2 is the only option. */
#define PROTOCOL_IKEV2  "ikev2"

/*****************************************************************************/
/* Editor widget                                                             */
/*****************************************************************************/

typedef struct {
    GObject parent;
    GtkWidget *widget; /* top-level container returned by get_widget */
    GtkWidget *gateway;
    GtkWidget *local_id;
    GtkWidget *server_id;
    GtkWidget *psk;
    GtkWidget *user;
    GtkWidget *password;
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

static gboolean
update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    VeepinEditor *self = VEEPIN_EDITOR(editor);
    NMSettingVpn *vpn;
    const char *s;

    vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, VEEPIN_SERVICE, NULL);
    nm_setting_vpn_add_data_item(vpn, KEY_PROTOCOL, PROTOCOL_IKEV2);

    s = gtk_entry_get_text(GTK_ENTRY(self->gateway));
    if (!s || !*s) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            "A gateway (server address) is required.");
        g_object_unref(vpn);
        return FALSE;
    }
    nm_setting_vpn_add_data_item(vpn, KEY_GATEWAY, s);

    s = gtk_entry_get_text(GTK_ENTRY(self->local_id));
    if (!s || !*s) {
        g_set_error_literal(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            "A local identity is required.");
        g_object_unref(vpn);
        return FALSE;
    }
    nm_setting_vpn_add_data_item(vpn, KEY_LOCAL_ID, s);

    s = gtk_entry_get_text(GTK_ENTRY(self->server_id));
    if (s && *s)
        nm_setting_vpn_add_data_item(vpn, KEY_SERVER_ID, s);

    s = gtk_entry_get_text(GTK_ENTRY(self->user));
    if (s && *s)
        nm_setting_vpn_add_data_item(vpn, KEY_USER, s);

    s = gtk_entry_get_text(GTK_ENTRY(self->mtu));
    if (s && *s)
        nm_setting_vpn_add_data_item(vpn, KEY_MTU, s);

    nm_setting_vpn_add_data_item(vpn, KEY_FULL_TUNNEL,
                                 gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(self->full_tunnel))
                                     ? "yes" : "no");

    /* Secret storage: NONE means "the system saves this secret with the
     * connection" (the root service reads it at Connect, no prompt needed);
     * NOT_SAVED means "ask every time" (needs the auth-dialog, still TODO). */
    NMSettingSecretFlags flags =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(self->save_secrets))
            ? NM_SETTING_SECRET_FLAG_NONE
            : NM_SETTING_SECRET_FLAG_NOT_SAVED;

    s = gtk_entry_get_text(GTK_ENTRY(self->psk));
    if (s && *s) {
        nm_setting_vpn_add_secret(vpn, KEY_PSK, s);
        nm_setting_set_secret_flags(NM_SETTING(vpn), KEY_PSK, flags, NULL);
    }

    s = gtk_entry_get_text(GTK_ENTRY(self->password));
    if (s && *s) {
        nm_setting_vpn_add_secret(vpn, KEY_PASSWORD, s);
        nm_setting_set_secret_flags(NM_SETTING(vpn), KEY_PASSWORD, flags, NULL);
    }

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

static void
build_ui(VeepinEditor *self, NMConnection *connection)
{
    NMSettingVpn *vpn = connection ? nm_connection_get_setting_vpn(connection) : NULL;
    GtkGrid *grid;
    int row = 0;

    grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_row_spacing(grid, 6);
    gtk_grid_set_column_spacing(grid, 12);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);

    self->gateway   = add_row(grid, row++, "Gateway",       make_entry(FALSE));
    self->local_id  = add_row(grid, row++, "Local ID",      make_entry(FALSE));
    self->server_id = add_row(grid, row++, "Server ID",     make_entry(FALSE));
    self->psk       = add_row(grid, row++, "Pre-shared key", make_entry(TRUE));
    self->user      = add_row(grid, row++, "Username",      make_entry(FALSE));
    self->password  = add_row(grid, row++, "Password",      make_entry(TRUE));
    self->mtu       = add_row(grid, row++, "MTU (optional)", make_entry(FALSE));

    self->full_tunnel = gtk_check_button_new_with_label("Route all traffic through the VPN");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->full_tunnel), TRUE);
    gtk_grid_attach(grid, self->full_tunnel, 0, row++, 2, 1);

    self->save_secrets = gtk_check_button_new_with_label("Save the pre-shared key / password");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->save_secrets), TRUE);
    gtk_grid_attach(grid, self->save_secrets, 0, row++, 2, 1);

    /* Pre-fill from an existing connection. */
    set_entry_from_data(self->gateway, vpn, KEY_GATEWAY);
    set_entry_from_data(self->local_id, vpn, KEY_LOCAL_ID);
    set_entry_from_data(self->server_id, vpn, KEY_SERVER_ID);
    set_entry_from_data(self->user, vpn, KEY_USER);
    set_entry_from_data(self->mtu, vpn, KEY_MTU);
    if (vpn) {
        const char *ft = nm_setting_vpn_get_data_item(vpn, KEY_FULL_TUNNEL);
        if (ft)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->full_tunnel),
                                         g_strcmp0(ft, "no") != 0);
        const char *psk = nm_setting_vpn_get_secret(vpn, KEY_PSK);
        if (psk)
            gtk_entry_set_text(GTK_ENTRY(self->psk), psk);
        /* Reflect the stored secret's flag in the checkbox. */
        NMSettingSecretFlags fl = NM_SETTING_SECRET_FLAG_NONE;
        nm_setting_get_secret_flags(NM_SETTING(vpn), KEY_PSK, &fl, NULL);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->save_secrets),
                                     fl != NM_SETTING_SECRET_FLAG_NOT_SAVED);
    }

    /* Re-validate on any edit. */
    g_signal_connect(self->gateway, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->local_id, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->server_id, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->psk, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->user, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->password, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->mtu, "changed", G_CALLBACK(field_changed), self);
    g_signal_connect(self->full_tunnel, "toggled", G_CALLBACK(field_changed), self);
    g_signal_connect(self->save_secrets, "toggled", G_CALLBACK(field_changed), self);

    self->widget = g_object_ref_sink(GTK_WIDGET(grid));
    gtk_widget_show_all(self->widget);
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
        g_value_set_string(value, "IKEv2 (veepin)");
        break;
    case PROP_DESC:
        g_value_set_string(value, "Compatible with the veepin IKEv2 VPN server.");
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
