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
 * A protocol chooser at the top switches between one field set per protocol. The
 * field sets are data-driven: each protocol is a row in the `protocols` table
 * below listing its fields (label, vpn key, and whether the key is a required
 * data item, an optional data item, or a secret). Adding or changing a protocol
 * is a table edit here — the widget building, validation and (de)serialisation
 * are generic. The keys must match nm/internal/nmconfig's requireKeys /
 * secretMissing switches (and each protocol package's Opt* constants).
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
/* Shared across protocols. */
#define KEY_SERVER        "server"
#define KEY_PORT          "port"
#define KEY_USER          "user"
#define KEY_PASSWORD      "password"
#define KEY_DNS           "dns"
#define KEY_CA            "ca"
#define KEY_CERT          "cert"
#define KEY_KEYFILE       "key"
/* IKEv2. */
#define KEY_GATEWAY       "gateway"
#define KEY_LOCAL_ID      "local-id"
#define KEY_SERVER_ID     "server-id"
#define KEY_PSK           "psk"
/* WireGuard. */
#define KEY_PUBLIC_KEY    "public-key"
#define KEY_ENDPOINT      "endpoint"
#define KEY_ADDRESS       "address"
#define KEY_ALLOWED_IPS   "allowed-ips"
#define KEY_PRIVATE_KEY   "private-key"
#define KEY_PRESHARED_KEY "preshared-key"
/* OpenVPN (its user key differs from the rest). */
#define KEY_REMOTE        "remote"
#define KEY_USERNAME      "username"
/* SSH. */
#define KEY_IDENTITY      "identity"
/* Fortinet. */
#define KEY_REALM         "realm"
#define KEY_TOTP          "totp"
/* MASQUE. */
#define KEY_AUTHORITY     "authority"
/* Nebula. */
#define KEY_LIGHTHOUSES   "lighthouses"
#define KEY_STATIC_HOSTS  "static-hosts"

/*****************************************************************************/
/* Protocol / field model                                                    */
/*****************************************************************************/

typedef enum {
    F_REQUIRED, /* required data item — update_connection fails if empty */
    F_DATA,     /* optional data item — written only when non-empty */
    F_SECRET,   /* stored as a secret with the chosen storage flag */
} FieldKind;

typedef struct {
    const char *label;
    const char *key;
    FieldKind   kind;
} FieldDef;

typedef struct {
    const char     *id;    /* vpn.data "protocol" value */
    const char     *label; /* combo display text */
    const FieldDef *fields;
    guint           n_fields;
} ProtocolDef;

static const FieldDef ikev2_fields[] = {
    { "Gateway",        KEY_GATEWAY,   F_REQUIRED },
    { "Local ID",       KEY_LOCAL_ID,  F_REQUIRED },
    { "Server ID",      KEY_SERVER_ID, F_DATA },
    { "Username",       KEY_USER,      F_DATA },
    { "Pre-shared key", KEY_PSK,       F_SECRET },
    { "Password",       KEY_PASSWORD,  F_SECRET },
};

static const FieldDef wireguard_fields[] = {
    { "Private key",     KEY_PRIVATE_KEY,   F_SECRET },
    { "Peer public key", KEY_PUBLIC_KEY,    F_REQUIRED },
    { "Endpoint",        KEY_ENDPOINT,      F_REQUIRED },
    { "Address",         KEY_ADDRESS,       F_REQUIRED },
    { "Allowed IPs",     KEY_ALLOWED_IPS,   F_REQUIRED },
    { "Pre-shared key",  KEY_PRESHARED_KEY, F_SECRET },
    { "DNS",             KEY_DNS,           F_DATA },
};

static const FieldDef openvpn_fields[] = {
    { "Remote (host)",     KEY_REMOTE,   F_REQUIRED },
    { "Port",              KEY_PORT,     F_DATA },
    { "CA (path)",         KEY_CA,       F_DATA },
    { "Certificate (path)", KEY_CERT,    F_DATA },
    { "Key (path)",        KEY_KEYFILE,  F_DATA },
    { "Username",          KEY_USERNAME, F_DATA },
    { "Password",          KEY_PASSWORD, F_SECRET },
};

static const FieldDef sstp_fields[] = {
    { "Server",   KEY_SERVER,   F_REQUIRED },
    { "Port",     KEY_PORT,     F_DATA },
    { "Username", KEY_USER,     F_REQUIRED },
    { "Password", KEY_PASSWORD, F_SECRET },
};

static const FieldDef ssh_fields[] = {
    { "Server",         KEY_SERVER,   F_REQUIRED },
    { "Username",       KEY_USER,     F_REQUIRED },
    { "Port",           KEY_PORT,     F_DATA },
    { "Identity (path)", KEY_IDENTITY, F_DATA },
    { "Password",       KEY_PASSWORD, F_SECRET },
};

static const FieldDef anyconnect_fields[] = {
    { "Server",   KEY_SERVER,   F_REQUIRED },
    { "Username", KEY_USER,     F_REQUIRED },
    { "Port",     KEY_PORT,     F_DATA },
    { "Password", KEY_PASSWORD, F_SECRET },
};

static const FieldDef nebula_fields[] = {
    { "CA (path)",          KEY_CA,           F_REQUIRED },
    { "Certificate (path)", KEY_CERT,         F_REQUIRED },
    { "Private key (path)", KEY_KEYFILE,      F_REQUIRED },
    { "Lighthouses",        KEY_LIGHTHOUSES,  F_DATA },
    { "Static hosts",       KEY_STATIC_HOSTS, F_DATA },
};

static const FieldDef masque_fields[] = {
    { "Server",         KEY_SERVER,    F_REQUIRED },
    { "Port",           KEY_PORT,      F_DATA },
    { "Authority",      KEY_AUTHORITY, F_DATA },
    { "CA (path)",      KEY_CA,        F_DATA },
};

static const FieldDef fortinet_fields[] = {
    { "Server",       KEY_SERVER,   F_REQUIRED },
    { "Username",     KEY_USER,     F_REQUIRED },
    { "Port",         KEY_PORT,     F_DATA },
    { "Realm",        KEY_REALM,    F_DATA },
    { "Password",     KEY_PASSWORD, F_SECRET },
    { "TOTP secret",  KEY_TOTP,     F_SECRET },
};

static const FieldDef l2tp_fields[] = {
    { "Server",        KEY_SERVER,   F_REQUIRED },
    { "Username",      KEY_USER,     F_REQUIRED },
    { "Port",          KEY_PORT,     F_DATA },
    { "Pre-shared key", KEY_PSK,     F_SECRET },
    { "Password",      KEY_PASSWORD, F_SECRET },
    { "DNS",           KEY_DNS,      F_DATA },
};

#define PROTO(id_, label_, fields_) { id_, label_, fields_, G_N_ELEMENTS(fields_) }

static const ProtocolDef protocols[] = {
    PROTO("ikev2",      "IKEv2",       ikev2_fields),
    PROTO("wireguard",  "WireGuard",   wireguard_fields),
    PROTO("openvpn",    "OpenVPN",     openvpn_fields),
    PROTO("sstp",       "SSTP",        sstp_fields),
    PROTO("ssh",        "SSH",         ssh_fields),
    PROTO("anyconnect", "AnyConnect",  anyconnect_fields),
    PROTO("nebula",     "Nebula",      nebula_fields),
    PROTO("masque",     "MASQUE",      masque_fields),
    PROTO("fortinet",   "Fortinet",    fortinet_fields),
    PROTO("l2tp",       "L2TP/IPsec",  l2tp_fields),
};

#define N_PROTOCOLS G_N_ELEMENTS(protocols)

/*****************************************************************************/
/* Editor widget                                                             */
/*****************************************************************************/

typedef struct {
    GObject parent;
    GtkWidget *widget; /* top-level container returned by get_widget */

    GtkWidget *protocol; /* combo selecting the protocol */

    /* One field-set box per protocol, shown one at a time, and the entry
     * widgets inside it — entries[i][j] is field j of protocols[i]. */
    GtkWidget  *boxes[N_PROTOCOLS];
    GtkWidget **entries[N_PROTOCOLS];

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

/* selected_index returns the index into protocols[] of the chosen protocol,
 * defaulting to 0 (ikev2, which is also nmconfig's default). */
static guint
selected_index(VeepinEditor *self)
{
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(self->protocol));
    if (id) {
        for (guint i = 0; i < N_PROTOCOLS; i++)
            if (g_strcmp0(id, protocols[i].id) == 0)
                return i;
    }
    return 0;
}

/* first_secret_key returns the key of a protocol's first secret field, or NULL
 * if it has none — used to reflect the stored save-secrets flag in the checkbox. */
static const char *
first_secret_key(guint idx)
{
    const ProtocolDef *p = &protocols[idx];
    for (guint j = 0; j < p->n_fields; j++)
        if (p->fields[j].kind == F_SECRET)
            return p->fields[j].key;
    return NULL;
}

/* update_visibility shows only the selected protocol's field box. */
static void
update_visibility(VeepinEditor *self)
{
    guint sel = selected_index(self);
    for (guint i = 0; i < N_PROTOCOLS; i++)
        gtk_widget_set_visible(self->boxes[i], i == sel);
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
    guint sel = selected_index(self);
    const ProtocolDef *p = &protocols[sel];
    NMSettingVpn *vpn;

    vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, VEEPIN_SERVICE, NULL);
    nm_setting_vpn_add_data_item(vpn, KEY_PROTOCOL, p->id);

    /* Secret storage: NONE means "the system saves this secret with the
     * connection" (the root service reads it at Connect, no prompt needed);
     * NOT_SAVED means "ask every time" (needs the auth-dialog). */
    NMSettingSecretFlags flags =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(self->save_secrets))
            ? NM_SETTING_SECRET_FLAG_NONE
            : NM_SETTING_SECRET_FLAG_NOT_SAVED;

    for (guint j = 0; j < p->n_fields; j++) {
        const FieldDef *f = &p->fields[j];
        GtkWidget *entry = self->entries[sel][j];
        switch (f->kind) {
        case F_REQUIRED:
            if (!require(vpn, entry, f->key, f->label, error)) {
                g_object_unref(vpn);
                return FALSE;
            }
            break;
        case F_DATA:
            add_optional_data(vpn, entry, f->key);
            break;
        case F_SECRET:
            add_secret(vpn, entry, f->key, flags);
            break;
        }
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
    GtkGrid *top;

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);

    /* Protocol chooser. */
    top = new_grid();
    self->protocol = gtk_combo_box_text_new();
    for (guint i = 0; i < N_PROTOCOLS; i++)
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(self->protocol),
                                  protocols[i].id, protocols[i].label);
    add_row(top, 0, "Protocol", self->protocol);
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(top), FALSE, FALSE, 0);

    /* One field box per protocol, built and pre-filled from its table. */
    for (guint i = 0; i < N_PROTOCOLS; i++) {
        const ProtocolDef *p = &protocols[i];
        GtkGrid *grid = new_grid();
        self->entries[i] = g_new0(GtkWidget *, p->n_fields);
        for (guint j = 0; j < p->n_fields; j++) {
            const FieldDef *f = &p->fields[j];
            GtkWidget *e = make_entry(f->kind == F_SECRET);
            add_row(grid, (int) j, f->label, e);
            self->entries[i][j] = e;
            connect_changed(self, e);
            if (f->kind == F_SECRET)
                set_entry_from_secret(e, vpn, f->key);
            else
                set_entry_from_data(e, vpn, f->key);
        }
        self->boxes[i] = GTK_WIDGET(grid);
        gtk_box_pack_start(GTK_BOX(box), self->boxes[i], FALSE, FALSE, 0);
    }

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

    /* Select the connection's protocol (default ikev2) and pre-fill the commons. */
    const char *proto = vpn ? nm_setting_vpn_get_data_item(vpn, KEY_PROTOCOL) : NULL;
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(self->protocol),
                                proto ? proto : protocols[0].id);

    set_entry_from_data(self->mtu, vpn, KEY_MTU);
    if (vpn) {
        const char *ft = nm_setting_vpn_get_data_item(vpn, KEY_FULL_TUNNEL);
        if (ft)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->full_tunnel),
                                         g_strcmp0(ft, "no") != 0);
        /* Reflect the stored secret flag (from the selected protocol's first
         * secret) in the checkbox; protocols with no secret keep the default. */
        const char *skey = first_secret_key(selected_index(self));
        if (skey) {
            NMSettingSecretFlags fl = NM_SETTING_SECRET_FLAG_NONE;
            nm_setting_get_secret_flags(NM_SETTING(vpn), skey, &fl, NULL);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->save_secrets),
                                         fl != NM_SETTING_SECRET_FLAG_NOT_SAVED);
        }
    }

    /* Re-validate on any edit. */
    g_signal_connect(self->protocol, "changed", G_CALLBACK(protocol_changed), self);
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
    for (guint i = 0; i < N_PROTOCOLS; i++)
        g_clear_pointer(&self->entries[i], g_free); /* frees the array, not the widgets */
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
        g_value_set_string(value,
                           "Connect via the veepin VPN backend (IKEv2, WireGuard, OpenVPN, "
                           "SSTP, SSH, AnyConnect, Nebula, MASQUE, Fortinet, L2TP/IPsec).");
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
