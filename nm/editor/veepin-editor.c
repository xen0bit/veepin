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
 * ONE PROTOCOL PER BUILD. This file is compiled once per protocol, with
 * -DVEEPIN_PROTOCOL="ikev2" and so on, producing one .so per protocol; each is
 * named by its own .name descriptor so every veepin protocol is a separate entry
 * in the OS's "Add VPN" list. That is forced by libnm, not chosen: it refuses to
 * load a plugin whose reported service does not match the .name file's, and
 * nm_vpn_editor_plugin_factory() takes no service argument, so a shared library
 * can answer to exactly one service name. The alternative — one entry that opens
 * a second dialog to pick the protocol — is what this replaced.
 *
 * The field sets are data-driven: each protocol is a row in the `protocols`
 * table below listing its fields (label, vpn key, and whether the key is a
 * required data item, an optional data item, or a secret). Adding or changing a
 * protocol is a table edit here plus a line in the Makefile's VEEPIN_PROTOCOLS —
 * the widget building, validation and (de)serialisation are generic. The keys
 * must match nm/internal/nmconfig's requireKeys / secretMissing switches (and
 * each protocol package's Opt* constants).
 */

#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <libnm/nm-vpn-editor-plugin.h>
#include <libnm/nm-vpn-editor.h>

#ifndef VEEPIN_PROTOCOL
#error "VEEPIN_PROTOCOL must be defined, e.g. -DVEEPIN_PROTOCOL=\\\"ikev2\\\" (see ../Makefile)"
#endif

/* The D-Bus service this build backs. It must match, byte for byte, the
 * service= of the .name descriptor that points at this .so — libnm checks. */
#define VEEPIN_SERVICE_BASE "org.freedesktop.NetworkManager.veepin"
#define VEEPIN_SERVICE      VEEPIN_SERVICE_BASE "." VEEPIN_PROTOCOL

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

#define KEY_HUB           "hub"
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

#define KEY_GROUP         "group"
#define KEY_GROUP_PSK     "group-psk"
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
    const char     *id;    /* vpn.data "protocol" value, and the service suffix */
    const char     *label; /* display name, e.g. "IKEv2" */
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

/* AmneziaWG takes WireGuard's fields unchanged — it is WireGuard with the wire
 * format perturbed. The obfuscation parameters (H1-H4, S1-S4, Jc/Jmin/Jmax) are
 * deliberately absent: they are a shared secret between peers, they are all or
 * nothing, and a dozen spin boxes in a connection dialog is the wrong way to
 * enter them. A profile that needs them uses a config file via nmcli. */
static const FieldDef amneziawg_fields[] = {
    { "Private key",     KEY_PRIVATE_KEY,   F_SECRET },
    { "Peer public key", KEY_PUBLIC_KEY,    F_REQUIRED },
    { "Endpoint",        KEY_ENDPOINT,      F_REQUIRED },
    { "Address",         KEY_ADDRESS,       F_REQUIRED },
    { "Allowed IPs",     KEY_ALLOWED_IPS,   F_REQUIRED },
    { "Pre-shared key",  KEY_PRESHARED_KEY, F_SECRET },
    { "DNS",             KEY_DNS,           F_DATA },
};

static const FieldDef softether_fields[] = {
    { "Server",       KEY_SERVER,   F_REQUIRED },
    { "Username",     KEY_USER,     F_REQUIRED },
    { "Password",     KEY_PASSWORD, F_SECRET },
    { "Virtual hub",  KEY_HUB,      F_DATA },
    { "Port",         KEY_PORT,     F_DATA },
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

static const FieldDef gp_fields[] = {
    { "Gateway",      KEY_SERVER,   F_REQUIRED },
    { "Username",     KEY_USER,     F_REQUIRED },
    { "Port",         KEY_PORT,     F_DATA },
    { "CA (path)",    KEY_CA,       F_DATA },
    { "Password",     KEY_PASSWORD, F_SECRET },
};

static const FieldDef pulse_fields[] = {
    { "Gateway",      KEY_SERVER,   F_REQUIRED },
    { "Username",     KEY_USER,     F_REQUIRED },
    { "Port",         KEY_PORT,     F_DATA },
    { "CA (path)",    KEY_CA,       F_DATA },
    { "Password",     KEY_PASSWORD, F_SECRET },
};

static const FieldDef cisco_fields[] = {
    { "Gateway",       KEY_SERVER,    F_REQUIRED },
    { "Group",         KEY_GROUP,     F_REQUIRED },
    { "Username",      KEY_USER,      F_REQUIRED },
    { "Port",          KEY_PORT,      F_DATA },
    { "Group key",     KEY_GROUP_PSK, F_SECRET },
    { "Password",      KEY_PASSWORD,  F_SECRET },
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
    PROTO("gp",         "GlobalProtect", gp_fields),
    PROTO("cisco",      "Cisco IPsec", cisco_fields),
    PROTO("pulse",      "Ivanti Connect Secure", pulse_fields),
    PROTO("l2tp",       "L2TP/IPsec",  l2tp_fields),
    PROTO("amneziawg",  "AmneziaWG",   amneziawg_fields),
    PROTO("softether",  "SoftEther VPN", softether_fields),
};

#define N_PROTOCOLS G_N_ELEMENTS(protocols)

/* this_protocol returns the row this .so was built for, or NULL if
 * VEEPIN_PROTOCOL names a protocol with no table above. The mismatch is
 * possible only by editing the Makefile's list without adding the table, so it
 * is reported through the factory's GError rather than aborting a GUI process;
 * editor_smoketest turns it into a build failure in CI. */
static const ProtocolDef *
this_protocol(void)
{
    for (guint i = 0; i < N_PROTOCOLS; i++) {
        if (g_strcmp0(VEEPIN_PROTOCOL, protocols[i].id) == 0)
            return &protocols[i];
    }
    return NULL;
}

/*****************************************************************************/
/* Editor widget                                                             */
/*****************************************************************************/

typedef struct {
    GObject parent;
    GtkWidget *widget; /* top-level container returned by get_widget */

    /* The entry widgets of this protocol's field set — entries[j] is field j of
     * this_protocol()->fields. */
    GtkWidget **entries;

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

/* first_secret_key returns the key of this protocol's first secret field, or
 * NULL if it has none — used to reflect the stored save-secrets flag in the
 * checkbox. */
static const char *
first_secret_key(void)
{
    const ProtocolDef *p = this_protocol();
    for (guint j = 0; j < p->n_fields; j++) {
        if (p->fields[j].kind == F_SECRET)
            return p->fields[j].key;
    }
    return NULL;
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
    VeepinEditor      *self = VEEPIN_EDITOR(editor);
    const ProtocolDef *p    = this_protocol();
    NMSettingVpn      *vpn;

    vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(vpn, NM_SETTING_VPN_SERVICE_TYPE, VEEPIN_SERVICE, NULL);
    /* The service name already identifies the protocol, but the key is written
     * anyway: nmconfig on the Go side reads it, which keeps the service's
     * parsing identical however the connection was created (GUI, nmcli, or a
     * hand-written keyfile). */
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
        GtkWidget *entry = self->entries[j];
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
    NMSettingVpn      *vpn = connection ? nm_connection_get_setting_vpn(connection) : NULL;
    const ProtocolDef *p   = this_protocol();
    GtkWidget         *box;

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);

    /* This protocol's field set, built and pre-filled from its table. There is
     * no protocol chooser: the user already chose by picking this VPN type. */
    GtkGrid *grid = new_grid();
    self->entries = g_new0(GtkWidget *, p->n_fields);
    for (guint j = 0; j < p->n_fields; j++) {
        const FieldDef *f = &p->fields[j];
        GtkWidget *e = make_entry(f->kind == F_SECRET);
        add_row(grid, (int) j, f->label, e);
        self->entries[j] = e;
        connect_changed(self, e);
        if (f->kind == F_SECRET)
            set_entry_from_secret(e, vpn, f->key);
        else
            set_entry_from_data(e, vpn, f->key);
    }
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(grid), FALSE, FALSE, 0);

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

    set_entry_from_data(self->mtu, vpn, KEY_MTU);
    if (vpn) {
        const char *ft = nm_setting_vpn_get_data_item(vpn, KEY_FULL_TUNNEL);
        if (ft)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->full_tunnel),
                                         g_strcmp0(ft, "no") != 0);
        /* Reflect the stored secret flag (from this protocol's first secret) in
         * the checkbox; protocols with no secret keep the default. */
        const char *skey = first_secret_key();
        if (skey) {
            NMSettingSecretFlags fl = NM_SETTING_SECRET_FLAG_NONE;
            nm_setting_get_secret_flags(NM_SETTING(vpn), skey, &fl, NULL);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(self->save_secrets),
                                         fl != NM_SETTING_SECRET_FLAG_NOT_SAVED);
        }
    }

    /* Re-validate on any edit. */
    connect_changed(self, self->mtu);
    g_signal_connect(self->full_tunnel, "toggled", G_CALLBACK(field_changed), self);
    g_signal_connect(self->save_secrets, "toggled", G_CALLBACK(field_changed), self);

    self->widget = g_object_ref_sink(box);
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
    g_clear_pointer(&self->entries, g_free); /* frees the array, not the widgets */
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
    const ProtocolDef *p = this_protocol();

    (void) object;
    switch (prop_id) {
    case PROP_NAME:
        /* Kept identical to the .name descriptor's name=, because which of the
         * two a given GUI displays is not something the plugin can observe. */
        g_value_take_string(value, g_strdup_printf("veepin %s", p->label));
        break;
    case PROP_DESC:
        g_value_take_string(value,
                            g_strdup_printf("Connect to a veepin server over %s.", p->label));
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
    if (!this_protocol()) {
        g_set_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
                    "veepin: built for protocol \"%s\", which has no field table "
                    "in veepin-editor.c",
                    VEEPIN_PROTOCOL);
        return NULL;
    }
    return g_object_new(VEEPIN_TYPE_EDITOR_PLUGIN, NULL);
}
