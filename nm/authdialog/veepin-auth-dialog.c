/*
 * veepin-auth-dialog.c — NetworkManager VPN auth-dialog for veepin.
 *
 * NetworkManager runs this helper when an veepin connection needs secrets that
 * are not saved (flag NOT_SAVED, "ask every time") — the interactive complement
 * to the editor's saved-secret support. It speaks NM's auth-dialog stdio
 * protocol: NM writes the connection's data/secrets to stdin (DATA_KEY/DATA_VAL,
 * SECRET_KEY/SECRET_VAL, DONE), the helper prompts for the missing psk/password
 * via a libnma dialog, and writes the secrets back to stdout ("key\nvalue\n"
 * pairs, terminated by a blank line), then waits for NM to close the pipe.
 *
 * Built separately (C/libnm/libnma) and never linked into any Go binary, so the
 * core stays CGO-free. Keys match nm/internal/nmconfig and the editor.
 */

#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <libnm/nm-vpn-service-plugin.h>
#include <libnma/nma-vpn-password-dialog.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define VEEPIN_SERVICE "org.freedesktop.NetworkManager.veepin"
#define KEY_PROTOCOL    "protocol"
#define KEY_PSK         "psk"
#define KEY_PASSWORD    "password"
#define KEY_USER        "user"
#define KEY_PRIVATE_KEY "private-key"

/* True if NM must (re-)prompt for the named secret. */
static gboolean
secret_needed(GHashTable *data, GHashTable *secrets, const char *key, gboolean reprompt)
{
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
    const char *val = g_hash_table_lookup(secrets, key);

    nm_vpn_service_plugin_get_secret_flags(data, key, &flags);
    if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
        return FALSE;
    if (reprompt)
        return TRUE;
    return (val == NULL || val[0] == '\0');
}

/* Wait for NM to close stdin (or send "QUIT"), bounded to 20s, so the dialog
 * stays available until NM is done reading our secrets. */
static void
wait_for_quit(void)
{
    GString *buf = g_string_sized_new(16);
    time_t start = time(NULL);
    char c;
    ssize_t n;

    while (time(NULL) < start + 20) {
        n = read(0, &c, 1);
        if (n <= 0)
            break; /* EOF or error: NM closed the pipe */
        g_string_append_c(buf, c);
        if (strstr(buf->str, "QUIT") || buf->len > 16)
            break;
    }
    g_string_free(buf, TRUE);
}

static void
emit_secret(const char *key, const char *val)
{
    if (val)
        printf("%s\n%s\n", key, val);
}

int
main(int argc, char **argv)
{
    char *opt_uuid = NULL, *opt_name = NULL, *opt_service = NULL;
    gboolean opt_interaction = FALSE, opt_reprompt = FALSE;
    char **opt_hints = NULL;
    GOptionEntry entries[] = {
        {"uuid", 'u', 0, G_OPTION_ARG_STRING, &opt_uuid, "UUID", NULL},
        {"name", 'n', 0, G_OPTION_ARG_STRING, &opt_name, "Name", NULL},
        {"service", 's', 0, G_OPTION_ARG_STRING, &opt_service, "Service", NULL},
        {"allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &opt_interaction, "Allow interaction", NULL},
        {"reprompt", 'r', 0, G_OPTION_ARG_NONE, &opt_reprompt, "Reprompt", NULL},
        {"hint", 't', 0, G_OPTION_ARG_STRING_ARRAY, &opt_hints, "Hints", NULL},
        {NULL},
    };
    GOptionContext *ctx;
    GError *error = NULL;
    GHashTable *data = NULL, *secrets = NULL;

    ctx = g_option_context_new(NULL);
    g_option_context_set_ignore_unknown_options(ctx, TRUE);
    g_option_context_add_main_entries(ctx, entries, NULL);
    /* GTK options are parsed lazily below (only when we actually prompt). */
    g_option_context_set_help_enabled(ctx, FALSE);
    if (!g_option_context_parse(ctx, &argc, &argv, &error)) {
        g_printerr("veepin-auth-dialog: %s\n", error->message);
        return 1;
    }
    g_option_context_free(ctx);

    if (opt_service && g_strcmp0(opt_service, VEEPIN_SERVICE) != 0) {
        g_printerr("veepin-auth-dialog: not my service (%s)\n", opt_service);
        return 1;
    }

    if (!nm_vpn_service_plugin_read_vpn_details(0, &data, &secrets)) {
        g_printerr("veepin-auth-dialog: failed to read connection details from stdin\n");
        return 1;
    }

    const char *protocol = g_hash_table_lookup(data, KEY_PROTOCOL);
    gboolean is_wg = protocol && g_strcmp0(protocol, "wireguard") == 0;
    const char *user = g_hash_table_lookup(data, KEY_USER);
    gboolean have_user = (user && user[0]);

    /* The secrets to consider, by protocol. WireGuard needs only the private key
     * interactively (its optional preshared key is left to the saved path);
     * IKEv2 needs the PSK, and the EAP password when a username is configured.
     * Both protocols fit the dialog's two fields. */
    struct field {
        const char *key, *label, *cur;
        gboolean need;
    } fields[2];
    int nfields = 0;
    if (is_wg) {
        const char *priv = g_hash_table_lookup(secrets, KEY_PRIVATE_KEY);
        fields[nfields++] = (struct field){
            KEY_PRIVATE_KEY, "Private key:", priv,
            secret_needed(data, secrets, KEY_PRIVATE_KEY, opt_reprompt)};
    } else {
        const char *psk = g_hash_table_lookup(secrets, KEY_PSK);
        const char *pw = g_hash_table_lookup(secrets, KEY_PASSWORD);
        fields[nfields++] = (struct field){
            KEY_PSK, "Pre-shared key:", psk,
            secret_needed(data, secrets, KEY_PSK, opt_reprompt)};
        fields[nfields++] = (struct field){
            KEY_PASSWORD, "Password:", pw,
            have_user && secret_needed(data, secrets, KEY_PASSWORD, opt_reprompt)};
    }

    gboolean any_need = FALSE;
    for (int i = 0; i < nfields; i++)
        any_need = any_need || fields[i].need;

    /* Prompt only if something is missing and NM permits interaction. */
    if (any_need && opt_interaction && gtk_init_check(&argc, &argv)) {
        GtkWidget *dlg = nma_vpn_password_dialog_new(
            "Authenticate VPN", "Enter the veepin VPN credentials.", NULL);
        NMAVpnPasswordDialog *pd = NMA_VPN_PASSWORD_DIALOG(dlg);

        /* Assign the needed secrets to the primary/secondary fields in order. */
        int primary = -1, secondary = -1;
        nma_vpn_password_dialog_set_show_password(pd, FALSE);
        nma_vpn_password_dialog_set_show_password_secondary(pd, FALSE);
        for (int i = 0; i < nfields; i++) {
            if (!fields[i].need)
                continue;
            if (primary < 0) {
                primary = i;
                nma_vpn_password_dialog_set_show_password(pd, TRUE);
                nma_vpn_password_dialog_set_password_label(pd, fields[i].label);
                if (fields[i].cur)
                    nma_vpn_password_dialog_set_password(pd, fields[i].cur);
            } else if (secondary < 0) {
                secondary = i;
                nma_vpn_password_dialog_set_show_password_secondary(pd, TRUE);
                nma_vpn_password_dialog_set_password_secondary_label(pd, fields[i].label);
                if (fields[i].cur)
                    nma_vpn_password_dialog_set_password_secondary(pd, fields[i].cur);
            }
        }

        if (!nma_vpn_password_dialog_run_and_block(pd)) {
            gtk_widget_destroy(dlg);
            return 1; /* user cancelled */
        }
        if (primary >= 0)
            fields[primary].cur = g_strdup(nma_vpn_password_dialog_get_password(pd));
        if (secondary >= 0)
            fields[secondary].cur = g_strdup(nma_vpn_password_dialog_get_password_secondary(pd));
        gtk_widget_destroy(dlg);
    }

    /* Emit the secrets NM asked about, terminated by a blank line. */
    for (int i = 0; i < nfields; i++)
        emit_secret(fields[i].key, fields[i].cur);
    printf("\n");
    fflush(stdout);

    wait_for_quit();

    g_hash_table_unref(data);
    g_hash_table_unref(secrets);
    return 0;
}
