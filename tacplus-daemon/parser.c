/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <assert.h>
#include <glib.h>
#include <netinet/ip.h>
#include <stdbool.h>

#include "parser.h"
#include "utils.h"

/* TODO: set max config size 
 *       header file
 *       make more versatile/flexible
 */

static const char *s_general = "general";
static const char *s_options = "options";

static inline
void g_syslog(int priority, const char *fmt, GError **e)
{
	syslog(priority, fmt, (*e)->message);
	g_error_free(*e);
	*e = NULL;
}

static inline
void sa_set_port(struct sockaddr *sa, ushort port)
{
	if (!sa) {
		syslog(LOG_CRIT, "sa should never be NULL");
		exit(1);
	}

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;
		sin->sin_port = htons(port);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
		sin6->sin6_port = htons(port);
	}
}

static
bool isReservedSection(const char *name)
{
	return (!strcmp(name, s_general) || !strcmp(name, s_options));
}

void read_config(const char *f_name, struct tacplus_options **opts)
{
	GKeyFile *keyfile;
	GKeyFileFlags flags;
	GError *error = NULL;
	gsize length;
	const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_NUMERICHOST,
	};
	struct connection conn[TACPLUS_MAX_SERVERS];
	unsigned nservers, setupTimeout;
	int dscp;
	unsigned i, j;

	nservers = 0;

	/* initialize key file */
	keyfile = g_key_file_new();
	flags = G_KEY_FILE_NONE;

	if (!g_key_file_load_from_file(keyfile, f_name, flags, &error)) {
		g_syslog(LOG_ERR, "config file open: %s", &error);
		g_key_file_free(keyfile);
		return;
	}

	/* get the names of sections; any section that doesn't have
	 * a reserved name is assumed to be a server configuration.
	 */

	char **sections = g_key_file_get_groups(keyfile, &length);

	/* any global options would be handled here from the
	 * 'general' section
	 */

	gboolean broadcast = g_key_file_get_boolean(keyfile, s_general, "BroadcastAccounting", &error);
	if (error) {
		g_syslog(LOG_ERR, "parse BroadcastAccounting option: %s", &error);
		goto cleanup2;
	}

#ifndef HAVE_LIBTAC_EVENT
	if (broadcast) {
		syslog(LOG_ERR, "Cannot enable unsupported BroadcastAccounting option");
		broadcast = false;
	}
#endif

	setupTimeout = g_key_file_get_integer(keyfile, s_general, "SetupTimeout", &error);
	if (error) {
		g_syslog(LOG_ERR, "parse SetupTimeout option: %s", &error);
		goto cleanup2;
	}
	if (setupTimeout <= 0) {
		syslog(LOG_ERR, "parse SetupTimeout option must be higher than 0.\n");
		goto cleanup2;
	}

	dscp = g_key_file_get_integer(keyfile, s_general, "Dscp", &error);
	if (error) {
		if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
			g_syslog(LOG_ERR, "parse Dscp option: %s", &error);
			goto cleanup2;
		}
		dscp = IPTOS_CLASS_CS6;
		g_error_free(error);
		error = NULL;
	} else if (dscp < 0 || dscp > 63) {
		syslog(LOG_ERR, "Dscp value must be in the range <0-63>");
		goto cleanup2;
	} else {
		// The two least significant bits are used for ECN
		dscp <<= 2;
	}

	for (i = j = 0; i < length; ++i) {
		int hold_down, port, timeout, err;
		gchar *gsecret, *addr, *src_addr, *gsrc_intf;
		struct addrinfo *ai, *pai, *sai;
		gchar *server = sections[i];
		const char *secret, *src_intf;
		bool valid = true;

		if (isReservedSection(server))
			continue;

		/* Clear variables which may be set from previous iterations */
		error = NULL;
		ai = pai = sai = NULL;

		/* start with tuple of address and port */
		addr = g_key_file_get_string(keyfile, server, "Address", &error);
		if (error) {
			g_syslog(LOG_ERR, "parse server address: %s", &error);
			ai = NULL;
			valid = false;
		} else {
			/* ignore the port, we'll patch it in later... */
			err = getaddrinfo(addr, NULL, &hints, &ai);
			if (err != 0) {
				syslog(LOG_ERR, "parse server address: %s",
				       gai_strerror(err));
				valid = false;
			}
		}

		port = g_key_file_get_integer(keyfile, server, "Port", &error);
		if (error) {
			g_syslog(LOG_ERR, "parse port: %s", &error);
			valid = false;
		}

		/* ... then required secret and timeout. */
		gsecret = g_key_file_get_string(keyfile, server, "Secret", &error);
		if (error) {
			g_syslog(LOG_ERR, "parse secret: %s", &error);
			valid = false;
			secret = NULL;
		} else {
			/* we do this so that the special memory destruction
			 * that glib requires is confined to this module.
			 */
			secret = strdup(gsecret);
			if (! secret) {
				syslog(LOG_CRIT, "tacplus secret allocation fail: out-of-memory");
				valid = false;
			}
			g_free(gsecret);
		}

		timeout = g_key_file_get_integer(keyfile, server, "Timeout", &error);
		if (error) {
			g_syslog(LOG_ERR, "parse timeout: %s", &error);
			valid = false;
		}

		hold_down = g_key_file_get_integer(keyfile, server, "HoldDown", &error);
		if (error) {
			g_syslog(LOG_ERR, "parse HoldDown: %s", &error);
			valid = false;
		} else if (hold_down < 0) {
			syslog(LOG_ERR, "Invalid negative HoldDown %d", hold_down);
			valid = false;
		}

		/* substitute in port # */
		for (pai = ai; pai != NULL; pai = pai->ai_next)
			/* if pai is non-NULL, then pai->ai_addr should
			 * also never be NULL...
			 */
			sa_set_port(pai->ai_addr, port);

		/* SourceAddress, which is optional... */
		src_addr = g_key_file_get_string(keyfile, server, "SourceAddress", &error);
		if (error) {
			if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
				g_syslog(LOG_ERR, "parse source address: %s", &error);
			else
				g_error_free(error);

			error = NULL;
			sai = NULL;
		} else {
			err = getaddrinfo(src_addr, "", &hints, &sai);
			if (err != 0) {
				syslog(LOG_ERR, "parse source address: %s",
				       gai_strerror(err));
				valid = false;
			}
		}

		/* Optional SourceInterface */
		gsrc_intf = g_key_file_get_string(keyfile, server, "SourceInterface", &error);
		if (error) {
			if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
				g_syslog(LOG_ERR, "parse source interface: %s", &error);
				valid = false;
			}
			else
				g_error_free(error);

			error = NULL;
			src_intf = NULL;
		} else {
			src_intf = strdup (gsrc_intf);
			if (! src_intf) {
				syslog(LOG_CRIT, "tacplus source interface allocation "
					   "fail: out-of-memory");
				valid = false;
			}
			g_free(gsrc_intf);
		}

		if (!valid)
			goto cleanup;

		if (j == TACPLUS_MAX_SERVERS) {
			syslog(LOG_WARNING,
			       "too many servers configured: ignoring %s", server);
			goto cleanup;
		}

		conn[j].addr = ai;
		conn[j].secret = secret;
		conn[j].timeout = timeout;
		conn[j].hold_down = hold_down;
		conn[j].src_addr = sai;
		conn[j].src_intf = src_intf;
		++j;

cleanup:
		g_free((char *)addr);
		g_free((char *)src_addr);

		if (valid)
			continue;

		if (ai)
			freeaddrinfo(ai);
		if (sai)
			freeaddrinfo(sai);
	}

	nservers = j;

cleanup2:
	/* release stuff... */
	g_strfreev(sections);
	g_key_file_free(keyfile);

	*opts = tacplus_options_alloc(nservers);
	if (!opts) {
		syslog(LOG_CRIT, "tacplus_options allocation fail: out-of-memory");
		exit(1);
	}

	if (!nservers)
		return;

	(*opts)->next_server = INVALID_SERVER_ID;
	(*opts)->curr_server = 0;
	(*opts)->broadcast = broadcast;
	(*opts)->dscp = dscp;
	(*opts)->setupTimeout = setupTimeout;

	for (i = 0; i < nservers; ++i) {
		(*opts)->server[i].id = i;
		(*opts)->server[i].addrs = conn[i].addr;
		(*opts)->server[i].src_addrs = conn[i].src_addr;
		(*opts)->server[i].src_intf = conn[i].src_intf;
		(*opts)->server[i].secret = conn[i].secret;
		(*opts)->server[i].timeout = conn[i].timeout;
		(*opts)->server[i].hold_down = conn[i].hold_down;
#ifdef HAVE_LIBTAC_EVENT
		(*opts)->server[i].session = NULL;
#endif
	}
}

