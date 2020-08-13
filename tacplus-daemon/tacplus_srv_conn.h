/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef TACPLUS_SRV_CONN_H
#define TACPLUS_SRV_CONN_H

#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <libtac.h>

#include "utils.h"

struct tacplus_options_server;

struct tac_session_extra {
	unsigned server_id;
	struct tacplus_options_server *server;
#ifdef HAVE_LIBTAC_EVENT
	session_event_t state;
#endif
};

struct tacplus_options
{
	unsigned n_servers, curr_server, next_server;
	bool broadcast;
	uint8_t dscp;
	unsigned setupTimeout, offlineTimer;
	struct tacplus_options_server {
		unsigned id;
		struct addrinfo *addrs;
		struct addrinfo *src_addrs;
		const char *src_intf;
		int timeout;
		unsigned hold_down;
		const char *secret;
#ifdef HAVE_LIBTAC_EVENT
		struct tac_session *session;
#else
		int fd;
#endif
		struct tacplus_server_state {
			struct timespec lastTrouble;
			unsigned activeHoldDown;
			struct timespec lastHoldDownReset;
		} state;
	} server[0];
};

#define HIGHEST_PRIO_SERVER_ID 0
#define INVALID_SERVER_ID	   (TACPLUS_MAX_SERVERS + 1)

#define TACPLUS_SERVER_LOOP(O,S)						\
	struct tacplus_options_server *S;					\
	for (unsigned _i = 0; _i < (O)->n_servers; _i++)	\
		if ((S = tacplus_server((O), _i)))

struct tacplus_options *tacplus_options_alloc(unsigned n);

static inline
struct tacplus_options_server *tacplus_server(struct tacplus_options *opts, unsigned i)
{
	return i >= opts->n_servers ? NULL : (struct tacplus_options_server *)&opts->server[i];
}

#ifndef HAVE_LIBTAC_EVENT
static inline
struct tacplus_options_server *tacplus_current_server(struct tacplus_options *opts)
{
	return tacplus_server(opts, opts->curr_server);
}

/*
 * Populate a tac_session_extra structure with the details of the currently
 * active server.
 *
 * This reduces the amount of ifdef'd code required to support both event-driven
 * and non-event-driven libtac implementations.
 */
static inline
struct tac_session_extra *tacplus_current_session_extra(struct tacplus_options *opts,
														struct tac_session_extra *extra)
{
	if (extra) {
		extra->server_id = opts->curr_server;
		extra->server = tacplus_current_server(opts);
	}

	return extra;
}
#else
static inline
struct tac_session *tacplus_session(struct tacplus_options *opts)
{
	if (opts->n_servers > 0)
		return opts->server[opts->curr_server].session;
	else
		return NULL;
}
#endif

bool tacplus_connect(void);
unsigned tacplus_connect_all(void);

struct tacplus_options *tacplus_parse_options(const char *);

struct tacplus_options *tacplus_parse_reload_options(const char *file,
													 struct tacplus_options **cur_opts);

struct tacplus_options *tacplus_reload_options(struct tacplus_options **cur_opts,
											   struct tacplus_options *new_opts);

#ifdef HAVE_LIBTAC_EVENT
void tacplus_session_close(struct tac_session *);
#else
void tacplus_close();
#endif

void cleanup_tacplus_options(struct tacplus_options **);

bool
tacplus_server_remaining_hold_down(const struct tacplus_options_server *server,
								   struct timespec *remaining);

time_t
tacplus_server_remaining_hold_down_secs(const struct tacplus_options_server *server);

bool
tacplus_server_is_held_down(const struct tacplus_options_server *server);

void
tacplus_server_activate_hold_down(struct tacplus_options_server *server);

void
tacplus_server_reset_hold_down(struct tacplus_options_server *server);

void
tacplus_copy_server_state(struct tacplus_options *from_opts,
						  struct tacplus_options *to_opts);

#endif /* TACPLUS_SRV_CONN_H */
