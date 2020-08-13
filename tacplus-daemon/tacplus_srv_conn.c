/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "tacplus_srv_conn.h"
#include "dbus_service.h"
#include "statistics.h"
#include "parser.h"



static bool
tacplus_server_remaining_hold_down_at(const struct tacplus_options_server *server,
									  const struct timespec *cur_time,
									  struct timespec *remaining)
{
	struct timespec expires;

	if (remaining)
		SET_TIMESPEC_VALS(*remaining, 0, 0);

	/* Hold down disabled */
	if (server->state.activeHoldDown == 0)
		return false;

	/* No trouble seen */
	if (TIMESPEC_VALS_EQ(server->state.lastTrouble, -1, -1))
		return false;

	/* Clock shift - not much to do other than expire the timer */
	if (timespec_cmp(cur_time, &server->state.lastTrouble) < 0)
		return false;

	expires = server->state.lastTrouble;
	expires.tv_sec += server->state.activeHoldDown;

	if (timespec_cmp(cur_time, &expires) >= 0)
		return false;

	if (remaining)
		timespec_sub(&expires, cur_time, remaining);

	return true;
}

bool
tacplus_server_remaining_hold_down(const struct tacplus_options_server *server,
								   struct timespec *remaining)
{
	struct timespec cur_time;

	cur_mono_time(&cur_time);
	return tacplus_server_remaining_hold_down_at(server, &cur_time, remaining);
}

time_t
tacplus_server_remaining_hold_down_secs(const struct tacplus_options_server *server)
{
	struct timespec remaining;

	tacplus_server_remaining_hold_down(server, &remaining);
	return timespec_nearest_sec(&remaining);
}

bool
tacplus_server_is_held_down(const struct tacplus_options_server *server)
{
	return tacplus_server_remaining_hold_down(server, NULL);
}

void
tacplus_server_activate_hold_down(struct tacplus_options_server *server)
{
	if (server->hold_down) {
		char *addr_str = addrinfo_to_string(server->addrs);

		syslog(LOG_DEBUG, "Hold down timer started on %s for %us",
			   strOrNil(addr_str), server->hold_down);
		free(addr_str);
	}

	server->state.activeHoldDown = server->hold_down;
	cur_mono_time(&server->state.lastTrouble);
}

void
tacplus_server_reset_hold_down(struct tacplus_options_server *server)
{
	SET_TIMESPEC_VALS(server->state.lastTrouble, -1, -1);
}

static
bool tacplus_connect_ith(
#ifdef HAVE_LIBTAC_EVENT
						 struct tac_session *sess,
#endif
						 unsigned i)
{
	struct tacplus_options *opts = connControl->opts;
	struct tacplus_options_server *server = tacplus_server(opts, i);
	int timeout;
	char *dest_addr_str = NULL;
	char *src_addr_str = NULL;
	struct addrinfo *addr, *src_addr = NULL;
	bool success = false;

	addr = server->addrs;

	dest_addr_str = addrinfo_to_string(addr);

	if (server->src_addrs)
		src_addr = server->src_addrs;
	else if (server->src_intf) {
		int if_up = is_interface_up(server->src_intf);
		switch (if_up) {
			case 1:
				break;
			case 0:
				syslog(LOG_DEBUG, "Source interface %s is not up",
					   server->src_intf);
				/* fall through */
			default:
				goto fail;
		}

		src_addr = get_interface_addrinfo(server->src_intf, addr->ai_family);
		if (! src_addr)
			goto fail;
	}

#ifdef HAVE_LIBTAC_EVENT
	timeout = opts->setupTimeout;
#else
	timeout = server->timeout;
#endif

	syslog(LOG_DEBUG, "Opening TCP connection to [%u] %s:%d "
			"using timeout of %d second(s)",
			i, strOrNil(dest_addr_str), get_addrinfo_port(addr),
			timeout);

	if (src_addr) {
		src_addr_str = addrinfo_to_string(src_addr);
		syslog(LOG_DEBUG, "Using source address: %s", strOrNil(src_addr_str));
		free(src_addr_str);
		src_addr_str = NULL;
	}

#ifdef HAVE_LIBTAC_EVENT
	success = tac_connect_single_ev(sess, connControl->tac_event,
									server->addrs, src_addr, timeout);
#else
	int fd = tac_connect_single(addr, server->secret, src_addr, timeout);
	success = fd > 0 ? true : false;

	server->fd = success ? fd : -1;
#endif

	if (server->src_intf)
		free_interface_addrinfo(&src_addr);

	if (!success) {
fail:
		syslog(LOG_DEBUG, "Failed to connect to %s",
			strOrNil(dest_addr_str));
		inc_failed_connects(i);

		tacplus_server_activate_hold_down(tacplus_server(opts, i));

		free(dest_addr_str);
		dest_addr_str = NULL;
		return false;
	}

#ifdef HAVE_LIBTAC_EVENT
	tac_session_set_oob(sess, oob_callback);
	tac_session_set_response(sess, response_callback);

	/* In all releases so far we used "login' as authentication type. */
	/* TODO: consider to make this configurable in future */
	tac_session_set_authen_type(sess, TAC_PLUS_AUTHEN_TYPE_ASCII);

	tac_session_set_secret(sess, server->secret);
	tac_session_set_timeout(sess, server->timeout);

	/* need to store index of opts->server[] into tac_session */
	struct tac_session_extra *extra = tac_session_get_user_data(sess);
	extra->server_id = i;
	extra->server = server;
	extra->state = UNINITIALIZED;

	server->session = sess;
#endif

	syslog(LOG_DEBUG, "TCP connection to %s successfully opened",
		strOrNil(dest_addr_str));
	free(dest_addr_str);

	return true;
}

static inline void
tacplus_set_active_server(struct tacplus_options *opts,
						  const struct tacplus_options_server *server)
{
	opts->curr_server = server->id;
}

static inline void
tacplus_clear_active_server(struct tacplus_options *opts)
{
	opts->curr_server = INVALID_SERVER_ID;
}

static inline bool
tacplus_have_active_server(const struct tacplus_options *opts)
{
	return opts->curr_server < opts->n_servers ? true : false;
}

static inline void
tacplus_set_next_server(struct tacplus_options *opts,
						const struct tacplus_options_server *server)
{
	opts->next_server = server->id;
}

static inline void
tacplus_clear_next_server(struct tacplus_options *opts)
{
	opts->next_server = INVALID_SERVER_ID;
}

static inline bool
tacplus_have_next_server(const struct tacplus_options *opts)
{
	return opts->next_server < opts->n_servers ? true : false;
}

/*
 * This is a somewhat limited use function, designed for initialising an
 * iteration counter used for looping over the server list - see tacplus_connect()
 */
static unsigned
tacplus_get_server_list_pos(struct tacplus_options *opts)
{
	/*
	 * If the next expiring, and higher priority, server's hold down timer has
	 * expired then start from the beginning of the server list. This allows us
	 * to choose the highest priority server which is available and updates
	 * next_server if necessary (during the connection loop routine).
	 */
	if (tacplus_have_next_server(opts) &&
		(! tacplus_server_is_held_down(tacplus_server(opts, opts->next_server)))) {
		tacplus_clear_next_server(opts);
		return HIGHEST_PRIO_SERVER_ID;
	}
	/*
	 * Otherwise if there is no active server then all servers are held down
	 * and there is no need to iterate the server list.
	 *
	 * In this condition there *should* always be a next_server set, if there
	 * isn't then we simply iterate from the highest priority server.
	 */
	else if (! tacplus_have_active_server(opts)) {
		if (! tacplus_have_next_server(opts)) {
			syslog(LOG_DEBUG, "No active server and no next server");
			return HIGHEST_PRIO_SERVER_ID;
		}

		return INVALID_SERVER_ID;
	}

	/*
	 * Otherwise if there isn't a higher priority server whose hold down timer
	 * has expired then start iterating the server list from the last used
	 * (active) server.
	 */
	return opts->curr_server;
}

static void
tacplus_update_next_server(struct tacplus_options *opts,
						   const struct tacplus_options_server *server)
{
	struct timespec cur_time, remaining, next_remaining;

	if (! tacplus_have_next_server(opts)) {
		tacplus_set_next_server(opts, server);
		return;
	}

	cur_mono_time(&cur_time);
	tacplus_server_remaining_hold_down_at(server, &cur_time, &remaining);
	tacplus_server_remaining_hold_down_at(tacplus_server(opts, opts->next_server),
										  &cur_time, &next_remaining);

	if (timespec_cmp(&remaining, &next_remaining) < 0)
		tacplus_set_next_server(opts, server);
}

#ifdef HAVE_LIBTAC_EVENT
unsigned tacplus_connect_all(void)
{
	struct tacplus_options *opts = connControl->opts;
	unsigned tries, i, successes;
	struct tac_session *sess;

	syslog(LOG_DEBUG, "Number of servers in config: %d", opts->n_servers);

	sess = tac_session_alloc_extra(sizeof(struct tac_session_extra));

	for (successes = tries = 0, i = opts->curr_server; tries < opts->n_servers; tries++) {
		i = (i + 1) % opts->n_servers;

		if (opts->server[i].session)
			continue;

		if (! tacplus_server_is_held_down(tacplus_server(opts, i)) &&
			tacplus_connect_ith(sess, i)) {
			successes++;
			sess = tac_session_alloc_extra(sizeof(struct tac_session_extra));
		}
	}

	/* the last one will always be unused */
	tac_session_free(sess);

	return successes;
}
#endif

static bool
go_offline(struct tacplus_options *opts, bool use_offline_timer)
{
	struct itimerspec it = {};
	struct timespec *ts = &it.it_value;
	offline_mode_t mode;

	/*
	 * If an offline timer has been configured, and it is to be used, then
	 * the mode is always OFFLINE_EXPLICIT even if the calculated offline period
	 * is the time until the soonest expiring hold down timer.
	 */
	if (use_offline_timer && opts->offlineTimer)
		mode = OFFLINE_EXPLICIT;
	else
		mode = OFFLINE_HOLD_DOWN;

	if (tacplus_have_next_server(opts))
		tacplus_server_remaining_hold_down(
			tacplus_server(opts, opts->next_server), ts);

	if (use_offline_timer && opts->offlineTimer > ts->tv_sec)
		SET_TIMESPEC_VALS(*ts, opts->offlineTimer, 0);

	if (TIMESPEC_VALS_EQ(*ts, 0, 0))
		return false;

	syslog(LOG_DEBUG, "Setting offline timer for %lis %lins", ts->tv_sec, ts->tv_nsec);

	tacplus_clear_active_server(opts);
	return tacplusd_go_offline(ts, mode);
}

bool
go_offline_until_next_hold_down_expiry(struct tacplus_options *opts)
{
	return go_offline(opts, false);
}

bool tacplus_connect(void)
{
	static bool last_connect_failed;
	struct tacplus_options *opts = connControl->opts;
	bool all_servers_held_down = true;
	unsigned i;

	syslog(LOG_DEBUG, "Number of servers in config: %d", opts->n_servers);
	if (! opts->n_servers)
		return false;

	/* If we are offline there is no point continuing */
	if (! tacplusd_online()) {
		syslog(LOG_INFO, "TACACS+ component offline");
		goto fail;
	}

#ifdef HAVE_LIBTAC_EVENT
	struct tac_session *sess;

	/* if the connection is already up and multiplexed, re-use it */
	i = opts->curr_server;
	if (opts->server[i].session) {
		sess = opts->server[i].session;
		if (sess->tac_multiplex)
			return true;
	}

	sess = tac_session_alloc_extra(sizeof(struct tac_session_extra));
#endif

	for (i = tacplus_get_server_list_pos(opts); i < opts->n_servers; i++) {
		if (! tacplus_server_is_held_down(tacplus_server(opts, i)) &&
#ifdef HAVE_LIBTAC_EVENT
			tacplus_connect_ith(sess, i)
#else
			tacplus_connect_ith(i)
#endif
		)
		{
			if (last_connect_failed) {
				char *serv_addr = addrinfo_to_string(tacplus_server(opts, i)->addrs);
				syslog(LOG_NOTICE, "Successfully connected to TACACS+ server at "
								   "%s following failure(s)", strOrNil(serv_addr));
				free(serv_addr);
			}

			tacplus_set_active_server(opts, tacplus_server(opts, i));
			last_connect_failed = false;
			return true;
		}

		if (! tacplus_server_is_held_down(tacplus_server(opts, i))) {
			if (all_servers_held_down)
				tacplus_set_active_server(opts, tacplus_server(opts, i));

			all_servers_held_down = false;
		}

		tacplus_update_next_server(opts, tacplus_server(opts, i));
	}

	go_offline(opts, true);

#ifdef HAVE_LIBTAC_EVENT
	tac_session_free(sess);
#endif

	if (all_servers_held_down)
		syslog(LOG_WARNING, "All servers have active hold down timers");

fail:
	last_connect_failed = true;
	return false;
}

#ifdef HAVE_LIBTAC_EVENT
void tacplus_session_close(struct tac_session *sess)
{
	struct tac_session_extra *extra = (struct tac_session_extra *)tac_session_get_user_data(sess);

	connControl->opts->server[extra->server_id].session = NULL;

	/* not strictly necessary but useful for debugging... */
	extra->server = NULL;

	tac_session_free(sess);
}
#else
void tacplus_close()
{
	struct tac_session_extra extra = {};

	tacplus_current_session_extra (connControl->opts, &extra);
	if (extra.server && extra.server->fd >= 0) {
		close(extra.server->fd);
		extra.server->fd = -1;
	}
}
#endif

static struct tacplus_options_server *
tacplus_lookup_server_by_addr(struct tacplus_options *opts,
							  const struct sockaddr *saddr)
{
	struct tacplus_options_server *server;
	unsigned i;

	for (i = 0; i < opts->n_servers; i++) {
		server = tacplus_server(opts, i);

		if (sockaddr_addr_equal(server->addrs->ai_addr, saddr))
			return server;
	}

	return NULL;
}

void
tacplus_copy_server_state(struct tacplus_options *from_opts,
						  struct tacplus_options *to_opts)
{
	struct tacplus_options_server *new_server, *existing_server;
	unsigned i;

	assert(from_opts != to_opts);

	for (i = 0; i < to_opts->n_servers; i++) {
		new_server = tacplus_server(to_opts, i);
		existing_server = tacplus_lookup_server_by_addr(
							from_opts, new_server->addrs->ai_addr);
		if (! existing_server)
			continue;

		new_server->state = existing_server->state;

		/*
		 * If the existing server did not have a hold down timer configured
		 * then ensure all hold down state is cleared on the new server
		 */
		if (existing_server->state.activeHoldDown == 0)
			tacplus_server_reset_hold_down(new_server);
	}
}

struct tacplus_options *tacplus_options_alloc(unsigned n)
{
	struct tacplus_options *ret = NULL;

	ret = calloc(1, sizeof(*ret) + (n * sizeof(ret->server[0])));
	ret->n_servers = n;

	for (unsigned i = 0; i < n; i++) {
#ifndef HAVE_LIBTAC_EVENT
		ret->server[i].fd = -1;
#endif
		tacplus_server_reset_hold_down(&ret->server[i]);
	}

	return ret;
}

struct tacplus_options *tacplus_parse_options(const char *file)
{
	struct tacplus_options *opts = NULL;

	read_config(file, &opts);
	return opts;
}

struct tacplus_options *tacplus_parse_reload_options(const char *file,
													 struct tacplus_options **cur_opts)
{
	struct tacplus_options *opts = tacplus_parse_options(file);

	if (cur_opts && *cur_opts)
		tacplus_reload_options(cur_opts, opts);

	return opts;
}

struct tacplus_options *tacplus_reload_options(struct tacplus_options **cur_opts,
											   struct tacplus_options *new_opts)
{
	if (new_opts) {
		tacplus_copy_server_state(*cur_opts, new_opts);

		/* If an explicit offline timer was configured we do nothing and let it run */
		if (! tacplusd_online() && connControl->state.offline_mode == OFFLINE_EXPLICIT)
			goto finish;

		/* Now we have the server state populate the active and next server IDs */
		tacplus_clear_active_server(new_opts);
		TACPLUS_SERVER_LOOP(new_opts, serv) {
			/*
			 * Changes to per-server hold down timers *are* effected on a
			 * reload, therefore update activeHoldDown. This must be done
			 * before calling tacplus_server_is_held_down().
			 */
			serv->state.activeHoldDown = serv->hold_down;

			if (tacplus_server_is_held_down(serv))
				tacplus_update_next_server(new_opts, serv);
			else if (! tacplus_have_active_server(new_opts))
				tacplus_set_active_server(new_opts, serv);
		}

		/*
		 * If we are currently offline then check to see if we can come back
		 * online. This is indicated by the presence of an "active" server.
		 * Otherwise we go (remain) offline based upon our current state
		 * and the new options.
		 */
		if (! tacplusd_online()) {
			if (tacplus_have_active_server(new_opts))
				tacplusd_go_online();
			else {
				/*
				 * Changes to the offline timer value are not effected
				 * on a reload, so only take hold down timers into account
				 * when re-calculating the offline period.
				 */
				go_offline_until_next_hold_down_expiry(new_opts);
			}
		}
	}

finish:
	cleanup_tacplus_options(cur_opts);
	return new_opts;
}

void cleanup_tacplus_options(struct tacplus_options **opts)
{
	if (! opts || ! *opts)
		return;

	TACPLUS_SERVER_LOOP(*opts, serv) {
		freeaddrinfo(serv->addrs);
		freeaddrinfo(serv->src_addrs);
		free((char *)serv->src_intf);
		free((char *)serv->secret);
	}

	free(*opts);
	*opts = NULL;
}
