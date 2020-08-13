/*
	Copyright (c) 2018-2020 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <assert.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "utils.h"
#include "global.h"

#define ARRAY_SIZE(A) (sizeof(A)/sizeof(A[0]))

extern int *_tac_connect_fds;
extern int _tac_connect_fds_len;

struct tac_connect_call {
	struct sockaddr server_addr;
	struct sockaddr source_addr;
	const char *key;
	int timeout;
};

extern struct tac_connect_call *_tac_connect_calls;
extern int _tac_connect_call_count;

bool
ut_tac_connect_call_eq(struct tac_connect_call *a, struct tac_connect_call *b)
{
	if (a->timeout != b->timeout)
		return false;

	if (a->key && b->key) {
		if (strcmp(a->key, b->key) != 0)
			return false;
	}
	else if (! (!a->key && !b->key)) {
		return false;
	}

	if (memcmp(&a->server_addr, &b->server_addr, sizeof a->server_addr))
		return false;

	if (memcmp(&a->source_addr, &b->source_addr, sizeof a->source_addr))
		return false;

	return true;
}

void
ut_reset_tac_connect_wrapper()
{
	for (int i = 0; i < _tac_connect_fds_len; i++)
		free((void *)_tac_connect_calls[i].key);

	free(_tac_connect_calls);
	_tac_connect_calls = NULL;
	_tac_connect_call_count = 0;

	_tac_connect_fds = NULL;
	_tac_connect_fds_len = 0;
}

void
ut_set_tac_connect_fds(int *fds, int fds_len)
{
	_tac_connect_fds = fds;
	_tac_connect_fds_len = fds_len;

	assert(! _tac_connect_calls);
	_tac_connect_calls = (struct tac_connect_call *) calloc(_tac_connect_fds_len,
															sizeof(struct tac_connect_call));
	assert(_tac_connect_calls);
}

int
ut_get_tac_connect_calls(struct tac_connect_call **calls)
{
	*calls = _tac_connect_calls;
	return _tac_connect_call_count;
}

/*
 * Wrapper function for tac_connect_single()
 *
 * Use ut_set_tac_connect_fds() to set an array of return values for this
 * function.
 *
 * Use ut_get_tac_connect_calls() to retrieve an array of tac_connect_call
 * structs with the arguments from each call to tac_connect_single().
 */
int
__wrap_tac_connect_single(const struct addrinfo *server,
						  const char *key,
						  struct addrinfo *srcaddr,
						  int timeout)
{
	if (! _tac_connect_fds)
		return 9999;

	assert(_tac_connect_call_count < _tac_connect_fds_len);

	struct tac_connect_call *call = &_tac_connect_calls[_tac_connect_call_count];
	if (server)
		call->server_addr = *server->ai_addr;

	if (srcaddr)
		call->source_addr = *srcaddr->ai_addr;

	call->key = key ? strdup(key) : NULL;
	call->timeout = timeout;

	return _tac_connect_fds[_tac_connect_call_count++];
}

#define CHECK_TIMESPEC_VALS(T,S,N) \
	{                              \
		LONGS_EQUAL(S, T.tv_sec);  \
		LONGS_EQUAL(N, T.tv_nsec); \
	}

extern struct timespec _cur_time;

void
__wrap_cur_mono_time(struct timespec *ts)
{
    *ts = _cur_time;
}

void
ut_set_cur_mono_time(time_t sec, long nsec)
{
    _cur_time.tv_sec = sec;
    _cur_time.tv_nsec = nsec;
}

void
ut_inc_cur_mono_time(time_t sec, long nsec)
{
    ut_set_cur_mono_time(_cur_time.tv_sec + sec,
						 _cur_time.tv_nsec + nsec);
}

/*
 * Wrapper around the online/offline APIs
 *
 * Piggybacking on the simulated UT "time" (_cur_time) gives a simple mechanism
 * to simulate the service going on and offline in UTs.
 *
 * Upon request to go offline we store the "time" we expect to go back online
 * ie. the current UT "time" plus the offline interval.
 *
 * Conversely on a request to go online we store the current UT "time".
 *
 * To determine whether we are on or offline we then simply check whether
 * the current UT "time" is past the stored time (ie. when we expected to be
 * offline until).
 */
extern struct timespec _offline_until;

bool
__wrap_tacplusd_go_online() {
	_offline_until = _cur_time;
	return true;
}

bool
__wrap_tacplusd_go_offline(const struct timespec *ts, offline_mode_t mode) {
	struct timespec ts_copy = *ts;
	timespec_normalise(&ts_copy);

	assert(!TIMESPEC_VALS_EQ(ts_copy, 0, 0));

	_offline_until = _cur_time;
	timespec_normalise(&_offline_until);

	_offline_until.tv_sec += ts_copy.tv_sec;
	_offline_until.tv_nsec += ts_copy.tv_nsec;
	timespec_normalise(&_offline_until);

	connControl->state.offline_mode = mode;

	return true;
}

bool
__wrap_tacplusd_online() {
	return timespec_cmp(&_cur_time, &_offline_until) >= 0;
}
