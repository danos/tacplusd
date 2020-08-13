/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019-2020, AT&T Intellectual Property

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <syslog.h>

#include "dbus_service.h"
#include "global.h"
#include "utils.h"

static void offline_timer_expiry_cb(__attribute__((unused)) union sigval val)
{
	int id = val.sival_int;

	syslog(LOG_DEBUG, "Offline timer %d expired", id);

	pthread_mutex_lock(&connControl->state.lock);

	/*
	 * Every time we attempt to start an offline timer we increment the
	 * offline_timer_id. The incremented value is stored ready to be passed
	 * into the callback (ie. us) at timer expiry.
	 *
	 * This allows us to detect a race condition where we (attempted to)
	 * cancel a timer just after it expired and ignore the callback.
	 */
	if (id != connControl->state.offline_timer_id) {
		pthread_mutex_unlock(&connControl->state.lock);
		syslog(LOG_DEBUG, "Stale timer - ignoring");
		return;
	}

	if (! connControl->state.offline) {
		pthread_mutex_unlock(&connControl->state.lock);
		syslog(LOG_DEBUG, "Already online");
		return;
	}

	connControl->state.offline = false;
	connControl->state.offline_timer_id = 0;
	signal_offline_state_change();

	pthread_mutex_unlock(&connControl->state.lock);

	syslog(LOG_NOTICE, "TACACS+ component back online");
}

bool tacplusd_go_online() {
	pthread_mutex_lock(&connControl->state.lock);

	if (! connControl->state.offline) {
		pthread_mutex_unlock(&connControl->state.lock);
		return true;
	}

	/* Expire the running timer to trigger an online state change */
	int ret = expire_timer(connControl->state.offline_timer);

	pthread_mutex_unlock(&connControl->state.lock);
	return ret == 0;
}

bool tacplusd_go_offline(const struct timespec *time, offline_mode_t mode) {
	struct itimerspec it = { .it_value = *time };

	if (TIMESPEC_VALS_EQ(*time, 0, 0))
		return false;

	pthread_mutex_lock(&connControl->state.lock);

	/* If we are already offline then cancel an existing timer */
	if (connControl->state.offline)
		timer_delete(connControl->state.offline_timer);

	/* Start the offline timer */
	union sigval sv = { .sival_int = ++connControl->state.offline_timer_id };
	if (new_cb_timer(&connControl->state.offline_timer,
					 offline_timer_expiry_cb, &sv) < 0) {
		pthread_mutex_unlock(&connControl->state.lock);
		return false;
	}

	if (set_timer(connControl->state.offline_timer, &it) < 0) {
		pthread_mutex_unlock(&connControl->state.lock);
		return false;
	}

	if (connControl->state.offline) {
		if (mode != connControl->state.offline_mode) {
			syslog(LOG_DEBUG, "Already offline - ignoring %d -> %d mode change",
				   connControl->state.offline_mode, mode);
		}

		pthread_mutex_unlock(&connControl->state.lock);
		return true;
	}

	/* online --> offline transition */

	/* Mode cannot change without first expiring */
	connControl->state.offline_mode = mode;

	/* If we were previously online then signal a state change */
	connControl->state.offline = true;
	signal_offline_state_change();

	pthread_mutex_unlock(&connControl->state.lock);

	syslog(LOG_WARNING, "TACACS+ component offline for %lis",
		   timespec_nearest_sec(time));
	return true;
}

bool tacplusd_online() {
	return !connControl->state.offline;
}
