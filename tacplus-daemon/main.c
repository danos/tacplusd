/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020, AT&T Intellectual Property.
	Copyright (c) 2015 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <pthread.h>

#include "global.h"
#include "main.h"
#include "statistics.h"
#include "tacplus_srv_conn.h"

/*
 * TODO
 * add license to all source files
 */

static int run = 1; /* Initially to enter while loop */
static int reload = 0;

static ConnectionControl _connControl = { .state = { .offline = false } };
ConnectionControl *connControl = &_connControl;

static void signal_wait(sigset_t *set)
{
	int s, sig;

	for (;;) {
		s = sigwait(set, &sig);
		if (s != 0) {
			syslog(LOG_ERR, "Signal handler sigwait() call returned error");
		}
		syslog(LOG_DEBUG, "Signal handler received: %d\n", sig);
		switch(sig) {
			case SIGTERM:
				syslog(LOG_DEBUG, "Signal handler caught SIGTERM");
				run = 0;
				return;

			case SIGHUP:
				syslog(LOG_DEBUG, "Signal handler caught SIGHUP");
				reload = 1;
				return;

			default:
				syslog(LOG_DEBUG, "Ignoring signal %d", sig);
				break;
		}
	}
}

static int setup_service(const char *tacplus_cfg)
{
	int ret = 0;

	/* enable read timeout handling */
	tac_enable_readtimeout(1);

#ifndef HAVE_LIBTAC_EVENT
	/* libtac by default uses PAP auth method. tac_login is a global/extern variable of libtac */
	strncpy(tac_login, "login", 5);
#endif

	connControl->opts = tacplus_parse_reload_options(tacplus_cfg,
													 &connControl->opts);
	if(connControl->opts == NULL) {
		syslog(LOG_NOTICE, "No valid configuration");
		ret = -1;
		goto done;
	}

	/* Set global DSCP marking in libtac library */
	tac_set_dscp(connControl->opts->dscp);

	syslog(LOG_INFO, "Configuration loaded successfully");

	ret = create_statistics(connControl->opts->n_servers);
	if(ret != 0) {
		syslog(LOG_ERR, "Failed to allocate statistics");
		goto done;
	}
	syslog(LOG_DEBUG, "Statistics allocated successfully");

done:
	return ret;
}

static int reload_service(const char *tacplus_cfg)
{
	int ret;

	reload = 0;
	syslog(LOG_NOTICE, "Reloading");
	dbus_service_pause();

	free_statistics();
	ret = setup_service(tacplus_cfg);

	ret |= dbus_service_resume();
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	sigset_t set;
	char *tacplus_cfg;
	char *tacplus_pid;

	if (argc == 2 || argc == 3) {
		tacplus_cfg = argv[1];
		tacplus_pid = argc == 3 ? argv[2] : NULL;
	}
	else {
		fprintf(stderr, "Insufficient arguments to the daemon\n");
		return -1;
	}

	if (getenv("DEBUG"))
		tac_debug_enable = 1;

	if (!getenv("NODAEMON")) {
		openlog("tacplusd", LOG_ODELAY, LOG_AUTH);

		if (tacplus_pid)
			daemonize(tacplus_pid);
	}
	else
		openlog("tacplusd", LOG_PERROR, LOG_AUTH);

	/* from this point onwards, we're the child */
	syslog(LOG_NOTICE, "Tacplusd daemonized successfully");
	syslog(LOG_DEBUG, "Tacplusd started with %s\n", tacplus_cfg);

	sigemptyset(&set);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGKILL);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGHUP);

	ret = pthread_sigmask(SIG_BLOCK, &set, NULL);

	if (ret != 0) {
		syslog(LOG_ERR, "Blocking signals failed");
		goto done;
	}

	pthread_mutex_init(&connControl->state.lock, NULL);

	dbus_service_init();

	if (setup_service(tacplus_cfg) != 0) {
		ret = -1;
		goto done;
	}

	if (dbus_service_start() < 0) {
		syslog(LOG_ERR, "Failed to start DBus service");
		ret = -1;
		goto done;
	}
	syslog(LOG_DEBUG, "DBus service setup successful");

	/* Send an offline state change signal to indicate we have started up */
	signal_offline_state_change();

	while (run) {
		if (reload && (ret = reload_service(tacplus_cfg)) != 0)
			goto done;

		signal_wait(&set);

		ret = dbus_service_failed() ? 1 : 0;
	}

done:
	syslog(LOG_NOTICE, "Stopping");

	dbus_service_stop();
	dbus_service_wait();
	dbus_service_deinit();

	free_statistics();
	cleanup_tacplus_options(&connControl->opts);

	syslog(LOG_NOTICE, "Shutting down");
	return ret;
}
