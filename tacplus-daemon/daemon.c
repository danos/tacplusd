/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "daemon.h"

/* TODO
 * -use strerror_r() instead of strerror()
 */


/* TODO: Take filename from command line */
static void record_pid(const char *fname)
{
	FILE *f = fopen(fname, "w");

	if (f == NULL) {
		/* TODO: append strerr() */
		syslog(LOG_ERR, "Failed to open pid file: %s", fname);
		return;
	}

	fprintf(f, "%u\n", getpid());
	fclose(f);
}

void daemonize(const char *tacplus_pid)
{
	/* 0 returned in child */
	if (fork() != 0) {
		exit(EXIT_SUCCESS); /* parent exit */
	}

	/* Become new process group leader */
	if (setsid() < 0) {
		fprintf(stderr, "setsid() failed. Error: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Overwrite parent's cwd */
	if(chdir("/") < 0) {
		fprintf(stderr, "Changing cwd to root directory failed. Error: %s",
						   strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* Close standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Reset file permissions */
	umask(0);
	record_pid(tacplus_pid);
}

