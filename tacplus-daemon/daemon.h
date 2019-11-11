/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>

/* prototypes */
extern void daemonize(const char *tacplus_pid);

