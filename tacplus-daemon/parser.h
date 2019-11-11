/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "tacplus_srv_conn.h"
#include <syslog.h>

#define TACPLUS_MAX_SERVERS		100

struct connection {
	struct addrinfo *addr;
	const char *secret;
	int timeout;
	unsigned hold_down;
	struct addrinfo *src_addr;
	const char *src_intf;
};

void read_config(const char *, struct tacplus_options **);
