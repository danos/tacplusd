/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2019, AT&T Intellectual Property.
	Copyright (c) 2015 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef _DBUS_SERVICE_H
#define _DBUS_SERVICE_H

#include <assert.h>
#include <libtac.h>
#include <tacplus.h>
#include "tacplus_srv_conn.h"
#include "utils.h"

typedef struct tacplus_dbus_service * tacplus_dbus_service_t;

#define TACPLUS_DAEMON         "net.vyatta.tacplus"
#define TACPLUS_DAEMON_PATH    "/net/vyatta/tacplus"

/* prototypes */
extern void dbus_service_init();
extern void dbus_service_deinit();
extern int dbus_service_start();
extern void dbus_service_stop();
extern void dbus_service_pause();
extern int dbus_service_resume();
extern void dbus_service_wait();
bool dbus_service_failed();

int signal_offline_state_change();

#endif /*_DBUS_SERVICE_H */
