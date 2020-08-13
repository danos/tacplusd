/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019-2020, AT&T Intellectual Property

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct tacplus_global_state {
	/* Lock to be held while manipulating global state */
	pthread_mutex_t lock;

	/* ID of the offline expiry timer returned from timer_create() */
	timer_t offline_timer;

	/* Internal timer ID used to detect expiry races */
	uint8_t offline_timer_id;

	/* Flag indicating whether the component is offline */
	bool offline;
};

typedef struct {
	struct tacplus_options *opts;
	struct tacplus_global_state state;
} ConnectionControl;

extern ConnectionControl *connControl;

bool tacplusd_go_online();
bool tacplusd_go_offline(const struct timespec *);
bool tacplusd_online();
