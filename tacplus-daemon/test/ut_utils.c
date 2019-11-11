/*
	Copyright (c) 2018-2019 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "ut_utils.h"

int *_tac_connect_fds = NULL;
int _tac_connect_fds_len = 0;

struct tac_connect_call *_tac_connect_calls = NULL;
int _tac_connect_call_count = 0;

struct timespec _cur_time = { 0, 0 };

struct timespec _offline_until = { 0, 0 };
