/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "statistics.h"

static struct statistics **stats;
static int created = 0;

int create_statistics(int n)
{
	int i;
	int ret = 0;

	if(!created) {
		stats = malloc(sizeof(*stats) * n);

		if(!stats)
			return -1;

		for(i=0; i<n ; i++) {
			stats[i] = calloc(1, sizeof(**stats));
			if(!stats[i]) {
				free_statistics();
				return -1;
			}
			created++;
		}
	}

	return ret;
}

void inc_authen_requests(int i)
{
	stats[i]->authen_requests++;
}

void inc_authen_replies(int i)
{
	stats[i]->authen_replies++;
}

void inc_author_requests(int i)
{
	stats[i]->author_requests++;
}

void inc_author_replies(int i)
{
	stats[i]->author_replies++;
}

void inc_acct_requests(int i)
{
	stats[i]->acct_requests++;
}

void inc_acct_replies(int i)
{
	stats[i]->acct_replies++;
}

void inc_unknown_replies(int i)
{
	stats[i]->unknown_replies++;
}

void inc_failed_connects(int i)
{
	stats[i]->failed_connects++;
}

int get_authen_requests(int i)
{
	return stats[i]->authen_requests;
}

int get_authen_replies(int i)
{
	return stats[i]->authen_replies;
}

int get_author_requests(int i)
{
	return stats[i]->author_requests;
}

int get_author_replies(int i)
{
	return stats[i]->author_replies;
}

int get_acct_requests(int i)
{
	return stats[i]->acct_requests;
}

int get_acct_replies(int i)
{
	return stats[i]->acct_replies;
}

int get_failed_connects(int i)
{
	return stats[i]->failed_connects;
}

int get_unknown_replies(int i)
{
	return stats[i]->unknown_replies;
}

void free_statistics()
{
	int i;

	if (created) {
		for(i=0; i<created ; i++) {
			free(stats[i]);
		}
	}

	free(stats);

	stats = NULL;

	created = 0;
}
