/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <stdlib.h>

struct statistics {
	int authen_requests;
	int authen_replies;
	int author_requests;
	int author_replies;
	int acct_requests;
	int acct_replies;
	int failed_connects;
	int unknown_replies;
};


extern int create_statistics(int);
extern void free_statistics();

/* Authentication stats */
extern void inc_authen_requests(int);
extern void inc_authen_replies(int);
extern int get_authen_requests(int);
extern int get_authen_replies(int);

/* Authorization stats */
extern void inc_author_requests(int);
extern void inc_author_replies(int);
extern int get_author_requests(int);
extern int get_author_replies(int);

/* Accounting stats */
extern void inc_acct_requests(int);
extern void inc_acct_replies(int);
extern int get_acct_requests(int);
extern int get_acct_replies(int);

/* Misc stats */
extern void inc_failed_connects(int);
extern int get_failed_connects(int);

extern void inc_unknown_replies(int);
extern int get_unknown_replies(int);
