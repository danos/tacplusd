/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2019 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef _TRANSACTION_H
#define _TRANSACTION_H


struct authen_send_param {
	char *user;
	char *password;
	char *tty;
	char *r_addr;
};

struct author_send_param {
	char *login;
	char *tty;
	char *r_addr;
	char *protocol;
	char *service;
	char *secrets;
	char **cmd;
};

struct account_send_param {
	int account_flag;
	char *name;
	char *tty;
	char *r_addr;
	char *task_id;
	char *start_time;
	char *stop_time;
	char *service;
	char *protocol;
	char **command;
};

struct account_send_response {
	int status;
};

struct authen_send_response {
	int status;
};

struct author_send_response {
	int status;
	struct transaction_attrib *attrs;
};

typedef enum {
	TRANSACTION_AUTHEN = 1,
	TRANSACTION_AUTHOR,
	TRANSACTION_ACCOUNT,
	TRANSACTION_INVALID,
} transaction_type_t;

const char *transaction_type_str(transaction_type_t);

struct transaction {
	transaction_type_t type;

	union {
		struct authen_send_param authen;
		struct author_send_param author;
		struct account_send_param account;
	} request;

	union {
		struct authen_send_response authen;
		struct author_send_response author;
		struct account_send_response account;
	} response;

	void *user;
};

struct transaction *transaction_new(transaction_type_t);
void transaction_free(struct transaction **);

struct transaction_attrib {
	struct transaction_attrib *next;
	const char *name;
	const char *value;
};

struct transaction_attrib *transaction_attrib_new(const char *);
void transaction_attrib_free(struct transaction_attrib **);

int tacplus_author_send(struct transaction *);

int tacplus_acct_send(struct transaction *);

int tacplus_authen_send(struct transaction *);

#endif /*_TRANSACTION_H */
