/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <assert.h>
#include <stdbool.h>
#include <syslog.h>

#include <libtac.h>
#include <tacplus.h>

#include "global.h"
#include "statistics.h"
#include "tacplus_srv_conn.h"
#include "transaction.h"
#include "transaction_private.h"

#define OPTIONAL_ATTR_SEP '*'

const char *transaction_type_str(transaction_type_t type)
{
	switch (type) {
		case TRANSACTION_ACCOUNT:
			return "accounting";
		case TRANSACTION_AUTHEN:
			return "authentication";
		case TRANSACTION_AUTHOR:
			return "authorization";
		case TRANSACTION_CONN_CHECK:
			return "connection check";
		case TRANSACTION_INVALID:
			return "invalid";
		default:
			break;
	}

	syslog(LOG_ERR, "Unknown transaction type %d", type);
	return "unknown";
}

struct transaction *transaction_new(transaction_type_t type)
{
	struct transaction *t;

	t = calloc(1, sizeof(*t));
	if (!t)
		return NULL;

	t->type = type;
	return t;
}

void transaction_free(struct transaction **t)
{
	if (t && *t) {
		switch ((*t)->type) {
			case TRANSACTION_AUTHOR:
				transaction_attrib_free(&(*t)->response.author.attrs);
				break;
			case TRANSACTION_AUTHEN:
			case TRANSACTION_ACCOUNT:
			case TRANSACTION_CONN_CHECK:
			case TRANSACTION_INVALID:
				break;
		}
		free(*t);
		*t = NULL;
	}
}

struct transaction_attrib *
transaction_attrib_new(const char *av_pair)
{
	if (! av_pair || strlen(av_pair) == 0)
		return NULL;

	/*
	 * We need an attribute name, and separators are not allowed to be part
	 * of the name. Therefore if the first character is a separator just fail.
	 */
	if (av_pair[0] == '*' || av_pair[0] == '=')
		return NULL;

	struct transaction_attrib *attr = calloc(1, sizeof(struct transaction_attrib));
	if (! attr)
		goto malloc_fail;

	char *mand_sep = strchr(av_pair, '=');
	char *opt_sep  = strchr(av_pair, '*');
	char *sep = NULL;

	/*
	 * If both separators are found it means that one or both of them is
	 * present in the attribute value as well as the name. Therefore take
	 * the first one which occurs as the separator.
	 */
	if (mand_sep && opt_sep)
		sep = mand_sep < opt_sep ? mand_sep : opt_sep;
	else if (mand_sep)
		sep = mand_sep;
	else if (opt_sep)
		sep = opt_sep;

	if (sep) {
		attr->name = strndup(av_pair, (sep + 1) - av_pair);
		attr->value = strdup(sep + 1);
	}
	else {
		/* If there is no separator found treat it as a mandatory attribute */
		if ((attr->name = calloc(1, strlen(av_pair) + 2))) {
			strcat((char *) attr->name, av_pair);
			strcat((char *) attr->name, "=");
		}
		attr->value = strdup("");
	}

	if (attr->name && attr->value)
		return attr;

malloc_fail:
	syslog(LOG_ERR, "tacplus_attrib memory allocation failure!");
	transaction_attrib_free(&attr);
	return NULL;
}

void transaction_attrib_free(struct transaction_attrib **head)
{
	if (head && *head) {
		struct transaction_attrib *attr = *head, *next;
		*head = NULL;

		do {
			next = attr->next;
			free((void *) attr->name);
			free((void *) attr->value);
			free(attr);
		} while ((attr = next) != NULL);
	}
}

struct transaction_attrib *transaction_attrib_from_tac_attrib(const struct tac_attrib *tac_attr)
{
	struct transaction_attrib *head = NULL, *tail;

	for (; tac_attr != NULL; tac_attr = tac_attr->next) {
		struct transaction_attrib *attr = transaction_attrib_new(tac_attr->attr);
		if (! attr)
			continue;

		if (head) {
			tail->next = attr;
			tail = attr;
		}
		else {
			head = tail = attr;
		}
	}

	return head;
}

static int tacplus_add_attrib(struct tac_attrib **attr, char *name,
							  char *value, bool truncate)
{
	syslog(LOG_DEBUG, "Appending mandatory attribute %s: %s", name, value);

	return truncate ? tac_add_attrib_truncate(attr, name, value) :
					  tac_add_attrib(attr, name, value);
}

static int tacplus_add_optional_attrib(struct tac_attrib **attr, char *name,
				       char *value, bool truncate)
{
	syslog(LOG_DEBUG, "Appending optional attribute %s: %s", name, value);

	return truncate ? tac_add_attrib_pair_truncate(attr, name,
						       OPTIONAL_ATTR_SEP, value) :
		tac_add_attrib_pair(attr, name, OPTIONAL_ATTR_SEP, value);
}

int tacplus_author_send(struct transaction *t)
{
	struct tac_attrib *attr = NULL;
	char *addr_str;
	struct tac_session_extra *extra;
	struct areply author_rep = { .status = TAC_PLUS_AUTHOR_STATUS_ERROR };

	assert(t->type == TRANSACTION_AUTHOR);
	t->response.author.status = author_rep.status;

	/* Attempt to populate cmd and args before connecting to server */
	char **cmd_arg = t->request.author.cmd;
	if (cmd_arg && *cmd_arg) {
		if (tacplus_add_attrib(&attr, "cmd",  *cmd_arg, false) < 0)
			goto unable_to_send;

		for (cmd_arg++; cmd_arg && *cmd_arg; cmd_arg++) {
			if (tacplus_add_attrib(&attr, "cmd-arg",  *cmd_arg, false) < 0)
				goto unable_to_send;
		}
	}

	if (tacplus_connect() == false) {
		syslog(LOG_NOTICE, "Failed to connect to a TACACS+ server for "
						   "authorization transaction");
		goto finish;
	}

	struct tac_session_extra _extra = {};
	extra = tacplus_current_session_extra(connControl->opts, &_extra);

	if (tacplus_add_attrib(&attr, "protocol",
			       t->request.author.protocol, false) < 0)
		goto unable_to_send;

	if (tacplus_add_attrib(&attr, "service",
			       t->request.author.service, false) < 0)
		goto unable_to_send;

	if (t->request.author.secrets &&
		tacplus_add_optional_attrib(&attr, "secrets",
					t->request.author.secrets, false) < 0)
		goto unable_to_send;

	addr_str = addrinfo_to_string(extra->server->addrs);

	syslog(LOG_DEBUG, "Sending authorization request to %s",
		strOrNil(addr_str));

	free(addr_str);

	t->response.author.status = tac_author_send(extra->server->fd, t->request.author.login,
									t->request.author.tty, t->request.author.r_addr, attr);
	if (t->response.author.status < 0)
	{
		syslog(LOG_NOTICE, "Error sending authorization request for user: %s <%d>\n",
						    t->request.author.login, t->response.author.status);
		tacplus_server_activate_hold_down(extra->server);
		goto finish;
	} else {
		inc_author_requests(extra->server_id);
	}

	t->response.author.status = tac_author_read_timeout(extra->server->fd, &author_rep, extra->server->timeout);

	if (author_rep.status < 0) {
		syslog(LOG_NOTICE, "Failed to read authorization response for user: %s <%d>\n",
							t->request.author.login, author_rep.status);
		tacplus_server_activate_hold_down(extra->server);
		goto finish;
	}

	switch (author_rep.status) {
		case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
			syslog(LOG_DEBUG, "Authorization received: PASS_ADD");
			break;

		case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
			syslog(LOG_DEBUG, "Authorization received: PASS_REPLACE");
			break;

		case TAC_PLUS_AUTHOR_STATUS_FAIL:
			syslog(LOG_DEBUG, "Authorization received: FAILED");
			break;

		case TAC_PLUS_AUTHOR_STATUS_ERROR:
			syslog(LOG_DEBUG, "Authorization received: ERROR");
			break;

		case TAC_PLUS_AUTHOR_STATUS_FOLLOW:
			syslog(LOG_DEBUG, "Authorization received: FOLLOW");
			break;

		default:
			syslog(LOG_DEBUG, "Authorization received: UNKNOWN");
			break;
	}

	inc_author_replies(extra->server_id);
	goto finish;

unable_to_send:
	syslog(LOG_NOTICE, "Unable to send authorization request");

finish:
	t->response.author.attrs = transaction_attrib_from_tac_attrib(author_rep.attr);

	tacplus_close();
	tac_free_attrib(&attr);
	tac_free_attrib(&author_rep.attr);
	free(author_rep.msg);
	return t->response.author.status;
}

static int tacplus_acct_send_per_session(struct transaction *t)
{
	struct tac_attrib *attr;
	struct tac_session_extra *extra;
	char *addr_str;
	struct areply re = {0};

	struct tac_session_extra _extra = {};
	extra = tacplus_current_session_extra (connControl->opts, &_extra);

	attr = NULL;

	if (t->request.account.task_id)
		if (tacplus_add_attrib(&attr, "task_id", t->request.account.task_id, false) < 0)
			goto unable_to_send;

	if (t->request.account.start_time)
		if (tacplus_add_attrib(&attr, "start_time", t->request.account.start_time, false) < 0)
			goto unable_to_send;

	if (t->request.account.stop_time)
		if (tacplus_add_attrib(&attr, "stop_time", t->request.account.stop_time, false) < 0)
			goto unable_to_send;

	if (t->request.account.timezone)
		if (tacplus_add_attrib(&attr, "timezone", t->request.account.timezone, false) < 0)
			goto unable_to_send;

	if (t->request.account.service)
		if (tacplus_add_attrib(&attr, "service", t->request.account.service, false) < 0)
			goto unable_to_send;

	if (t->request.account.protocol)
		if (tacplus_add_attrib(&attr, "protocol", t->request.account.protocol, false) < 0)
			goto unable_to_send;

	char **cmd_arg = t->request.account.command;
	if (cmd_arg && *cmd_arg) {
		if (tacplus_add_attrib(&attr, "cmd",  *cmd_arg, true) < 0)
			goto unable_to_send;

		for (cmd_arg++; cmd_arg && *cmd_arg; cmd_arg++) {
			if (tacplus_add_attrib(&attr, "cmd-arg",  *cmd_arg, true) < 0)
				goto unable_to_send;
		}
	}

	addr_str = addrinfo_to_string(extra->server->addrs);

	syslog(LOG_DEBUG, "Sending accounting request to %s",
			strOrNil(addr_str));

	free(addr_str);

	if (tac_acct_send(extra->server->fd, t->request.account.account_flag, t->request.account.name,
					  t->request.account.tty, t->request.account.r_addr, attr) < 0) {
		syslog(LOG_ERR, "Error sending accounting request");
		tacplus_server_activate_hold_down(extra->server);
		t->response.account.status = TAC_PLUS_ACCT_STATUS_ERROR;
		goto finish;
	} else {
		inc_acct_requests(extra->server_id);
	}

	t->response.account.status = tac_acct_read_timeout(extra->server->fd, &re, extra->server->timeout);
	if (t->response.account.status < 0) {
		syslog(LOG_ERR, "Error reading accounting reply: %d", t->response.account.status);
		tacplus_server_activate_hold_down(extra->server);
		goto finish;
	}

	switch (t->response.account.status) {
		case TAC_PLUS_ACCT_STATUS_SUCCESS:
			syslog(LOG_DEBUG, "Accounting received: SUCCESS");
			break;

		case TAC_PLUS_ACCT_STATUS_ERROR:
			syslog(LOG_DEBUG, "Accounting received: ERROR");
			break;

		case  TAC_PLUS_ACCT_STATUS_FOLLOW:
			syslog(LOG_DEBUG, "Accounting received: FOLLOW");
			break;

		default:
			syslog(LOG_DEBUG, "Accounting received: UNKNOWN");
			break;
	}

	inc_acct_replies(extra->server_id);
	goto finish;

unable_to_send:
	syslog(LOG_NOTICE, "Unable to send accounting request");

finish:
	tac_free_attrib(&attr);
	tac_free_attrib(&re.attr);
	free(re.msg);
	return t->response.account.status;
}

int tacplus_acct_send(struct transaction *t)
{
	assert(t->type == TRANSACTION_ACCOUNT);
	t->response.account.status = TAC_PLUS_ACCT_STATUS_ERROR;

	if (connControl->opts->broadcast) {
		syslog(LOG_ERR, "Broadcast mode is not supported!");
		goto finish;
	}

	if (tacplus_connect() == false) {
		syslog(LOG_NOTICE, "Failed to connect to a TACACS+ server for "
						   "accounting transaction");
		goto finish;
	}

	tacplus_acct_send_per_session(t);
	tacplus_close();

finish:
	return t->response.account.status;
}

int tacplus_authen_send(struct transaction *t)
{
	char *addr_str;
	struct tac_session_extra *extra;

	assert(t->type == TRANSACTION_AUTHEN);
	t->response.authen.status = TAC_PLUS_AUTHEN_STATUS_ERROR;

	if (tacplus_connect() == false) {
		syslog(LOG_NOTICE, "Failed to connect to a TACACS+ server for "
						   "authentication transaction");
		goto finish;
	}

	struct tac_session_extra _extra = {};
	extra = tacplus_current_session_extra (connControl->opts, &_extra);

	addr_str = addrinfo_to_string(extra->server->addrs);

	syslog(LOG_DEBUG, "Sending authentication request to %s",
		strOrNil(addr_str));

	free(addr_str);

	if (tac_authen_send(extra->server->fd, t->request.authen.user,
						t->request.authen.password, t->request.authen.tty,
						t->request.authen.r_addr) < 0)
	{
		syslog(LOG_ERR, "Error sending authentication request");
		t->response.authen.status = TAC_PLUS_AUTHEN_STATUS_ERROR;
		tacplus_server_activate_hold_down(extra->server);
		goto finish;
	}
	else {
		inc_authen_requests(extra->server_id);
	}

	bool auth_in_prog = true;

	while (auth_in_prog) {
		t->response.authen.status = tac_authen_read_timeout(extra->server->fd, extra->server->timeout);
		if (t->response.authen.status < 0) {
			syslog(LOG_ERR, "Error reading authentication reply: %d",
							t->response.authen.status);
			tacplus_server_activate_hold_down(extra->server);
			goto finish;
		}

		switch (t->response.authen.status) {
			case TAC_PLUS_AUTHEN_STATUS_PASS:
				auth_in_prog = false;
				syslog(LOG_DEBUG, "Authentication received: PASS");
				break;

			case TAC_PLUS_AUTHEN_STATUS_FAIL:
				auth_in_prog = false;
				syslog(LOG_DEBUG, "Authentication received: FAIL");
				break;

			case TAC_PLUS_AUTHEN_STATUS_GETDATA:
				/* FALLTHRU */
			case TAC_PLUS_AUTHEN_STATUS_GETUSER:
				syslog(LOG_DEBUG, "Authentication received: CONTINUE");

				/* FALLTHRU */
			case TAC_PLUS_AUTHEN_STATUS_RESTART:
				auth_in_prog = false;
				syslog(LOG_DEBUG, "Authentication received: RESTART");
				break;

			case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
				auth_in_prog = false;
				syslog(LOG_DEBUG, "Authentication received: FOLLOW");
				break;

			case TAC_PLUS_AUTHEN_STATUS_GETPASS:
				if (tac_cont_send(extra->server->fd, t->request.authen.password) < 0) {
					syslog(LOG_NOTICE, "Could not send TACACS+ password for user %s.\n", t->request.authen.user);
					/* This means the dbus client will receive a return 
					 * value of TAC_PLUS_AUTHEN_STATUS_GETPASS.
					 */
					goto finish;
				}
				/* continue the loop and read the TACACS+ server response to the supplied password */
				break;

			case TAC_PLUS_AUTHEN_STATUS_ERROR:
				auth_in_prog = false;
				syslog(LOG_DEBUG, "Authentication received: ERROR");
				break;

			default:
				auth_in_prog = false;
				break;
		}
	}

	inc_authen_replies(extra->server_id);

finish:
	tacplus_close();
	return t->response.authen.status;
}

void tacplus_connection_check(struct transaction *t)
{
	assert(t->type == TRANSACTION_CONN_CHECK);

	if ((t->response.conn_check.can_connect = tacplus_connect()))
		tacplus_close();
}
