/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <systemd/sd-bus.h>

#include "dbus_service.h"
#include "global.h"
#include "queue.h"
#include "statistics.h"
#include "transaction.h"

#define __unused __attribute__((unused))

/* Abstraction of commonly used types */
#define BUS_TYPE_ARRAY  "a"    /* SD_BUS_TYPE_ARRAY */
#define BUS_TYPE_INT32  "i"    /* SD_BUS_TYPE_INT32 */
#define BUS_TYPE_STRING "s"    /* SD_BUS_TYPE_STRING */
#define BUS_TYPE_BOOL   "b"    /* SD_BUS_TYPE_BOOLEAN */

#define BUS_TYPE_DICT_ELEM(K,V)                  \
	"{"      /* SD_BUS_TYPE_DICT_ENTRY_BEGIN */  \
		K V                                      \
	"}"      /* SD_BUS_TYPE_DICT_ENTRY_END */

#define BUS_TYPE_DICT(K,V) BUS_TYPE_ARRAY BUS_TYPE_DICT_ELEM(K,V)

#define BUS_TYPE_STR_STR_DICT_ELEM BUS_TYPE_DICT_ELEM(BUS_TYPE_STRING, BUS_TYPE_STRING)
#define BUS_TYPE_STR_STR_DICT BUS_TYPE_DICT(BUS_TYPE_STRING, BUS_TYPE_STRING)

/* DBus method signatures */
#define GET_STATUS_ARGS ""
#define GET_STATUS_RET  BUS_TYPE_INT32 BUS_TYPE_ARRAY BUS_TYPE_STRING

#define GET_ACCT_TASK_ID_ARGS ""
#define GET_ACCT_TASK_ID_RET  BUS_TYPE_STRING

#define ACCOUNT_SEND_ARGS BUS_TYPE_INT32 BUS_TYPE_STRING BUS_TYPE_STRING  \
						  BUS_TYPE_STRING BUS_TYPE_STR_STR_DICT
#define ACCOUNT_SEND_RET  BUS_TYPE_INT32

#define CMD_ACCOUNT_SEND_ARGS ACCOUNT_SEND_ARGS BUS_TYPE_ARRAY BUS_TYPE_STRING
#define CMD_ACCOUNT_SEND_RET  ACCOUNT_SEND_RET

#define AUTHEN_SEND_ARGS BUS_TYPE_STRING BUS_TYPE_STRING BUS_TYPE_STRING BUS_TYPE_STRING
#define AUTHEN_SEND_RET  BUS_TYPE_INT32

#define AUTHOR_SEND_ARGS BUS_TYPE_STRING BUS_TYPE_STRING BUS_TYPE_STRING BUS_TYPE_STR_STR_DICT
#define AUTHOR_SEND_RET  BUS_TYPE_INT32 BUS_TYPE_STR_STR_DICT

#define CMD_AUTHOR_SEND_ARGS AUTHOR_SEND_ARGS BUS_TYPE_ARRAY BUS_TYPE_STRING
#define CMD_AUTHOR_SEND_RET  AUTHOR_SEND_RET

#define CAN_CONNECT_ARGS ""
#define CAN_CONNECT_RET BUS_TYPE_BOOL

struct tacplus_dbus_service {
	sd_bus *bus;
	bool stop;
	bool process;

	Queue *tacacs_query_q;
	Queue *tacacs_response_q;

	pthread_mutex_t bus_lock;
	pthread_t request_thread, reply_thread, dbus_thread;

	uint64_t acct_task_id;
};

static struct tacplus_dbus_service _service = { .stop = true, .process = false };
static tacplus_dbus_service_t service = &_service;

static void transaction_queue_free_element(void *e)
{
	struct transaction *t = e;

	/* To cleanly exit, we add bogus entries to our queues that trick
	 * our threads into returning from pthread_cond_wait. These bogus
	 * queue elements are allocated with calloc, hence the check for
	 * NULL.
	 */
	if (t->user)
		sd_bus_message_unref(t->user);

	/* Do any per-type cleanup */
	switch (t->type) {
		case TRANSACTION_ACCOUNT:
			free(t->request.account.task_id);
			free(t->request.account.r_addr);
			for (char **arg = t->request.account.command; arg && *arg; arg++)
				free(*arg);
			free(t->request.account.command);
			break;
		case TRANSACTION_AUTHOR:
			for (char **arg = t->request.author.cmd; arg && *arg; arg++)
				free(*arg);
			free(t->request.author.cmd);
			break;
		case TRANSACTION_AUTHEN:
		case TRANSACTION_CONN_CHECK:
		default:
			break;
	}

	transaction_free(&t);
}

void dbus_service_init()
{
	pthread_mutex_init(&service->bus_lock, NULL);

	service->tacacs_query_q = create_queue(transaction_queue_free_element);
	service->tacacs_response_q = create_queue(transaction_queue_free_element);
}

void dbus_service_deinit()
{
	destroy_queue(&service->tacacs_query_q);
	destroy_queue(&service->tacacs_response_q);

	pthread_mutex_lock(&service->bus_lock);
	sd_bus_release_name(service->bus, TACPLUS_DAEMON);
	sd_bus_close(service->bus);
	sd_bus_unref(service->bus);
	service->bus = NULL;
	pthread_mutex_unlock(&service->bus_lock);

	pthread_mutex_destroy(&service->bus_lock);
}

static int
fill_bus_msg_from_account_transaction(const struct account_send_response *r,
									  sd_bus_message *m)
{
	return sd_bus_message_append(m, BUS_TYPE_INT32, r->status);
}

static int
fill_bus_msg_from_authen_transaction(const struct authen_send_response *r,
									 sd_bus_message *m)
{
	return sd_bus_message_append(m, BUS_TYPE_INT32, r->status);
}

static int
fill_bus_msg_from_author_transaction(const struct author_send_response *r,
									 sd_bus_message *m)
{
	int type, ret;

	switch (r->status) {
		case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
		case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
		case TAC_PLUS_AUTHOR_STATUS_FAIL:
		case TAC_PLUS_AUTHOR_STATUS_ERROR:
			type = r->status;
			break;
		case TAC_PLUS_AUTHOR_STATUS_FOLLOW:
		default:
			type = TAC_PLUS_AUTHOR_STATUS_ERROR;
			break;
	}

	ret = sd_bus_message_append(m, BUS_TYPE_INT32, type);
	if (ret < 0)
		return ret;

	sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, BUS_TYPE_STR_STR_DICT_ELEM);
	if (ret < 0)
		return ret;

	for (struct transaction_attrib *attr = r->attrs; attr; attr = attr->next) {
		ret = sd_bus_message_append(m, BUS_TYPE_STR_STR_DICT_ELEM, attr->name, attr->value);
		if (ret < 0)
			return ret;
	}

	return sd_bus_message_close_container(m);
}

static int
fill_bus_msg_from_conn_check_transaction(const struct conn_check_response *r,
										 sd_bus_message *m)
{
	return sd_bus_message_append(m, BUS_TYPE_BOOL, r->can_connect);
}

static sd_bus_message *
fill_bus_msg_for_transaction(struct transaction *t)
{
	sd_bus_message *reply;
	int ret;

	if (! t->user) {
		syslog(LOG_ERR, "Cannot generate method response without method call message");
		return NULL;
	}

	ret = sd_bus_message_new_method_return(t->user, &reply);
	if (ret < 0) {
		syslog(LOG_ERR, "Failed to allocate method response message: %d", ret);
		return NULL;
	}

	switch (t->type) {
		case TRANSACTION_ACCOUNT:
			ret = fill_bus_msg_from_account_transaction(&t->response.account, reply);
			break;
		case TRANSACTION_AUTHEN:
			ret = fill_bus_msg_from_authen_transaction(&t->response.authen, reply);
			break;
		case TRANSACTION_AUTHOR:
			ret = fill_bus_msg_from_author_transaction(&t->response.author, reply);
			break;
		case TRANSACTION_CONN_CHECK:
			ret = fill_bus_msg_from_conn_check_transaction(
					&t->response.conn_check, reply);
			break;
		default:
			ret = -1;
			break;
	}

	if (ret < 0) {
		sd_bus_message_unref(reply);
		return NULL;
	}

	return reply;
}

static void release_transaction_for_bus_message(struct transaction **t)
{
	if (t && *t) {
		transaction_queue_free_element(*t);
		*t = NULL;
	}
}

static void *consume_dbus_reply_thread(void *arg __unused)
{
	while (! service->stop) {
		struct transaction *t;

		pthread_mutex_lock(&(service->tacacs_response_q->lock));
		while (is_queue_empty(service->tacacs_response_q)) {
			pthread_cond_wait(&(service->tacacs_response_q->empty),
							  &(service->tacacs_response_q->lock));
		}
		pthread_mutex_unlock(&(service->tacacs_response_q->lock));

		/* TODO: what if there's still a valid msg to send? */
		if (service->stop || !service->process) {
			syslog(LOG_DEBUG, "TACACS+ reply_thread: stopping");
			break;
		}

		t = dequeue(service->tacacs_response_q);
		if (t->type == TRANSACTION_INVALID) {
			release_transaction_for_bus_message(&t);
			continue;
		}

		syslog(LOG_DEBUG, "Processing %s transaction response",
						  transaction_type_str(t->type));

		pthread_mutex_lock(&service->bus_lock);

		sd_bus_message *reply = fill_bus_msg_for_transaction(t);
		if (reply) {
			int ret = sd_bus_send(sd_bus_message_get_bus(reply), reply, NULL);

			if (ret < 0)
				syslog(LOG_DEBUG, "Failed to send %s transaction response: %d",
								   transaction_type_str(t->type), ret);
			else
				syslog(LOG_DEBUG, "Sent %s transaction response",
								   transaction_type_str(t->type));

			sd_bus_message_unref(reply);
			reply = NULL;
		}
		else {
			syslog(LOG_ERR, "Failed to generate response for transaction");
		}

		pthread_mutex_unlock(&service->bus_lock);

		release_transaction_for_bus_message(&t);
	}

	syslog(LOG_DEBUG, "TACACS+ reply_thread: exiting");
	pthread_exit(NULL);
}

static void *consume_dbus_req_thread(void *arg __unused)
{
	while (! service->stop) {
		struct transaction *t;

		pthread_mutex_lock(&(service->tacacs_query_q->lock));
		while (is_queue_empty(service->tacacs_query_q)) {
			pthread_cond_wait(&(service->tacacs_query_q->empty),
							  &(service->tacacs_query_q->lock));
		}
		pthread_mutex_unlock(&(service->tacacs_query_q->lock));

		/* at this point we now have at least one tacacs+ request in our queue */

		if (service->stop || !service->process) {
			syslog(LOG_DEBUG, "TACACS+ request_thread: stopping");
			break;
		}

		t = dequeue(service->tacacs_query_q);
		if (t->type == TRANSACTION_INVALID) {
			release_transaction_for_bus_message(&t);
			continue;
		}

		syslog(LOG_DEBUG, "Processing %s transaction from queue",
						  transaction_type_str(t->type));

		switch (t->type) {
			case TRANSACTION_ACCOUNT:
				tacplus_acct_send(t);
				break;
			case TRANSACTION_AUTHEN:
				tacplus_authen_send(t);
				break;
			case TRANSACTION_AUTHOR:
				tacplus_author_send(t);
				break;
			case TRANSACTION_CONN_CHECK:
				tacplus_connection_check(t);
				break;
			default:
				syslog(LOG_ERR, "Unknown transaction type %d - ignoring", t->type);
				release_transaction_for_bus_message(&t);
				continue;
		}

		syslog(LOG_DEBUG, "Completed %s transaction, queueing response",
						  transaction_type_str(t->type));

		enqueue(service->tacacs_response_q, t);
	}

	syslog(LOG_DEBUG, "TACACS+ request_thread: exiting");
	pthread_exit(NULL);
}

static int fill_status_reply(struct sd_bus_message *m)
{
	int ret;

	sd_bus_message_append(m, BUS_TYPE_INT32,
						  tacplusd_remaining_offline_secs());

	ret = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, BUS_TYPE_STRING);
	if (ret < 0)
		return ret;

	for (unsigned i = 0 ; i < connControl->opts->n_servers ; i++) {
		uint16_t port;
		char *addr;
		char *src = NULL;
		char *val;
		size_t val_size;
		FILE *val_stream;

		addr = addrinfo_to_string(tacplus_server(connControl->opts, i)->addrs);
		if (! addr)
			continue;

		if (connControl->opts->server[i].src_addrs)
			src = addrinfo_to_string(connControl->opts->server[i].src_addrs);
		else if (connControl->opts->server[i].src_intf)
			src = strdup(connControl->opts->server[i].src_intf);

		port = get_addrinfo_port(tacplus_server(connControl->opts, i)->addrs);

		val_stream = open_memstream(&val, &val_size);

		fprintf(val_stream, "%s,%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%ld",
				addr,
				port,
				src ? src : "",
				get_authen_requests(i),
				get_authen_replies(i),
				get_author_requests(i),
				get_author_replies(i),
				get_acct_requests(i),
				get_acct_replies(i),
				get_unknown_replies(i),
				get_failed_connects(i),
				(i == connControl->opts->curr_server) ? true : false,
				tacplus_server_remaining_hold_down_secs(&connControl->opts->server[i]));

		fclose(val_stream);

		sd_bus_message_append(m, BUS_TYPE_STRING, val);

		free(addr);
		free(val);
		free(src);
	}

	return sd_bus_message_close_container(m);
}

static int get_status(sd_bus_message *m,
					  __unused void *userdata,
					  __unused sd_bus_error *error)
{
	int ret;
	sd_bus_message *reply;

	syslog(LOG_DEBUG, "get_status() call");

	ret = sd_bus_message_new_method_return(m, &reply);
	if (ret < 0)
		return ret;

	ret = fill_status_reply(reply);
	if (ret < 0) {
		syslog(LOG_ERR, "Failed to generate status reply: %d", ret);
		sd_bus_message_unref(reply);
		return ret;
	}

	ret = sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
	if (ret < 0)
		syslog(LOG_DEBUG, "Failed to send get_status() response: %d", ret);

	sd_bus_message_unref(reply);
	return ret;
}

static int queue_transaction_for_bus_message(struct transaction *t,
											 sd_bus_message *m)
{
	/*
	 * Stash message with the transaction so we can send a reply later. We
	 * must add a ref to ensure the sd-bus library doesn't free the message
	 * until we are done.
	 */
	t->user = m;
	sd_bus_message_ref(m);

	enqueue(service->tacacs_query_q, t);

	syslog(LOG_DEBUG, "Queued %s transaction request",
					  transaction_type_str(t->type));

	/* Return non-zero to allow us to send an asynchronous reply */
	return 1;
}

typedef int (*account_variant_fill_handler)(struct account_send_param *,
											sd_bus_message *);

static int fill_account_transaction_from_bus_msg(struct account_send_param *p,
												 sd_bus_message *m,
												 account_variant_fill_handler var_fn)
{
	int ret;
	char *key = NULL, *value = NULL;

	ret = sd_bus_message_read(m, BUS_TYPE_INT32 BUS_TYPE_STRING
								 BUS_TYPE_STRING BUS_TYPE_STRING,
							  &p->account_flag, &p->name, &p->tty, &p->r_addr);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY,
										 BUS_TYPE_STR_STR_DICT_ELEM);
	if (ret < 0)
		return ret;

	while (sd_bus_message_read(m, BUS_TYPE_STR_STR_DICT_ELEM, &key, &value) > 0) {
		if (strcmp("task_id", key) == 0) {
			p->task_id = value;
		}
		else if (strcmp("start_time", key) == 0) {
			p->start_time = value;
		}
		else if (strcmp("stop_time", key) == 0) {
			p->stop_time = value;
		}
		else if (strcmp("timezone", key) == 0) {
			p->timezone = value;
		}
		else if (strcmp("service", key) == 0) {
			p->service = value;
		}
		else if (strcmp("protocol", key) == 0) {
			p->protocol = value;
		}
		else {
			syslog(LOG_ERR, "Ignoring unsupported attribute-key: %s", key);
		}
	}

	ret = sd_bus_message_exit_container(m);
	if (ret < 0 || !var_fn)
		return ret;

	return var_fn(p, m);
}

static void fill_account_transaction_task_id(struct account_send_param *p) {
	/*
	 * Choose a new task ID if one was not provided
	 *
	 * Otherwise copy the provided ID. This allows common cleanup in
	 * transaction_queue_free_element() since the memory lifecycle of the
	 * data filled into the transaction by fill_account_transaction_from_bus_msg()
	 * is managed by sd-dbus. Hence we also don't free any existing value.
	 */
	if (!p->task_id) {
		char buf[TAC_PLUS_ATTRIB_MAX_LEN] = {0};
		assert(snprintf(buf, sizeof(buf), "%lu", service->acct_task_id++) < (int) sizeof(buf));
		p->task_id = strdup(buf);
	} else {
		p->task_id = strdup(p->task_id);
	}
}

static int get_account_task_id(sd_bus_message *m,
							   __unused void *userdata,
							   __unused sd_bus_error *error)
{
	int ret;
	sd_bus_message *reply;
	struct account_send_param p = {0};

	syslog(LOG_DEBUG, "get_account_task_id() call");

	ret = sd_bus_message_new_method_return(m, &reply);
	if (ret < 0)
		return ret;

	fill_account_transaction_task_id(&p);
	ret = sd_bus_message_append(reply, BUS_TYPE_STRING, p.task_id ? p.task_id : "");
	if (ret < 0) {
		syslog(LOG_ERR, "Failed to generate task ID reply: %d", ret);
		goto done;
	}

	ret = sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
	if (ret < 0)
		syslog(LOG_DEBUG, "Failed to send get_account_task_id() response: %d", ret);

done:
	free(p.task_id);
	sd_bus_message_unref(reply);
	return ret;
}

static void fill_account_transaction_rem_addr(struct account_send_param *p) {
	/*
	 * If we don't have a remote login address then attempt to obtain one based
	 * on the TTY (if we were passed one).
	 *
	 * Otherwise copy the provided address. This allows common cleanup in
	 * transaction_queue_free_element() since the memory lifecycle of the
	 * data filled into the transaction by fill_account_transaction_from_bus_msg()
	 * is managed by sd-dbus. Hence we also don't free any existing value.
	 */
	char *r_addr;
	if ((!p->r_addr || strlen(p->r_addr) == 0) &&
			(r_addr = get_tty_login_addr(p->tty))) {
		p->r_addr = r_addr;
	} else {
		p->r_addr = strdup(p->r_addr);
	}
}

#define ACCOUNT_SEND_VARIANT(N, V)											\
static int N(sd_bus_message *m,												\
			 __unused void *userdata,										\
			 __unused sd_bus_error *error)									\
{																			\
	struct transaction *t;													\
	int ret;																\
																			\
	syslog(LOG_DEBUG, #N "() call");										\
																			\
	t = transaction_new(TRANSACTION_ACCOUNT);								\
	if (!t)																	\
		return -ENOMEM;														\
																			\
	ret = fill_account_transaction_from_bus_msg(&t->request.account, m, V);	\
	if (ret < 0) {															\
		syslog(LOG_ERR, "Failed to parse " #N " call: %d", ret);			\
		transaction_free(&t);												\
		return ret;															\
	}																		\
																			\
	fill_account_transaction_task_id(&t->request.account);					\
	fill_account_transaction_rem_addr(&t->request.account);					\
																			\
	return queue_transaction_for_bus_message(t, m);							\
}

ACCOUNT_SEND_VARIANT(account_send, NULL);

static int cmd_account_fill_handler(struct account_send_param *p,
									sd_bus_message *m)
{
	return sd_bus_message_read_strv(m, &(p->command));
}

ACCOUNT_SEND_VARIANT(cmd_account_send, cmd_account_fill_handler);

static int fill_authen_transaction_from_bus_msg(struct authen_send_param *p,
												sd_bus_message *m)
{
	return sd_bus_message_read(m, AUTHEN_SEND_ARGS,
							   &p->user, &p->password,
							   &p->tty, &p->r_addr);
}

static int authen_send(sd_bus_message *m,
					   __unused void *userdata,
					   __unused sd_bus_error *error)
{
	struct transaction *t;
	int ret;

	syslog(LOG_DEBUG, "authen_send() call");

	t = transaction_new(TRANSACTION_AUTHEN);
	if (!t)
		return -ENOMEM;

	ret = fill_authen_transaction_from_bus_msg(&t->request.authen, m);
	if (ret < 0) {
		syslog(LOG_ERR, "Failed to parse authen_send() call: %d", ret);
		transaction_free(&t);
		return ret;
	}

	return queue_transaction_for_bus_message(t, m);
}

typedef int (*author_variant_fill_handler)(struct author_send_param *,
										   sd_bus_message *);

static int fill_author_transaction_from_bus_msg(struct author_send_param *p,
												sd_bus_message *m,
												author_variant_fill_handler var_fn)
{
	int ret;
	char *key = NULL, *value = NULL;

	ret = sd_bus_message_read(m, BUS_TYPE_STRING BUS_TYPE_STRING BUS_TYPE_STRING,
							  &p->login, &p->tty, &p->r_addr);
	if (ret < 0)
		return ret;

	ret = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY,
										 BUS_TYPE_STR_STR_DICT_ELEM);
	if (ret < 0)
		return ret;

	while (sd_bus_message_read(m, BUS_TYPE_STR_STR_DICT_ELEM, &key, &value) > 0) {
		if (strcmp("protocol", key) == 0) {
			p->protocol = value;
		}
		else if (strcmp("service", key) == 0) {
			p->service = value;
		}
		else if (strcmp("secrets", key) == 0) {
			p->secrets = value;
		}
		else {
			syslog(LOG_ERR, "Ignoring unsupported attribute-key: %s", key);
		}
	}

	ret = sd_bus_message_exit_container(m);
	if (ret < 0 || !var_fn)
		return ret;

	return var_fn(p, m);
}

#define AUTHOR_SEND_VARIANT(N, V)											\
static int N(sd_bus_message *m,												\
			 __unused void *userdata,										\
			 __unused sd_bus_error *error)									\
{																			\
	struct transaction *t;													\
	int ret;																\
																			\
	syslog(LOG_DEBUG, #N "() call");										\
																			\
	t = transaction_new(TRANSACTION_AUTHOR);								\
	if (!t)																	\
		return -ENOMEM;														\
																			\
	ret = fill_author_transaction_from_bus_msg(&t->request.author, m, V);	\
	if (ret < 0) {															\
		syslog(LOG_ERR, "Failed to parse " #N "() call: %d", ret);			\
		transaction_free(&t);												\
		return ret;															\
	}																		\
																			\
	return queue_transaction_for_bus_message(t, m);							\
}

AUTHOR_SEND_VARIANT(author_send, NULL);

static int cmd_author_fill_handler(struct author_send_param *p,
								   sd_bus_message *m)
{
	return sd_bus_message_read_strv(m, &(p->cmd));
}

AUTHOR_SEND_VARIANT(cmd_author_send, cmd_author_fill_handler);

int signal_offline_state_change() {
	if (service->stop) {
		syslog(LOG_ERR, "Unable to signal offline state change");
		return -1;
	}

	pthread_mutex_lock(&service->bus_lock);
	int ret = sd_bus_emit_properties_changed(
		service->bus, TACPLUS_DAEMON_PATH, TACPLUS_DAEMON, "offline", NULL);
	pthread_mutex_unlock(&service->bus_lock);

	if (ret < 0)
		syslog(LOG_ERR, "Failed to signal offline state change");
	return ret;
}

static int can_connect(sd_bus_message *m,
					   __unused void *userdata,
					   __unused sd_bus_error *error)
{
	struct transaction *t;

	syslog(LOG_DEBUG, "can_connect() call");

	t = transaction_new(TRANSACTION_CONN_CHECK);
	if (!t)
		return -ENOMEM;

	return queue_transaction_for_bus_message(t, m);
}

static int offline_property_get(__unused sd_bus *bus,
								__unused const char *path,
								__unused const char *interface,
								__unused const char *property,
								sd_bus_message *reply,
								__unused void *userdata,
								__unused sd_bus_error *error)
{
	return sd_bus_message_append(reply, BUS_TYPE_BOOL, connControl->state.offline);
}

static const sd_bus_vtable serv_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("get_status", GET_STATUS_ARGS, GET_STATUS_RET,
				  get_status, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("get_account_task_id", GET_ACCT_TASK_ID_ARGS, GET_ACCT_TASK_ID_RET,
				  get_account_task_id, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("account_send", ACCOUNT_SEND_ARGS, ACCOUNT_SEND_RET,
				  account_send, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("cmd_account_send", CMD_ACCOUNT_SEND_ARGS, CMD_ACCOUNT_SEND_RET,
				  cmd_account_send, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("authen_send", AUTHEN_SEND_ARGS, AUTHEN_SEND_RET,
				  authen_send, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("author_send", AUTHOR_SEND_ARGS, AUTHOR_SEND_RET,
				  author_send, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("cmd_author_send", CMD_AUTHOR_SEND_ARGS, CMD_AUTHOR_SEND_RET,
				  cmd_author_send, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("can_connect", CAN_CONNECT_ARGS, CAN_CONNECT_RET,
				  can_connect, SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_PROPERTY("offline", BUS_TYPE_BOOL, offline_property_get, 0,
					SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_VTABLE_END
};

static void dbus_service_fail(tacplus_dbus_service_t service)
{
	service->stop = true;
	if (kill(getpid(), SIGTERM) != 0)
		abort();
}

static void *dbus_service_listen(__unused void *arg)
{
	int ret;

	while (! service->stop) {
		pthread_mutex_lock(&service->bus_lock);
		ret = sd_bus_process(service->bus, NULL);
		pthread_mutex_unlock(&service->bus_lock);

		if (ret > 0) /* More queued messages to process */
			continue;
		if (ret < 0)
			goto fail;

		ret = sd_bus_wait(service->bus, 1000000);
		if (ret < 0)
			goto fail;
	}

	syslog(LOG_DEBUG, "Stopping dbus_service_listen thread");
	return NULL;

fail:
	syslog(LOG_ERR, "DBus processing error: %s (%d)", strerror(-ret), ret);
	dbus_service_fail(service);
	return NULL;
}

static void force_wake_queue_threads(tacplus_dbus_service_t service)
{
	assert(service->stop || !service->process);

	/* Wake up queue threads - transaction type MUST be TRANSACTION_INVALID */

	enqueue(service->tacacs_query_q, transaction_new(TRANSACTION_INVALID));
	enqueue(service->tacacs_response_q, transaction_new(TRANSACTION_INVALID));
}

static void start_processing(tacplus_dbus_service_t service)
{
	assert(! service->stop);

	if (service->process) {
		syslog(LOG_DEBUG, "Processing already started");
		return;
	}

	/*
	 * The process flag MUST be set before starting the consumer threads
	 * otherwise they may immediately exit
	 */
	service->process = true;

	if (pthread_create(&service->request_thread, NULL,
					   consume_dbus_req_thread, NULL)) {
		syslog(LOG_ERR, "Failed to instantiate request_thread");
		service->process = false;
		return;
	}

	if (pthread_create(&service->reply_thread, NULL,
					   consume_dbus_reply_thread, NULL)) {
		syslog(LOG_ERR, "Failed to instantiate reply_thread");
		service->process = false;
		force_wake_queue_threads(service);
		pthread_join(service->request_thread, NULL);
		return;
	}
}

static void stop_processing(tacplus_dbus_service_t service)
{
	/* Check the processing threads have started */
	if (!service->process)
		return;

	service->process = false;
	force_wake_queue_threads(service);

	syslog(LOG_DEBUG, "Waiting on request_thread...");
	pthread_join(service->request_thread, NULL);

	syslog(LOG_DEBUG, "Waiting on reply_thread...");
	pthread_join(service->reply_thread, NULL);
}

void dbus_service_wait(void)
{
	syslog(LOG_DEBUG, "Waiting on dbus_thread...");
	pthread_join(service->dbus_thread, NULL);
}

// Calling thread must hold service->bus_lock
static void _dbus_service_start_fail_cleanup()
{
	if (service->bus)
		sd_bus_unref(service->bus);
	service->bus = NULL;
	pthread_mutex_unlock(&service->bus_lock);
}

int dbus_service_start()
{
	int ret;

	if (service->bus || !service->stop) {
		syslog(LOG_DEBUG, "DBus service is already running");
		return 0;
	}

	pthread_mutex_lock(&service->bus_lock);

	ret = sd_bus_open_system(&service->bus);
	if (ret < 0) {
		_dbus_service_start_fail_cleanup();
		return ret;
	}

	ret = sd_bus_request_name(service->bus, TACPLUS_DAEMON, 0);
	if (ret < 0) {
		_dbus_service_start_fail_cleanup();
		return ret;
	}

	ret = sd_bus_add_object_vtable(service->bus, NULL, TACPLUS_DAEMON_PATH,
								   TACPLUS_DAEMON, serv_vtable, NULL);
	if (ret < 0) {
		sd_bus_release_name(service->bus, TACPLUS_DAEMON);
		_dbus_service_start_fail_cleanup();
		return ret;
	}

	service->stop = false;

	ret = pthread_create(&service->dbus_thread, NULL, dbus_service_listen, NULL);
	if (ret != 0) {
		syslog(LOG_ERR, "Failed to instantiate dbus_thread: %s", strerror(ret));
		sd_bus_release_name(service->bus, TACPLUS_DAEMON);
		_dbus_service_start_fail_cleanup();
		return ret;
	}

	start_processing(service);

	/* TODO: add dbus filters? */
	pthread_mutex_unlock(&service->bus_lock);
	return service->process ? 0 : -1;
}

void dbus_service_stop(void)
{
	service->stop = true;
	stop_processing(service);
}

void dbus_service_pause()
{
	/*
	 * Stop request/reply consumer threads and acquire the bus lock.
	 * Acquiring the bus lock is required to prevent the processing of
	 * DBus requests.
	 */
	stop_processing(service);
	pthread_mutex_lock(&service->bus_lock);
}

int dbus_service_resume()
{
	/*
	 * Start the request/reply consumer threads and release the bus lock
	 * so we start processing DBus requests once again.
	 */
	start_processing(service);
	pthread_mutex_unlock(&service->bus_lock);
	return service->process ? 0 : -1;
}

bool dbus_service_failed()
{
	return (service->stop && service->process);
}
