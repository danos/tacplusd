/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef QUEUE_H
#define QUEUE_H

#include <syslog.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef struct queueNode {
	void *element;
	struct queueNode *next;
} Node;

typedef struct queue {
	Node *front, *rear;
	pthread_mutex_t lock;
	pthread_cond_t empty;
	void (*free_element)(void *);
} Queue;

extern Queue * create_queue(void (*)(void *));
extern void enqueue(Queue *q, void *);
extern void re_enqueue(Queue *q, void *e);
extern int is_queue_empty(Queue *);
extern void * dequeue(Queue *);
extern void destroy_queue(Queue **);

#endif /* QUEUE_H */
