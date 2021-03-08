/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018,2021 AT&T Intellectual Property.
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

enum queue_priority {
	MIN_PRIORITY = 0,
	MAX_PRIORITY = 1,
	NR_PRIORITY = MAX_PRIORITY + 1,
} queue_priority_t;

typedef struct queueNode {
	void *element;
	int prio;
	struct queueNode *next;
} Node;

typedef struct queue {
	Node *front;
	Node *rear[NR_PRIORITY];
	pthread_mutex_t lock;
	pthread_cond_t empty;
	void (*free_element)(void *);
} Queue;

extern Queue * create_queue(void (*)(void *));
extern void enqueue(Queue *q, void *, int);
extern int is_queue_empty(Queue *);
extern void * dequeue(Queue *);
extern void destroy_queue(Queue **);

#endif /* QUEUE_H */
