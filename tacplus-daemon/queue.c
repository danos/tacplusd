/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "queue.h"

Queue * create_queue(void (*free_element)(void *))
{
	Queue *q;
	q = malloc(sizeof(*q));

	if (q == NULL) {
		syslog(LOG_ERR, "Failed to allocate queue");
	}
	else {
		q->front = NULL;
		q->rear = NULL;
		q->free_element = free_element;
		pthread_mutex_init(&(q->lock), NULL);
		pthread_cond_init(&(q->empty), NULL);
	}
	return q;
}

void enqueue(Queue *q, void *e)
{
	Node *n;

	if (q == NULL || e == NULL)
		return;

	pthread_mutex_lock(&(q->lock));

	n = malloc(sizeof(*n));
	n->element = e;
	n->next = NULL;

	if (is_queue_empty(q)) {
		q->front = n;
		q->rear = n;
	}
	else {
		q->rear->next = n;
		q->rear = n;
	}
	pthread_cond_broadcast(&(q->empty));
	pthread_mutex_unlock(&(q->lock));
}

void re_enqueue(Queue *q, void *e)
{
	Node *n;

	if (q == NULL || e == NULL)
		return;

	pthread_mutex_lock(&(q->lock));

	n = malloc(sizeof(*n));
	n->element = e;
	n->next = q->front;

	if (is_queue_empty(q)) {
		q->front = n;
		q->rear = n;
	}
	else {
		q->front = n;
	}
	pthread_cond_broadcast(&(q->empty));
	pthread_mutex_unlock(&(q->lock));
}

void * dequeue(Queue *q)
{
	Node *n, *nextNode;
	void *data = NULL;

	pthread_mutex_lock(&(q->lock));

	if (!is_queue_empty(q)) {
		n = q->front;
		nextNode = q->front->next;
		if (q->front == q->rear) {
			q->rear = nextNode;
		}
		q->front = nextNode;
		data = n->element;
		free(n);
	}
	pthread_cond_broadcast(&(q->empty));
	pthread_mutex_unlock(&(q->lock));
	return data;
}

int is_queue_empty(Queue *q)
{
	return (q->front == NULL);
}

void destroy_queue(Queue **q)
{
	Node *n = NULL;
	Node *next_n;

	if (!q || !*q)
		return;

	for (n = (*q)->front; n != NULL ; n = next_n) {
		next_n = n->next;
		if((*q)->free_element)
			(*q)->free_element(n->element);
		free(n);
	}

	pthread_mutex_destroy(&((*q)->lock));
	pthread_cond_destroy(&((*q)->empty));

	free(*q);
	*q = NULL;
}

