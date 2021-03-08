/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018,2021 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "queue.h"

Queue * create_queue(void (*free_element)(void *))
{
	Queue *q;
	int i;

	q = malloc(sizeof(*q));

	if (q == NULL) {
		syslog(LOG_ERR, "Failed to allocate queue");
	}
	else {
		q->front = NULL;
		for (i = 0; i < NR_PRIORITY; ++i)
			q->rear[i] = NULL;
		q->free_element = free_element;
		pthread_mutex_init(&(q->lock), NULL);
		pthread_cond_init(&(q->empty), NULL);
	}
	return q;
}

/*
 * Finds the insertion node for a particular node, the node is
 * before all the nodes with node->prio < prio, but after all the
 * nodes previously inserted the same prio. Instead of doing a linear
 * search over the queue elements, the insertion uses q->rear[prio]
 * to identify the last inserted node at current priority.
 * if q->rear[prio] is NULL:
 *      returns the next non NULL q->rear[prio].
 *      if there is no node with higher priority, then this function
 *      returns NULL indicating the Node needs to be inserted at queue
 *      front.
 */
static Node *find_rear_prio(Queue *q, int prio)
{
	int i;
	for (i = prio; i < NR_PRIORITY; ++i) {
		if (q->rear[i])
			return q->rear[i];
	}
	return NULL;
}

static int fix_prio(int prio)
{
	if (prio < MIN_PRIORITY)
		return MIN_PRIORITY;
	if (prio > MAX_PRIORITY)
		return MAX_PRIORITY;
	return prio;
}

void enqueue(Queue *q, void *e, int prio)
{
	Node *n;
	Node *rear;
	Node **pnext;

	if (q == NULL || e == NULL)
		return;
	prio = fix_prio(prio);

	pthread_mutex_lock(&(q->lock));
	rear = find_rear_prio(q, prio);

	if (rear)
		pnext = &rear->next;
	else
		pnext = &q->front;

	n = malloc(sizeof(*n));
	n->element = e;
	n->prio = prio;
	n->next = *pnext;
	*pnext = n;
	q->rear[prio] = n;

	pthread_cond_broadcast(&(q->empty));
	pthread_mutex_unlock(&(q->lock));
}

void * dequeue(Queue *q)
{
	Node *n;
	void *data = NULL;

	pthread_mutex_lock(&(q->lock));

	if (!is_queue_empty(q)) {
		n = q->front;
		data = n->element;
		if (n == q->rear[n->prio])
			q->rear[n->prio] = NULL;
		q->front = n->next;
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
