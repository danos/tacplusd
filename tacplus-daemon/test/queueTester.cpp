/*
	Copyright (c) 2018 AT&T Intellectual Property.
	Copyright (c) 2015 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/TestHarness.h"
extern "C" {
    #include "queue.h"
}

struct test_elem {
    int num;
    void *opaque;
};

TEST_GROUP(Queueing)
{
    Queue *q;

    void setup() {
        q = create_queue(NULL);
        CHECK(q);
    }

    void teardown (void) {
        destroy_queue(&q);
        POINTERS_EQUAL(NULL, q);
    }
};

TEST(Queueing, EnqueueSingle)
{
    struct test_elem *pair = (struct test_elem *)malloc(sizeof(struct test_elem));
    int empty;

    POINTERS_EQUAL(NULL, q->front);
    POINTERS_EQUAL(NULL, q->rear);

    enqueue(q, pair);

    CHECK(q->front != NULL);
    CHECK(q->rear != NULL);
    CHECK(q->front == q->rear);

    empty = is_queue_empty(q);
    LONGS_EQUAL(0, empty)

    /* memory pointed to by pair will be freed in teardown */
};

TEST(Queueing, DequeueEmpty)
{
    struct test_elem *pair_consumed;
    int empty;

    POINTERS_EQUAL(NULL, q->front);
    POINTERS_EQUAL(NULL, q->rear);

    empty = is_queue_empty(q);
    LONGS_EQUAL(1, empty);

    pair_consumed = (struct test_elem *)dequeue(q);
    POINTERS_EQUAL(NULL, pair_consumed);
    LONGS_EQUAL(1, empty);
};

TEST(Queueing, DequeueNonEmpty)
{
    struct test_elem *pair = (struct test_elem *)malloc(sizeof(struct test_elem));
    struct test_elem *pair_consumed;
    int empty;

    POINTERS_EQUAL(NULL, q->front);
    POINTERS_EQUAL(NULL, q->rear);

    enqueue(q, pair);

    CHECK(q->front != NULL);
    CHECK(q->rear != NULL);

    pair_consumed = (struct test_elem *)dequeue(q);
    POINTERS_EQUAL(pair, pair_consumed);

    empty = is_queue_empty(q);
    LONGS_EQUAL(1, empty)

    free(pair);
};

TEST(Queueing, DequeueMultiple)
{
    struct test_elem *pair1 = (struct test_elem *)malloc(sizeof(struct test_elem));
    struct test_elem *pair2 = (struct test_elem *)malloc(sizeof(struct test_elem));
    struct test_elem *pair3 = (struct test_elem *)malloc(sizeof(struct test_elem));
    struct test_elem *pair_consumed1;
    struct test_elem *pair_consumed2;
    struct test_elem *pair_consumed3;
    Node *rear;
    int empty;

    POINTERS_EQUAL(NULL, q->front);
    POINTERS_EQUAL(NULL, q->rear);

    rear = q->rear;
    enqueue(q, pair1);
    CHECK(q->rear != rear);

    CHECK(q->front != NULL);
    CHECK(q->rear != NULL);
    POINTERS_EQUAL(q->front, q->rear);

    rear = q->rear;
    enqueue(q, pair2);
    CHECK(q->rear != rear);

    CHECK(q->front != q->rear);

    rear = q->rear;
    enqueue(q, pair3);
    CHECK(q->rear != rear);

    CHECK(q->front != q->rear);

    LONGS_EQUAL(0, empty);

    pair_consumed1 = (struct test_elem *)dequeue(q);
    POINTERS_EQUAL(pair1, pair_consumed1);
    free(pair1);

    pair_consumed2 = (struct test_elem *)dequeue(q);
    POINTERS_EQUAL(pair2, pair_consumed2);
    free(pair2);

    pair_consumed3 = (struct test_elem *)dequeue(q);
    POINTERS_EQUAL(pair3, pair_consumed3);
    free(pair3);

    empty = is_queue_empty(q);
    LONGS_EQUAL(1, empty);
};

