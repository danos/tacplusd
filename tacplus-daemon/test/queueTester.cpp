/*
	Copyright (c) 2018,2021 AT&T Intellectual Property.
	Copyright (c) 2015 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/TestHarness.h"
extern "C" {
    #include "queue.h"
}

struct test_elem {
    int num;
    int prio;
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

    void reset() {
        teardown();
        setup();
    }

    void check_q_rear_null(void) {
        int i;
        for (i = 0; i < NR_PRIORITY; ++i) {
            POINTERS_EQUAL(NULL, q->rear[i]);
        }
    }

    void check_q_rear_null_except(int prio) {
        int i;
        for (i = 0; i < NR_PRIORITY; ++i) {
            if (i == prio) {
                CHECK(q->rear[i] != NULL);
            } else {
                POINTERS_EQUAL(NULL, q->rear[i]);
            }
        }
    }
};

TEST(Queueing, EnqueueSingle)
{
    int prio;
    for (prio = 0; prio < NR_PRIORITY; ++prio) {
        struct test_elem *pair = (struct test_elem *)malloc(sizeof(struct test_elem));
        int empty;

        POINTERS_EQUAL(NULL, q->front);
        check_q_rear_null();

        enqueue(q, pair, prio);

        CHECK(q->front != NULL);
        check_q_rear_null_except(prio);
        CHECK(q->front == q->rear[prio]);

        empty = is_queue_empty(q);
        LONGS_EQUAL(0, empty);

        reset();
    }
}


TEST(Queueing, DequeueEmpty)
{
    struct test_elem *pair_consumed;
    int empty;

    POINTERS_EQUAL(NULL, q->front);
    check_q_rear_null();

    empty = is_queue_empty(q);
    LONGS_EQUAL(1, empty);

    pair_consumed = (struct test_elem *)dequeue(q);
    POINTERS_EQUAL(NULL, pair_consumed);
    LONGS_EQUAL(1, empty);
};

TEST(Queueing, DequeueNonEmpty)
{
    int prio;

    for (prio = 0; prio < NR_PRIORITY; ++prio) {
        struct test_elem *pair = (struct test_elem *)malloc(sizeof(struct test_elem));
        struct test_elem *pair_consumed;
        int empty;

        POINTERS_EQUAL(NULL, q->front);
        check_q_rear_null();

        enqueue(q, pair, prio);

        CHECK(q->front != NULL);
        check_q_rear_null_except(prio);

        pair_consumed = (struct test_elem *)dequeue(q);
        POINTERS_EQUAL(pair, pair_consumed);

        empty = is_queue_empty(q);
        LONGS_EQUAL(1, empty);

        free(pair);
        reset();
    }
};

TEST(Queueing, DequeueMultiple)
{
    int prio;
    for (prio = 0; prio < NR_PRIORITY; ++prio) {
        struct test_elem *pair1 = (struct test_elem *)malloc(sizeof(struct test_elem));
        struct test_elem *pair2 = (struct test_elem *)malloc(sizeof(struct test_elem));
        struct test_elem *pair3 = (struct test_elem *)malloc(sizeof(struct test_elem));
        struct test_elem *pair_consumed1;
        struct test_elem *pair_consumed2;
        struct test_elem *pair_consumed3;
        Node *rear;
        int empty;

        POINTERS_EQUAL(NULL, q->front);
        check_q_rear_null();

        rear = q->rear[prio];
        enqueue(q, pair1, prio);
        CHECK(q->rear[prio] != rear);

        CHECK(q->front != NULL);
        check_q_rear_null_except(prio);
        POINTERS_EQUAL(q->front, q->rear[prio]);

        rear = q->rear[prio];
        enqueue(q, pair2, prio);
        CHECK(q->rear[prio] != rear);

        check_q_rear_null_except(prio);
        CHECK(q->front != q->rear[prio]);

        rear = q->rear[prio];
        enqueue(q, pair3, prio);
        CHECK(q->rear[prio] != rear);

        CHECK(q->front != q->rear[prio]);
        check_q_rear_null_except(prio);

        empty = is_queue_empty(q);
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
        reset();
    }
};

TEST(Queueing, EnqueuePrioMultiple)
{
    const int pairs_per_prio = 4;
    const int npairs = NR_PRIORITY * pairs_per_prio;
    struct test_elem *pairs[npairs];
    struct test_elem *pairs_consumed[npairs];
    int expected[npairs];
    int expected_index;
    int empty;
    int i;

    for(i = 0; i < npairs; ++i) {
        pairs[i] = (struct test_elem *)malloc(sizeof(struct test_elem));
        pairs[i]->num = i;
        pairs[i]->prio = i % NR_PRIORITY;
        enqueue(q, pairs[i], pairs[i]->prio);
        expected_index = ((MAX_PRIORITY - pairs[i]->prio) * pairs_per_prio) + (i / NR_PRIORITY);
        expected[expected_index] = pairs[i]->num;
        CHECK(q->front->prio >= pairs[i]->prio); // Front element priority must never decrease.
    }

    for (i = 0; i < npairs; ++i) {
        pairs_consumed[i] = (struct test_elem *)dequeue(q);
        printf("pair:num = %d prio = %d\n", pairs_consumed[i]->num, pairs_consumed[i]->prio);
    }

    empty = is_queue_empty(q);
    LONGS_EQUAL(1, empty);

    /* Check ordering */
    for (i = 0; i < npairs - 1; ++i) {
       LONGS_EQUAL(expected[i], pairs_consumed[i]->num);
       CHECK(pairs_consumed[i]->prio >= pairs_consumed[i+1]->prio);
       if (pairs_consumed[i]->prio == pairs_consumed[i+1]->prio) {
           CHECK(pairs_consumed[i]->num < pairs_consumed[i+1]->num);
           CHECK(pairs_consumed[i]->prio == pairs_consumed[i]->num % NR_PRIORITY);
       }
       POINTERS_EQUAL(pairs_consumed[i], pairs[pairs_consumed[i]->num]);
    }
    CHECK(pairs_consumed[i]->prio == pairs_consumed[i]->num % NR_PRIORITY);


    for (i = 0; i < npairs; ++i)
       free(pairs[i]);
};

