/*
	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/TestHarness.h"
extern "C" {
    #include "tacplus_srv_conn.h"
    #include "global.h"
    #include "parser.h"
    #include "statistics.h"

    bool go_offline_until_next_hold_down_expiry(struct tacplus_options *opts);
}
#include "ut_utils.h"

TEST_GROUP(ServerConnection) {

#define SET_OPTS_SERVER(O,I,A,P)                     \
    {                                                \
        CHECK(I < O->n_servers);                     \
        O->server[I].id = I;                         \
        O->server[I].addrs = tacplus_addrinfo(A, P); \
        SET_OPTS_SERVER_SRC_ADDR(O, I, NULL);        \
        O->server[I].timeout = (I+1)*5;              \
        O->server[I].secret = strdup(#I);            \
    }

#define SET_OPTS_SERVER_SRC_ADDR(O,I,S)                               \
    {                                                                 \
        O->server[I].src_addrs = S ? tacplus_addrinfo(S, "0") : NULL; \
    }

    static const int num_servers = 3;

    struct tacplus_options *opts;

    void setup()
    {
        CHECK_EQUAL(0, create_statistics(num_servers));

        connControl->opts = opts = tacplus_options_alloc(num_servers);
        CHECK(opts);

        SET_OPTS_SERVER(opts, 0, "1.1.1.1", "1");
        SET_OPTS_SERVER(opts, 1, "2.2.2.2", "2");
        SET_OPTS_SERVER(opts, 2, "3:3::3:3", "3");
    }

    void teardown()
    {
        cleanup_tacplus_options(&opts);
        POINTERS_EQUAL(NULL, opts);

        free_statistics();

        ut_reset_tac_connect_wrapper();
    }

};

#define PORT_STR_LEN (strlen("65535") + 1)

static struct tacplus_options *copy_tacplus_options(struct tacplus_options *src)
{
    struct tacplus_options *new_opts = tacplus_options_alloc(src->n_servers);
    CHECK(new_opts);

    memcpy(new_opts, src, sizeof(*src));

    for (unsigned i = 0; i < src->n_servers; i++) {
        struct tacplus_options::tacplus_options_server *server = &(src->server[i]);

        /* Quick and dirty copy for simple params */
        memcpy(&new_opts->server[server->id], server, sizeof(*server));

        /* Now need to properly copy params which point to allocated memory */
        char port_str[PORT_STR_LEN];
        int ret = snprintf(port_str, sizeof(port_str),
                           "%u", get_addrinfo_port(server->addrs));
        CHECK(ret > 0 && ret < (int) sizeof(port_str));

        SET_OPTS_SERVER(new_opts, server->id,
                        addrinfo_to_string(server->addrs), port_str);
        if (server->src_addrs)
            SET_OPTS_SERVER_SRC_ADDR(new_opts, server->id,
                                     addrinfo_to_string(server->src_addrs));
    }

    return new_opts;
}

TEST(ServerConnection, initOptions)
{
    CHECK_EQUAL(num_servers, opts->n_servers);
    CHECK_EQUAL(HIGHEST_PRIO_SERVER_ID, opts->curr_server);

    for (unsigned i = 0; i < opts->n_servers; i++) {
        struct tacplus_options::tacplus_options_server *serv = \
            (struct tacplus_options::tacplus_options_server *) tacplus_server(opts, i);
#ifndef HAVE_LIBTAC_EVENT
        CHECK_EQUAL(-1, serv->fd);
#endif
        CHECK_TIMESPEC_VALS(serv->state.lastTrouble, -1, -1);
    }
}

TEST(ServerConnection, lookupServer)
{
    struct tacplus_options::tacplus_options_server *serv;

    for (int i = 0; i < num_servers; i++) {
        serv = (struct tacplus_options::tacplus_options_server *) tacplus_server(opts, i);
        CHECK_EQUAL(i, serv->id);
    }

    /* Check out of bounds request */
    POINTERS_EQUAL(NULL, tacplus_server(opts, num_servers));
    POINTERS_EQUAL(NULL, tacplus_server(opts, num_servers+9999));
    POINTERS_EQUAL(NULL, tacplus_server(opts, -1));
}

#ifndef HAVE_LIBTAC_EVENT
TEST(ServerConnection, lookupCurrentServer)
{
    struct tacplus_options::tacplus_options_server *serv;

    CHECK_EQUAL(0, opts->curr_server);
    serv = (struct tacplus_options::tacplus_options_server *) tacplus_current_server(opts);
    CHECK_EQUAL(0, serv->id);

    opts->curr_server = 2;
    serv = (struct tacplus_options::tacplus_options_server *) tacplus_current_server(opts);
    CHECK_EQUAL(2, serv->id);

    opts->curr_server = INVALID_SERVER_ID;
    POINTERS_EQUAL(NULL, tacplus_current_server(opts));
}

TEST(ServerConnection, lookupCurrentSessionExtra)
{
    struct tac_session_extra extra, *ret;

    CHECK_EQUAL(0, opts->curr_server);
    ret = tacplus_current_session_extra(opts, &extra);

    POINTERS_EQUAL(&extra, ret);
    CHECK_EQUAL(0, extra.server_id);
    POINTERS_EQUAL(&opts->server[0], extra.server);

    opts->curr_server = 2;
    ret = tacplus_current_session_extra(opts, &extra);

    POINTERS_EQUAL(&extra, ret);
    CHECK_EQUAL(2, extra.server_id);
    POINTERS_EQUAL(&opts->server[2], extra.server);

    opts->curr_server = INVALID_SERVER_ID;
    ret = tacplus_current_session_extra(opts, &extra);

    POINTERS_EQUAL(&extra, ret);
    CHECK_EQUAL(INVALID_SERVER_ID, extra.server_id);
    POINTERS_EQUAL(NULL, extra.server);
}

TEST(ServerConnection, connectSingleServerNoHoldDown)
{
    opts->n_servers = 1;
    SET_OPTS_SERVER(opts, 0, "127.0.0.1", "100");
    SET_OPTS_SERVER_SRC_ADDR(opts, 0, "10.10.10.10");

    int fds[] = { 1, -1, 2 };
    ut_set_tac_connect_fds(fds, ARRAY_SIZE(fds));

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(1, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    CHECK_FALSE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(2, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    struct tac_connect_call exp_calls[] = {
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
    };

    struct tac_connect_call *calls;
    int calls_len = ut_get_tac_connect_calls(&calls);
    LONGS_EQUAL(ARRAY_SIZE(exp_calls), calls_len);

    for (int i = 0; i < calls_len; i++)
        CHECK_TRUE(ut_tac_connect_call_eq(&exp_calls[i], &calls[i]));
}

TEST(ServerConnection, connectSingleServerHoldDown)
{
    opts->n_servers = 1;
    SET_OPTS_SERVER(opts, 0, "127.0.0.1", "100");
    opts->server[0].hold_down = 10;

    int fds[] = { 1, -1, 2 };
    ut_set_tac_connect_fds(fds, ARRAY_SIZE(fds));

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(1, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    /* Check connect calls without a secret */
    free((void *) opts->server[0].secret);
    opts->server[0].secret = NULL;

    CHECK_FALSE(tacplus_connect());
    CHECK_FALSE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* Server is held down so there should be no attempt to connect */
    CHECK_FALSE(tacplus_connect());
    CHECK_FALSE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* Expire hold down timer */
    ut_inc_cur_mono_time(20, 0);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(2, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    struct tac_connect_call exp_calls[] = {
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = NULL,
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = NULL,
            .timeout = 5,
        },
    };

    struct tac_connect_call *calls;
    int calls_len = ut_get_tac_connect_calls(&calls);
    LONGS_EQUAL(ARRAY_SIZE(exp_calls), calls_len);

    for (int i = 0; i < calls_len; i++)
        CHECK_TRUE(ut_tac_connect_call_eq(&exp_calls[i], &calls[i]));
}

TEST(ServerConnection, connectMultiServerNoHoldDown)
{
    opts->n_servers = 2;
    SET_OPTS_SERVER(opts, 0, "127.0.0.1", "100");
    SET_OPTS_SERVER(opts, 1, "127.0.0.2", "100");
    SET_OPTS_SERVER_SRC_ADDR(opts, 0, "10.10.20.20");
    SET_OPTS_SERVER_SRC_ADDR(opts, 1, "20.20.10.10");

    int fds[] = { 1, -1, 2, -1, -1, 3 };
    ut_set_tac_connect_fds(fds, ARRAY_SIZE(fds));

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(1, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(2, opts->server[1].fd)
    CHECK_EQUAL(1, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* Both servers fail to connect */
    CHECK_FALSE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(-1, opts->server[1].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* Back to server 0 */
    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(3, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    struct tac_connect_call exp_calls[] = {
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = *(opts->server[1].src_addrs->ai_addr),
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = *(opts->server[1].src_addrs->ai_addr),
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
    };

    struct tac_connect_call *calls;
    int calls_len = ut_get_tac_connect_calls(&calls);
    LONGS_EQUAL(ARRAY_SIZE(exp_calls), calls_len);

    for (int i = 0; i < calls_len; i++)
        CHECK_TRUE(ut_tac_connect_call_eq(&exp_calls[i], &calls[i]));
}

TEST(ServerConnection, connectMultiServerHoldDown)
{
    SET_OPTS_SERVER(opts, 0, "127.0.0.1", "100");
    SET_OPTS_SERVER(opts, 1, "127.0.0.2", "100");
    SET_OPTS_SERVER(opts, 2, "127.0.0.3", "100");
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 10;
    opts->server[2].hold_down = 10;
    SET_OPTS_SERVER_SRC_ADDR(opts, 0, "10.10.10.10");
    SET_OPTS_SERVER_SRC_ADDR(opts, 2, "11.11.11.11");

    int fds[] = { 1, -1, 2, -1, 3, -1, 4, 5 };
    ut_set_tac_connect_fds(fds, ARRAY_SIZE(fds));

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(1, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(2, opts->server[1].fd)
    CHECK_EQUAL(1, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(-1, opts->server[1].fd);
    CHECK_EQUAL(3, opts->server[2].fd);
    CHECK_EQUAL(2, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    CHECK_FALSE(tacplus_connect());
    CHECK_FALSE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(-1, opts->server[1].fd);
    CHECK_EQUAL(-1, opts->server[2].fd);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* All servers are held down so there should be no attempt to connect to any */
    CHECK_FALSE(tacplus_connect());
    CHECK_FALSE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(-1, opts->server[1].fd);
    CHECK_EQUAL(-1, opts->server[2].fd);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* Expire hold down timers */
    ut_inc_cur_mono_time(20, 0);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(4, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    /* Should stick with server 0 on a subsequent connect */
    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(5, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    struct tac_connect_call exp_calls[] = {
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = {0},
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = {0},
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[2].addrs->ai_addr),
            .source_addr = *(opts->server[2].src_addrs->ai_addr),
            .key = "2",
            .timeout = 15,
        },
        {
            .server_addr = *(opts->server[2].addrs->ai_addr),
            .source_addr = *(opts->server[2].src_addrs->ai_addr),
            .key = "2",
            .timeout = 15,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = *(opts->server[0].src_addrs->ai_addr),
            .key = "0",
            .timeout = 5,
        },
    };

    struct tac_connect_call *calls;
    int calls_len = ut_get_tac_connect_calls(&calls);
    LONGS_EQUAL(ARRAY_SIZE(exp_calls), calls_len);

    for (int i = 0; i < calls_len; i++)
        CHECK_TRUE(ut_tac_connect_call_eq(&exp_calls[i], &calls[i]));
}

TEST(ServerConnection, connectMultiServerDiffHoldDown)
{
    SET_OPTS_SERVER(opts, 0, "127.0.0.1", "100");
    SET_OPTS_SERVER(opts, 1, "127.0.0.2", "100");
    SET_OPTS_SERVER(opts, 2, "127.0.0.3", "100");
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 5;
    opts->server[2].hold_down = 0;

    int fds[] = { 1, -1, 2, -1, 3, -1, 4, 5, 6, 7 };
    ut_set_tac_connect_fds(fds, ARRAY_SIZE(fds));

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(1, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(2, opts->server[1].fd)
    CHECK_EQUAL(1, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(-1, opts->server[1].fd);
    CHECK_EQUAL(3, opts->server[2].fd);
    CHECK_EQUAL(2, opts->curr_server);
    CHECK_EQUAL(1, opts->next_server);

    CHECK_FALSE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(-1, opts->server[0].fd);
    CHECK_EQUAL(-1, opts->server[1].fd);
    CHECK_EQUAL(-1, opts->server[2].fd);
    CHECK_EQUAL(2, opts->curr_server);
    CHECK_EQUAL(2, opts->next_server);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(4, opts->server[2].fd);
    CHECK_EQUAL(2, opts->curr_server);
    CHECK_EQUAL(1, opts->next_server);

    /* Expire hold down timer for server 1 */
    ut_inc_cur_mono_time(6, 0);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(5, opts->server[1].fd);
    CHECK_EQUAL(1, opts->curr_server);
    CHECK_EQUAL(0, opts->next_server);

    /* Expire hold down timer for server 0 */
    ut_inc_cur_mono_time(20, 0);

    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(6, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    /* Should stick with server 0 on a subsequent connect */
    CHECK_TRUE(tacplus_connect());
    CHECK_TRUE(tacplusd_online());
    CHECK_EQUAL(7, opts->server[0].fd);
    CHECK_EQUAL(0, opts->curr_server);
    CHECK_EQUAL(INVALID_SERVER_ID, opts->next_server);

    struct tac_connect_call exp_calls[] = {
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = {0},
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = {0},
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[2].addrs->ai_addr),
            .source_addr = {0},
            .key = "2",
            .timeout = 15,
        },
        {
            .server_addr = *(opts->server[2].addrs->ai_addr),
            .source_addr = {0},
            .key = "2",
            .timeout = 15,
        },
        {
            .server_addr = *(opts->server[2].addrs->ai_addr),
            .source_addr = {0},
            .key = "2",
            .timeout = 15,
        },
        {
            .server_addr = *(opts->server[1].addrs->ai_addr),
            .source_addr = {0},
            .key = "1",
            .timeout = 10,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = "0",
            .timeout = 5,
        },
        {
            .server_addr = *(opts->server[0].addrs->ai_addr),
            .source_addr = {0},
            .key = "0",
            .timeout = 5,
        },
    };

    struct tac_connect_call *calls;
    int calls_len = ut_get_tac_connect_calls(&calls);
    LONGS_EQUAL(ARRAY_SIZE(exp_calls), calls_len);

    for (int i = 0; i < calls_len; i++)
        CHECK_TRUE(ut_tac_connect_call_eq(&exp_calls[i], &calls[i]));
}
#endif

/*
 * Hold down timer tests
 */

TEST(ServerConnection, activateHoldDown)
{
    struct tacplus_options::tacplus_options_server *serv = &opts->server[0];

    CHECK_TIMESPEC_VALS(serv->state.lastTrouble, -1, -1);
    serv->hold_down = 10;

    ut_set_cur_mono_time(1245, 19828);
    tacplus_server_activate_hold_down((struct tacplus_options_server *)serv);
    CHECK_TIMESPEC_VALS(serv->state.lastTrouble, 1245, 19828);
    CHECK(tacplus_server_is_held_down((const struct tacplus_options_server *)serv));

    ut_set_cur_mono_time(97876757, 87687);
    tacplus_server_activate_hold_down((struct tacplus_options_server *)serv);
    CHECK_TIMESPEC_VALS(serv->state.lastTrouble, 97876757, 87687);
    CHECK(tacplus_server_is_held_down((const struct tacplus_options_server *)serv));
}

TEST(ServerConnection, resetHoldDown)
{
    struct tacplus_options::tacplus_options_server *serv = &opts->server[0];

    ut_set_cur_mono_time(110, 0);
    serv->hold_down = 10;

    SET_TIMESPEC_VALS(serv->state.lastTrouble, 105, 20221);
    CHECK_TIMESPEC_VALS(serv->state.lastTrouble, 105, 20221);

    CHECK(tacplus_server_is_held_down((const struct tacplus_options_server *)serv));

    tacplus_server_reset_hold_down((struct tacplus_options_server *)serv);
    CHECK_TIMESPEC_VALS(serv->state.lastTrouble, -1, -1);

    CHECK(! tacplus_server_is_held_down((const struct tacplus_options_server *)serv));
}

TEST(ServerConnection, remainingHoldDown)
{
    struct tacplus_options::tacplus_options_server serv = {};
    struct timespec remaining;
    bool held_down;

    ut_set_cur_mono_time(20, 500);

    /* No hold down configured, and no connection issues detected */
    UNSIGNED_LONGS_EQUAL(0, serv.hold_down);
    CHECK_TIMESPEC_VALS(serv.state.lastTrouble, 0, 0);

    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK_FALSE(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 0);

    /* Configure a hold down, still no connection issues detected */
    serv.hold_down = 10;
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK_FALSE(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 0);

    /* Experience some connection trouble */
    SET_TIMESPEC_VALS(serv.state.lastTrouble, 18, 99769);

    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 8, 99269);

    /* Some time passes */
    ut_set_cur_mono_time(24, 921978);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 3, 999177791);

    /* Not quite enough time passes */
    ut_set_cur_mono_time(28, 99768);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 1);

    /* Exactly enough time passes */
    ut_set_cur_mono_time(28, 99769);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK_FALSE(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 0);

    /* Some more time passes */
    ut_set_cur_mono_time(30, 10029);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK_FALSE(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 0);

    /* Experience some more connection trouble */
    SET_TIMESPEC_VALS(serv.state.lastTrouble, 30, 10029);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 10, 0);

    /* Some time passes */
    ut_set_cur_mono_time(32, 100);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 8, 9929);

    /* Enough time passes to expire timer again */
    ut_set_cur_mono_time(50, 89817);
    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK_FALSE(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 0);
}

TEST(ServerConnection, remainingHoldDownConfChange)
{
    struct tacplus_options::tacplus_options_server serv = {};
    struct timespec remaining;
    bool held_down;

    /* Hold down timer is active */
    ut_set_cur_mono_time(20, 500);
    serv.hold_down = 15;
    SET_TIMESPEC_VALS(serv.state.lastTrouble, 14, 21984);

    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 9, 21484);

    /* Hold down timer increases */
    serv.hold_down += 30;
    ut_set_cur_mono_time(24, 98897);

    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 34, 999923087);

    /* Hold down timer decreases */
    serv.hold_down -= 21;
    ut_set_cur_mono_time(26, 71298);

    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK(held_down);
    CHECK_TIMESPEC_VALS(remaining, 11, 999950686);

    /* Hold down timer disabled */
    serv.hold_down = 0;

    held_down = tacplus_server_remaining_hold_down((const struct tacplus_options_server *)
                                                    &serv, &remaining);
    CHECK_FALSE(held_down);
    CHECK_TIMESPEC_VALS(remaining, 0, 0);
}

TEST(ServerConnection, isHeldDown)
{
    struct tacplus_options::tacplus_options_server serv = {};
    bool held_down;

    held_down = tacplus_server_is_held_down((const struct tacplus_options_server *) &serv);
    CHECK_FALSE(held_down);

    /* Hold down timer is active */
    ut_set_cur_mono_time(30, 2480);
    serv.hold_down = 25;
    SET_TIMESPEC_VALS(serv.state.lastTrouble, 24, 21984);

    held_down = tacplus_server_is_held_down((const struct tacplus_options_server *) &serv);
    CHECK(held_down);

    /* Hold down timer increases */
    serv.hold_down += 30;
    ut_set_cur_mono_time(34, 98897);

    held_down = tacplus_server_is_held_down((const struct tacplus_options_server *) &serv);
    CHECK(held_down);

    /* Hold down timer decreases */
    serv.hold_down -= 21;
    ut_set_cur_mono_time(36, 71298);

    held_down = tacplus_server_is_held_down((const struct tacplus_options_server *) &serv);
    CHECK(held_down);

    /* Hold down timer disabled */
    serv.hold_down = 0;

    held_down = tacplus_server_is_held_down((const struct tacplus_options_server *) &serv);
    CHECK_FALSE(held_down);
}

TEST(ServerConnection, remainingHoldDownSecs)
{
    struct tacplus_options::tacplus_options_server serv = {};
    time_t remaining;

    /* Hold down timer is active */
    ut_set_cur_mono_time(20, 500);
    serv.hold_down = 15;
    SET_TIMESPEC_VALS(serv.state.lastTrouble, 14, 21984);

    remaining = tacplus_server_remaining_hold_down_secs(
                    (const struct tacplus_options_server *) &serv);
    LONGS_EQUAL(9, remaining);

    /* Hold down timer increases */
    serv.hold_down += 30;
    ut_set_cur_mono_time(24, 98897);

    remaining = tacplus_server_remaining_hold_down_secs(
                    (const struct tacplus_options_server *) &serv);
    LONGS_EQUAL(35, remaining);

    /* Hold down timer decreases */
    serv.hold_down -= 21;
    ut_set_cur_mono_time(26, 71298);

    remaining = tacplus_server_remaining_hold_down_secs(
                    (const struct tacplus_options_server *) &serv);
    LONGS_EQUAL(12, remaining);

    /* Hold down timer disabled */
    serv.hold_down = 0;

    remaining = tacplus_server_remaining_hold_down_secs(
                    (const struct tacplus_options_server *) &serv);
    LONGS_EQUAL(0, remaining);
}

TEST(ServerConnection, testGoOfflineNotAllHeldDown)
{
    SET_OPTS_SERVER(opts, 0, "127.0.0.1", "100");
    SET_OPTS_SERVER(opts, 1, "127.0.0.2", "100");
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 15;

    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[0]);
    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[1]);

    CHECK_TRUE(tacplus_server_is_held_down(
                    (const struct tacplus_options_server *)&opts->server[0]));
    CHECK_TRUE(tacplus_server_is_held_down(
                    (const struct tacplus_options_server *)&opts->server[1]));
    LONGS_EQUAL(0, opts->next_server);

    /*
     * Shouldn't go offline after expiring hold down on the 1st server.
     * The server was held down at t0 with a 10 second expiry, therefore
     * set time to t11 to expire the timer.
     */
    ut_inc_cur_mono_time(11, 0);
    CHECK_FALSE(go_offline_until_next_hold_down_expiry(opts));
    CHECK_TRUE(tacplusd_online());
}

TEST(ServerConnection, copyServerState)
{
    struct tacplus_options *new_opts;

    /* Set state on the current opts servers */
    SET_TIMESPEC_VALS(opts->server[0].state.lastTrouble, 10, 5);
    SET_TIMESPEC_VALS(opts->server[1].state.lastTrouble, -1, -1);
    SET_TIMESPEC_VALS(opts->server[2].state.lastTrouble, 767, 9867);

    /* Set some config - this should not be transferred */
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 15;
    opts->server[2].hold_down = 20;

    /* Exactly the same servers remain in the new opts */
    new_opts = tacplus_options_alloc(num_servers);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "2.2.2.2", "2");
    SET_OPTS_SERVER(new_opts, 2, "3:3::3:3", "3");

    CHECK_TIMESPEC_VALS(new_opts->server[0].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[1].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[2].state.lastTrouble, -1, -1);

    tacplus_copy_server_state(opts, new_opts);

    CHECK_TIMESPEC_VALS(new_opts->server[0].state.lastTrouble, 10, 5);
    CHECK_TIMESPEC_VALS(new_opts->server[1].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[2].state.lastTrouble, 767, 9867);
    CHECK_TIMESPEC_VALS(opts->server[0].state.lastTrouble, 10, 5);
    CHECK_TIMESPEC_VALS(opts->server[1].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(opts->server[2].state.lastTrouble, 767, 9867);

    CHECK_EQUAL(new_opts->server[0].hold_down, 0);
    CHECK_EQUAL(new_opts->server[1].hold_down, 0);
    CHECK_EQUAL(new_opts->server[2].hold_down, 0);
}

TEST(ServerConnection, copyServerStateSomeMatch)
{
    struct tacplus_options *new_opts;

    /* Set state on the current opts servers */
    SET_TIMESPEC_VALS(opts->server[0].state.lastTrouble, 10, 5);
    SET_TIMESPEC_VALS(opts->server[1].state.lastTrouble, -1, -1);
    SET_TIMESPEC_VALS(opts->server[2].state.lastTrouble, 767, 9867);

    /* Set some config - this should not be transferred */
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 15;
    opts->server[2].hold_down = 20;

    /* Only server ID 0 remains the same in the new opts */
    new_opts = tacplus_options_alloc(2);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "3.3.3.3", "3");

    CHECK_TIMESPEC_VALS(new_opts->server[0].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[1].state.lastTrouble, -1, -1);

    tacplus_copy_server_state(opts, new_opts);

    CHECK_TIMESPEC_VALS(new_opts->server[0].state.lastTrouble, 10, 5);
    CHECK_TIMESPEC_VALS(new_opts->server[1].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(opts->server[0].state.lastTrouble, 10, 5);
    CHECK_TIMESPEC_VALS(opts->server[1].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(opts->server[2].state.lastTrouble, 767, 9867);

    CHECK_EQUAL(new_opts->server[0].hold_down, 0);
    CHECK_EQUAL(new_opts->server[1].hold_down, 0);
}

TEST(ServerConnection, copyServerStateAdded)
{
    struct tacplus_options *new_opts;

    /* Set state on the current opts servers */
    SET_TIMESPEC_VALS(opts->server[0].state.lastTrouble, 10, 5);
    SET_TIMESPEC_VALS(opts->server[1].state.lastTrouble, 0, 2);
    SET_TIMESPEC_VALS(opts->server[2].state.lastTrouble, 767, 9867);

    /* Set some config - this should not be transferred */
    opts->server[0].hold_down = 0;
    opts->server[1].hold_down = 15;
    opts->server[2].hold_down = 20;

    /* Add an additional server to new opts */
    new_opts = tacplus_options_alloc(4);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "2.2.2.2", "200"); // Port does not affect match
    SET_OPTS_SERVER(new_opts, 2, "3:3::3:3", "33");
    SET_OPTS_SERVER(new_opts, 3, "4.4.4.4", "4");

    CHECK_TIMESPEC_VALS(new_opts->server[0].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[1].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[2].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(new_opts->server[3].state.lastTrouble, -1, -1);

    tacplus_copy_server_state(opts, new_opts);

    /* Hold down not was not previously configured - so last trouble should not be transferred */
    CHECK_TIMESPEC_VALS(new_opts->server[0].state.lastTrouble, -1, -1);

    CHECK_TIMESPEC_VALS(new_opts->server[1].state.lastTrouble, 0, 2);
    CHECK_TIMESPEC_VALS(new_opts->server[2].state.lastTrouble, 767, 9867);
    CHECK_TIMESPEC_VALS(new_opts->server[3].state.lastTrouble, -1, -1);
    CHECK_TIMESPEC_VALS(opts->server[0].state.lastTrouble, 10, 5);
    CHECK_TIMESPEC_VALS(opts->server[1].state.lastTrouble, 0, 2);
    CHECK_TIMESPEC_VALS(opts->server[2].state.lastTrouble, 767, 9867);

    CHECK_EQUAL(new_opts->server[0].hold_down, 0);
    CHECK_EQUAL(new_opts->server[1].hold_down, 0);
    CHECK_EQUAL(new_opts->server[2].hold_down, 0);
    CHECK_EQUAL(new_opts->server[3].hold_down, 0);
}

TEST(ServerConnection, tacplusReloadOptionsNull)
{
    struct tacplus_options *empty = NULL;

    POINTERS_EQUAL(NULL, tacplus_reload_options(&opts, NULL));
    POINTERS_EQUAL(NULL, opts);

    POINTERS_EQUAL(NULL, tacplus_reload_options(&empty, NULL));
    POINTERS_EQUAL(NULL, empty);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigWithTrouble)
{
    struct tacplus_options *opts_one, *opts_two, *opts_three;

    opts_one = tacplus_options_alloc(1);
    CHECK(opts_one);

    SET_OPTS_SERVER(opts_one, 0, "1.1.1.1", "1");

    /* Current server experienced trouble */
    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[0]);
    LONGS_EQUAL(0, opts->server[0].hold_down);

    /* Configure a hold down timer and reload */
    opts_one->server[0].hold_down = 10;
    ut_inc_cur_mono_time(3, 0);
    POINTERS_EQUAL(opts_one, tacplus_reload_options(&opts, opts_one));
    POINTERS_EQUAL(NULL, opts);

    /* Hold down timer should not be activated */
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&opts_one->server[0]));

    /* Unless we experience some more trouble on the server */
    ut_inc_cur_mono_time(2, 0);
    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts_one->server[0]);

    CHECK(tacplus_server_is_held_down(
            (struct tacplus_options_server *)&opts_one->server[0]));
    LONGS_EQUAL(10, tacplus_server_remaining_hold_down_secs(
                        (struct tacplus_options_server *)&opts_one->server[0]));

    /* Reconfigure with disabled hold down timers */
    opts_two = tacplus_options_alloc(1);
    CHECK(opts_two);

    SET_OPTS_SERVER(opts_two, 0, "1.1.1.1", "1");

    LONGS_EQUAL(0, opts_two->server[0].hold_down);

    POINTERS_EQUAL(opts_two, tacplus_reload_options(&opts_one, opts_two));
    POINTERS_EQUAL(NULL, opts_one);

    /* Hold down timer should not be activated */
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&opts_two->server[0]));

    /* Reconfigure with hold down timer once again */
    opts_three = tacplus_options_alloc(1);

    SET_OPTS_SERVER(opts_three, 0, "1.1.1.1", "1");
    opts_three->server[0].hold_down = 3000;

    POINTERS_EQUAL(opts_three, tacplus_reload_options(&opts_two, opts_three));
    POINTERS_EQUAL(NULL, opts_two);

    /* Hold down timer should not be activated */
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&opts_three->server[0]));

    cleanup_tacplus_options(&opts_three);
    POINTERS_EQUAL(NULL, opts_three);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigWithoutTrouble)
{
    struct tacplus_options *new_opts;

    new_opts = tacplus_options_alloc(2);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "3:3::3:3", "3");

    LONGS_EQUAL(0, opts->server[0].hold_down);

    /* Configure a hold down timer and reload */
    new_opts->server[0].hold_down = 10;
    ut_inc_cur_mono_time(3, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* Hold down timer should not be activated */
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&new_opts->server[0]));

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDisable)
{
    struct tacplus_options *new_opts;

    new_opts = tacplus_options_alloc(2);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "3:3::3:3", "3");

    LONGS_EQUAL(0, new_opts->server[0].hold_down);
    LONGS_EQUAL(0, new_opts->server[1].hold_down);

    /* Add hold down to current config */
    opts->server[0].hold_down = 15;
    opts->server[1].hold_down = 20;

    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[0]);

    CHECK(tacplus_server_is_held_down(
            (struct tacplus_options_server *)&opts->server[0]));

    ut_inc_cur_mono_time(10, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* Hold down timers should not be activated */
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&new_opts->server[0]));
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&new_opts->server[1]));

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigIncrement)
{
    struct tacplus_options *new_opts;

    new_opts = tacplus_options_alloc(2);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "3:3::3:3", "3");

    /* Add hold down to current config */
    opts->server[0].hold_down = 15;
    opts->server[1].hold_down = 20;

    /* Increase hold down of new config */
    new_opts->server[0].hold_down = 20;
    new_opts->server[1].hold_down = 25;

    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[0]);

    LONGS_EQUAL(15, tacplus_server_remaining_hold_down_secs(
                        (struct tacplus_options_server *)&opts->server[0]));

    ut_inc_cur_mono_time(10, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    LONGS_EQUAL(10, tacplus_server_remaining_hold_down_secs(
                        (struct tacplus_options_server *)&new_opts->server[0]));

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDecrement)
{
    struct tacplus_options *new_opts;

    new_opts = tacplus_options_alloc(2);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "3:3::3:3", "3");

    /* Add hold down to current config */
    opts->server[0].hold_down = 15;
    opts->server[1].hold_down = 20;

    /* Decrease hold down of new config */
    new_opts->server[0].hold_down = 10;
    new_opts->server[1].hold_down = 15;

    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[0]);

    LONGS_EQUAL(15, tacplus_server_remaining_hold_down_secs(
                        (struct tacplus_options_server *)&opts->server[0]));

    ut_inc_cur_mono_time(5, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    LONGS_EQUAL(5, tacplus_server_remaining_hold_down_secs(
                        (struct tacplus_options_server *)&new_opts->server[0]));

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDecrementBelowRemaining)
{
    struct tacplus_options *new_opts;

    new_opts = tacplus_options_alloc(2);
    CHECK(new_opts);

    SET_OPTS_SERVER(new_opts, 0, "1.1.1.1", "1");
    SET_OPTS_SERVER(new_opts, 1, "3:3::3:3", "3");

    /* Add hold down to current config */
    opts->server[0].hold_down = 15;
    opts->server[1].hold_down = 20;

    /* Decrease hold down of new config */
    new_opts->server[0].hold_down = 10;
    new_opts->server[1].hold_down = 15;

    tacplus_server_activate_hold_down(
        (struct tacplus_options_server *)&opts->server[0]);

    CHECK(tacplus_server_is_held_down(
            (struct tacplus_options_server *)&opts->server[0]));
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&opts->server[1]));

    ut_inc_cur_mono_time(12, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&new_opts->server[0]));
    CHECK(! tacplus_server_is_held_down(
                (struct tacplus_options_server *)&new_opts->server[1]));

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsNoHoldDownConfigOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Verify no hold down on current and new config */
    for (unsigned i = 0; i < opts->n_servers; i++) {
        LONGS_EQUAL(0, opts->server[i].hold_down);
        LONGS_EQUAL(0, new_opts->server[i].hold_down);
    }

    /* No hold down - we should be online */
    CHECK_TRUE(tacplusd_online());

    /* Pass some time and reload */
    ut_inc_cur_mono_time(10, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* Still No hold down - we should still be online */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Verify no hold down on current config */
    for (unsigned i = 0; i < opts->n_servers; i++)
        LONGS_EQUAL(0, opts->server[i].hold_down);

    /* Add hold down to new config */
    new_opts->server[0].hold_down = 10;
    new_opts->server[1].hold_down = 15;
    new_opts->server[2].hold_down = 20;

    /* No hold down - we should be online */
    CHECK_TRUE(tacplusd_online());

    /* Pass some time and reload */
    ut_inc_cur_mono_time(5, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* Now have hold down but no trouble - we should still be online */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

static void ut_do_failing_tacplus_connect(
    struct tacplus_options *opts, bool enforce_go_offline)
{
    int *fds = (int *) calloc(opts->n_servers, sizeof(int));
    CHECK(fds);

    unsigned num_servers_with_hold_down = 0;
    for (unsigned i = 0; i < opts->n_servers; i++) {
        if (opts->server[i].hold_down > 0)
            num_servers_with_hold_down++;
        fds[i] = -1;
    }
    ut_set_tac_connect_fds(fds, opts->n_servers);

    if (enforce_go_offline) {
        LONGS_EQUAL_TEXT(opts->n_servers, num_servers_with_hold_down,
                         "Test requires a hold down on all servers");
    }
    else {
        CHECK_TEXT(num_servers_with_hold_down < opts->n_servers,
                   "Test requires no hold down on at least one server");
    }

    CHECK_FALSE(tacplus_connect());
    CHECK_TEXT(tacplusd_online() == !enforce_go_offline,
               "Unexpected online state");

    ut_reset_tac_connect_wrapper();
    free(fds);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigWithTroubleOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Verify no hold down on current config */
    for (unsigned i = 0; i < opts->n_servers; i++)
        LONGS_EQUAL(0, opts->server[i].hold_down);

    /* Add hold down to new config */
    new_opts->server[0].hold_down = 10;
    new_opts->server[1].hold_down = 15;
    new_opts->server[2].hold_down = 20;

    /* Experience trouble on all servers */
    ut_do_failing_tacplus_connect(opts, false);

    /* No hold down - we should be online despite trouble */
    CHECK_TRUE(tacplusd_online());

    /* Pass some time and reload */
    ut_inc_cur_mono_time(5, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /*
     * We should still be online - previous trouble is ignored on a
     * newly configured hold down timer.
     */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDisableOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Add hold down to current config */
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 15;
    opts->server[2].hold_down = 20;

    /* Verify no hold down on new config */
    for (unsigned i = 0; i < new_opts->n_servers; i++)
        LONGS_EQUAL(0, new_opts->server[i].hold_down);

    /* Go offline */
    ut_do_failing_tacplus_connect(opts, true);

    /* Pass some time (but still within offline period) and reload */
    ut_inc_cur_mono_time(5, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* Hold down was removed - we should be online again */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDisableOneOnlineCheck)
{
    struct tacplus_options *new_opts;

    /* Add hold down to current config */
    opts->server[0].hold_down = 20;
    opts->server[1].hold_down = 25;
    opts->server[2].hold_down = 30;

    new_opts = copy_tacplus_options(opts);

    /* Remove hold down from second server in new config */
    new_opts->server[1].hold_down = 0;
    LONGS_EQUAL(20, new_opts->server[0].hold_down);
    LONGS_EQUAL(30, new_opts->server[2].hold_down);

    /* Go offline */
    ut_do_failing_tacplus_connect(opts, true);

    /* Pass some time (but still within offline period) and reload */
    ut_inc_cur_mono_time(15, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* We should be online again since server 2 is now available */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigIncrementOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Add hold down to current config */
    opts->server[0].hold_down = 10;
    opts->server[1].hold_down = 15;
    opts->server[2].hold_down = 20;

    /* Increase hold down on new config */
    new_opts->server[0].hold_down = 20;
    new_opts->server[1].hold_down = 25;
    new_opts->server[2].hold_down = 30;

    /* Go offline */
    ut_do_failing_tacplus_connect(opts, true);

    /* Pass some time (but still within offline period) and reload */
    ut_inc_cur_mono_time(5, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* We should still be offline */
    CHECK_FALSE(tacplusd_online());

    /* Pass enough time that the original hold down would have expired */
    ut_inc_cur_mono_time(6, 0);

    /* We should still be offline */
    CHECK_FALSE(tacplusd_online());

    /* Pass enough time that the first server hold down expires */
    ut_inc_cur_mono_time(10, 0);

    /* We should be online again */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDecrementOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Add hold down to current config */
    opts->server[0].hold_down = 20;
    opts->server[1].hold_down = 25;
    opts->server[2].hold_down = 30;

    /* Decrease hold down on new config */
    new_opts->server[0].hold_down = 10;
    new_opts->server[1].hold_down = 15;
    new_opts->server[2].hold_down = 20;

    /* Go offline */
    ut_do_failing_tacplus_connect(opts, true);

    /* Pass some time (but still within offline period) and reload */
    ut_inc_cur_mono_time(5, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* We should still be offline */
    CHECK_FALSE(tacplusd_online());

    /* Pass enough time that the new hold down expires */
    ut_inc_cur_mono_time(6, 0);

    /* We should be online again */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(ServerConnection, tacplusReloadOptionsHoldDownConfigDecrementBelowRemainingOnlineCheck)
{
    struct tacplus_options *new_opts = copy_tacplus_options(opts);

    /* Add hold down to current config */
    opts->server[0].hold_down = 20;
    opts->server[1].hold_down = 25;
    opts->server[2].hold_down = 30;

    /* Decrease hold down on new config */
    new_opts->server[0].hold_down = 10;
    new_opts->server[1].hold_down = 15;
    new_opts->server[2].hold_down = 20;

    /* Go offline */
    ut_do_failing_tacplus_connect(opts, true);

    /* Pass enough time that the new hold down expires */
    ut_inc_cur_mono_time(15, 0);
    POINTERS_EQUAL(new_opts, tacplus_reload_options(&opts, new_opts));

    /* We should be online again */
    CHECK_TRUE(tacplusd_online());

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}
