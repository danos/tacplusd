/*
	Copyright (c) 2018-2019 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/TestHarness.h"
extern "C" {
    #include <netinet/ip.h>
    #include "parser.h"
}

TEST_GROUP(Parser)
{
    static void check_server_opts(struct tacplus_options::tacplus_options_server *expect_serv,
                                  struct tacplus_options::tacplus_options_server *conf_serv)
    {
        CHECK(conf_serv != expect_serv);

        UNSIGNED_LONGS_EQUAL(expect_serv->id, conf_serv->id);
        CHECK(sockaddr_addr_equal(expect_serv->addrs->ai_addr,
                                  conf_serv->addrs->ai_addr));
        UNSIGNED_LONGS_EQUAL(get_addrinfo_port(expect_serv->addrs),
                             get_addrinfo_port(conf_serv->addrs));

        if (! expect_serv->src_addrs) {
            POINTERS_EQUAL(NULL, conf_serv->src_addrs);
        }
        else {
            CHECK(sockaddr_addr_equal(expect_serv->src_addrs->ai_addr,
                                      conf_serv->src_addrs->ai_addr));
        }

        if (! expect_serv->src_intf) {
            POINTERS_EQUAL(NULL, conf_serv->src_intf);
        }
        else {
            STRCMP_EQUAL(expect_serv->src_intf, conf_serv->src_intf);
        }

        STRCMP_EQUAL(expect_serv->secret, conf_serv->secret);
        UNSIGNED_LONGS_EQUAL(expect_serv->hold_down, conf_serv->hold_down);
        UNSIGNED_LONGS_EQUAL(expect_serv->timeout, conf_serv->timeout);

#ifdef HAVE_LIBTAC_EVENT
        CHECK(! conf_serv->session);
#else
        LONGS_EQUAL(-1, conf_serv->fd);
#endif
    }

    void test_typical(struct tacplus_options *loaded_opts)
    {
        struct tacplus_options::tacplus_options_server *serv1, *serv2;

        struct tacplus_options::tacplus_options_server expect_serv1 = {
            .id = 0,
            .addrs = tacplus_addrinfo("1.1.1.1", "49"),
            .src_addrs = NULL,
            .src_intf = "eth0",
            .timeout = 3,
            .hold_down = 0,
            .secret = "foo",
        };

        struct tacplus_options::tacplus_options_server expect_serv2 = {
            .id = 1,
            .addrs = tacplus_addrinfo("2:2::2:2", "200"),
            .src_addrs = tacplus_addrinfo("1:1::1:1", ""),
            .src_intf = NULL,
            .timeout = 10,
            .hold_down = 12,
            .secret = "bar",
        };

        CHECK(loaded_opts);

        CHECK(!loaded_opts->broadcast);
        UNSIGNED_LONGS_EQUAL(2, loaded_opts->setupTimeout);
        UNSIGNED_LONGS_EQUAL(16<<2, loaded_opts->dscp);

        UNSIGNED_LONGS_EQUAL(2, loaded_opts->n_servers);
        UNSIGNED_LONGS_EQUAL(0, loaded_opts->curr_server);
        UNSIGNED_LONGS_EQUAL(INVALID_SERVER_ID, loaded_opts->next_server);

        serv1 = (struct tacplus_options::tacplus_options_server *) tacplus_server(loaded_opts, 0);
        check_server_opts(&expect_serv1, serv1);

        serv2 = (struct tacplus_options::tacplus_options_server *) tacplus_server(loaded_opts, 1);
        check_server_opts(&expect_serv2, serv2);
    }

    void test_typical_changed_hold_down(struct tacplus_options *loaded_opts)
    {
        struct tacplus_options::tacplus_options_server *serv1, *serv2;

        struct tacplus_options::tacplus_options_server expect_serv1 = {
            .id = 0,
            .addrs = tacplus_addrinfo("1.1.1.1", "49"),
            .src_addrs = NULL,
            .src_intf = "eth0",
            .timeout = 3,
            .hold_down = 10,
            .secret = "foo",
        };

        struct tacplus_options::tacplus_options_server expect_serv2 = {
            .id = 1,
            .addrs = tacplus_addrinfo("2:2::2:2", "200"),
            .src_addrs = tacplus_addrinfo("1:1::1:1", ""),
            .src_intf = NULL,
            .timeout = 10,
            .hold_down = 5,
            .secret = "bar",
        };

        CHECK(loaded_opts);

        CHECK(!loaded_opts->broadcast);
        UNSIGNED_LONGS_EQUAL(2, loaded_opts->setupTimeout);
        UNSIGNED_LONGS_EQUAL(IPTOS_CLASS_CS6, loaded_opts->dscp);

        UNSIGNED_LONGS_EQUAL(2, loaded_opts->n_servers);
        UNSIGNED_LONGS_EQUAL(0, loaded_opts->curr_server);
        UNSIGNED_LONGS_EQUAL(INVALID_SERVER_ID, loaded_opts->next_server);

        serv1 = (struct tacplus_options::tacplus_options_server *) tacplus_server(loaded_opts, 0);
        check_server_opts(&expect_serv1, serv1);

        serv2 = (struct tacplus_options::tacplus_options_server *) tacplus_server(loaded_opts, 1);
        check_server_opts(&expect_serv2, serv2);
    }
};

TEST(Parser, nonExistentFile)
{
    struct tacplus_options *opts = tacplus_parse_options("config/UNKNOWN");
    POINTERS_EQUAL(NULL, opts);
}

TEST(Parser, typical)
{
    struct tacplus_options *opts = tacplus_parse_options("config/typical");
    test_typical(opts);

    cleanup_tacplus_options(&opts);
    POINTERS_EQUAL(NULL, opts);
}

TEST(Parser, typicalChangedHoldDown)
{
    struct tacplus_options *opts = tacplus_parse_options("config/typical-changed-hold-down");
    test_typical_changed_hold_down(opts);

    cleanup_tacplus_options(&opts);
    POINTERS_EQUAL(NULL, opts);
}

TEST(Parser, reloadTypicalChangedHoldDown)
{
    struct tacplus_options *opts = tacplus_parse_options("config/typical");
    test_typical(opts);

    struct tacplus_options *new_opts = tacplus_parse_reload_options(
                                            "config/typical-changed-hold-down", &opts);
    POINTERS_EQUAL(NULL, opts);
    test_typical_changed_hold_down(new_opts);

    cleanup_tacplus_options(&new_opts);
    POINTERS_EQUAL(NULL, new_opts);
}

TEST(Parser, typicalBroadcast)
{
    struct tacplus_options::tacplus_options_server *serv1, *serv2;

    struct tacplus_options::tacplus_options_server expect_serv1 = {
        .id = 0,
        .addrs = tacplus_addrinfo("1.1.1.2", "149"),
        .src_addrs = tacplus_addrinfo("2.2.2.2", ""),
        .src_intf = NULL,
        .timeout = 3,
        .hold_down = 0,
        .secret = "foobar",
    };

    struct tacplus_options::tacplus_options_server expect_serv2 = {
        .id = 1,
        .addrs = tacplus_addrinfo("2:2::2:2", "85"),
        .src_addrs = NULL,
        .src_intf = "eth3",
        .timeout = 15,
        .hold_down = 3600,
        .secret = "bar",
    };

    struct tacplus_options *opts = tacplus_parse_options("config/typical-broadcast");
    CHECK(opts);

#ifdef HAVE_LIBTAC_EVENT
    CHECK(opts->broadcast);
#else
    CHECK(!opts->broadcast);
#endif

    UNSIGNED_LONGS_EQUAL(4, opts->setupTimeout);
    UNSIGNED_LONGS_EQUAL(IPTOS_CLASS_CS6, opts->dscp);

    UNSIGNED_LONGS_EQUAL(2, opts->n_servers);
    UNSIGNED_LONGS_EQUAL(0, opts->curr_server);
    UNSIGNED_LONGS_EQUAL(INVALID_SERVER_ID, opts->next_server);

    serv1 = (struct tacplus_options::tacplus_options_server *) tacplus_server(opts, 0);
    check_server_opts(&expect_serv1, serv1);

    serv2 = (struct tacplus_options::tacplus_options_server *) tacplus_server(opts, 1);
    check_server_opts(&expect_serv2, serv2);

    cleanup_tacplus_options(&opts);
    POINTERS_EQUAL(NULL, opts);
}
