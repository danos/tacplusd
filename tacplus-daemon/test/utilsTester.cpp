/*
	Copyright (c) 2018-2019 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/TestHarness.h"
extern "C" {
    #include "utils.h"
}
#include "ut_utils.h"

TEST_GROUP(Utils) {};

TEST(Utils, tacplusAddrInfoV4)
{
    struct addrinfo *addr;
    char addr_str[INET_ADDRSTRLEN];
    char port_str[6];
    int ret;

    addr = tacplus_addrinfo("192.168.122.7", "66");
    CHECK(addr != NULL);

    ret = getnameinfo(addr->ai_addr, addr->ai_addrlen,
                      addr_str, INET_ADDRSTRLEN,
                      port_str, sizeof port_str,
                      NI_NUMERICHOST|NI_NUMERICSERV);
    CHECK(ret == 0);

    STRCMP_EQUAL("192.168.122.7", addr_str);
    STRCMP_EQUAL("66", port_str);

    freeaddrinfo(addr);
};

TEST(Utils, tacplusAddrInfoV6)
{
    struct addrinfo *addr;
    char addr_str[INET6_ADDRSTRLEN];
    char port_str[6];
    int ret;

    addr = tacplus_addrinfo("fe80::177", "49");
    CHECK(addr != NULL);

    ret = getnameinfo(addr->ai_addr, addr->ai_addrlen,
                      addr_str, INET6_ADDRSTRLEN,
                      port_str, sizeof port_str,
                      NI_NUMERICHOST|NI_NUMERICSERV);
    CHECK(ret == 0);

    STRCMP_EQUAL("fe80::177", addr_str);
    STRCMP_EQUAL("49", port_str);

    freeaddrinfo(addr);
};

TEST(Utils, tacplusAddrInfoInvalid)
{
    struct addrinfo *addr;

    addr = tacplus_addrinfo("invalid address", "invalid port");
    POINTERS_EQUAL(NULL, addr);
};

TEST(Utils, strOrNil)
{
    const char *str;

    str = strOrNil(NULL);
    CHECK_EQUAL("(nil)", str);

    str = strOrNil("foo");
    STRCMP_EQUAL("foo", str);
}

TEST(Utils, addrinfoToString)
{
    struct addrinfo *info;
    char *addr_str;

    info = tacplus_addrinfo("1.1.1.1", "50");
    CHECK(info);
    addr_str = addrinfo_to_string(info);
    STRCMP_EQUAL("1.1.1.1", addr_str);
    freeaddrinfo(info);
    free(addr_str);

    info = tacplus_addrinfo("2:2::2:2", "55");
    CHECK(info);
    addr_str = addrinfo_to_string(info);
    STRCMP_EQUAL("2:2::2:2", addr_str);
    freeaddrinfo(info);
    free(addr_str);
}

TEST(Utils, getAddrinfoPort)
{
    struct addrinfo *info;
    uint16_t port;

    info = tacplus_addrinfo("1.1.1.1", "50");
    CHECK(info);
    port = get_addrinfo_port(info);
    CHECK_EQUAL(50, port);
    freeaddrinfo(info);

    info = tacplus_addrinfo("2:2::2:2", "65535");
    CHECK(info);
    port = get_addrinfo_port(info);
    CHECK_EQUAL(65535, port);
    freeaddrinfo(info);
}

TEST(Utils, timespecValsEq)
{
    struct timespec ts = { 10, 908987 };
    CHECK(TIMESPEC_VALS_EQ(ts, 10, 908987));
}

TEST(Utils, setTimespecVals)
{
    struct timespec ts = {};
    CHECK(TIMESPEC_VALS_EQ(ts, 0, 0));

    SET_TIMESPEC_VALS(ts, 55, 9824798);
    CHECK(TIMESPEC_VALS_EQ(ts, 55, 9824798));
}

/*
 * timespec_normalise() tests
 */

TEST(Utils, timespecNormaliseNoOp)
{
    struct timespec ts = { 1, 500 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, 1, 500);
}

TEST(Utils, timespecNormaliseMultiWholeSec)
{
    struct timespec ts = { 890, 10000000000 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, 900, 0);
}

TEST(Utils, timespecNormaliseMultiSec)
{
    struct timespec ts = { 123210, 6674000000 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, 123216, 674000000);
}

TEST(Utils, timespecNormaliseNeg)
{
    struct timespec ts = { 67, -234 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, 66, 999999766);
}

TEST(Utils, timespecNormaliseMultiWholeNegSec)
{
    struct timespec ts = { 27, -4000000000 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, 23, 0);
}

TEST(Utils, timespecNormaliseMultiNegSec)
{
    struct timespec ts = { 12, -3000004413 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, 8, 999995587);
}


TEST(Utils, timespecNormaliseNegSecNoOp)
{
    struct timespec ts = { -1, 500 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, -1, 500);
}

TEST(Utils, timespecNormaliseNegMultiWholeSec)
{
    struct timespec ts = { -890, 10000000000 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, -880, 0);
}

TEST(Utils, timespecNormaliseNegMultiSec)
{
    struct timespec ts = { -123210, 6540674000 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, -123204, 540674000);
}

TEST(Utils, timespecNormaliseNegNeg)
{
    struct timespec ts = { -67, -234 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, -68, 999999766);
}

TEST(Utils, timespecNormaliseNegMultiWholeNegSec)
{
    struct timespec ts = { -27, -4000000000 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, -31, 0);
}

TEST(Utils, timespecNormaliseNegMultiNegSec)
{
    struct timespec ts = { -12, -3097604413 }, *ret;

    ret = timespec_normalise(&ts);
    POINTERS_EQUAL(&ts, ret);
    CHECK_TIMESPEC_VALS(ts, -16, 902395587);
}

/*
 * timespec_cmp() tests
 */

TEST(Utils, timespecCmpEq)
{
    struct timespec a = { 1, 200 };
    struct timespec b = a;

    CHECK_EQUAL(timespec_cmp(&a, &b), 0);
    CHECK_EQUAL(timespec_cmp(&b, &a), 0);
}

TEST(Utils, timespecCmpDiffSecs)
{
    struct timespec a = { 1, 200 };
    struct timespec b = { 10, 200 };

    CHECK_EQUAL(timespec_cmp(&a, &b), -1);
    CHECK_EQUAL(timespec_cmp(&b, &a), 1);
}

TEST(Utils, timespecCmpDiffNsecs)
{
    struct timespec a = { 188, 800 };
    struct timespec b = { 188, 89787 };

    CHECK_EQUAL(timespec_cmp(&a, &b), -1);
    CHECK_EQUAL(timespec_cmp(&b, &a), 1);
}

TEST(Utils, timespecCmpDiffSecsNsecs)
{
    struct timespec a = { 12, 12786 };
    struct timespec b = { 90, 82174 };

    CHECK_EQUAL(timespec_cmp(&a, &b), -1);
    CHECK_EQUAL(timespec_cmp(&b, &a), 1);

    a.tv_nsec = b.tv_nsec + 10;
    CHECK_EQUAL(timespec_cmp(&a, &b), -1);
    CHECK_EQUAL(timespec_cmp(&b, &a), 1);
}

/*
 * timespec_sub() tests
 */

TEST(Utils, timespecSubEq)
{
    struct timespec a = { 1, 200 };
    struct timespec b = a;
    struct timespec res;

    timespec_sub(&a, &b, &res);
    CHECK_TIMESPEC_VALS(res, 0, 0);
    CHECK_TIMESPEC_VALS(a, 1, 200);
    CHECK_TIMESPEC_VALS(b, 1, 200);

    timespec_sub(&b, &a, &res);
    CHECK_TIMESPEC_VALS(res, 0, 0);
    CHECK_TIMESPEC_VALS(a, 1, 200);
    CHECK_TIMESPEC_VALS(b, 1, 200);
}

TEST(Utils, timespecSub)
{
    struct timespec a = { 12, 98200 };
    struct timespec b = { 4, 999098654 };
    struct timespec res;

    timespec_sub(&a, &b, &res);
    CHECK_TIMESPEC_VALS(res, 7, 999546);
    CHECK_TIMESPEC_VALS(a, 12, 98200);
    CHECK_TIMESPEC_VALS(b, 4, 999098654);

    timespec_sub(&b, &a, &res);
    CHECK_TIMESPEC_VALS(res, -8, 999000454);
    CHECK_TIMESPEC_VALS(a, 12, 98200);
    CHECK_TIMESPEC_VALS(b, 4, 999098654);
}
