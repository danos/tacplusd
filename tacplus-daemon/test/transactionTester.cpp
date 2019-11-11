/*
	Copyright (c) 2019 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/TestHarness.h"
extern "C" {
    #include <libtac.h>
    #include "transaction.h"
    #include "transaction_private.h"
    #include "utils.h"
}
#include "ut_utils.h"

TEST_GROUP(Transaction) {};

TEST(Transaction, NewAttribInvalid)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new(NULL);
    POINTERS_EQUAL(NULL, attr);

    attr = transaction_attrib_new("");
    POINTERS_EQUAL(NULL, attr);

    attr = transaction_attrib_new("=");
    POINTERS_EQUAL(NULL, attr);

    attr = transaction_attrib_new("*");
    POINTERS_EQUAL(NULL, attr);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribNoSep)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("foobarbaz");
    CHECK(attr != NULL);

    STRCMP_EQUAL("foobarbaz=", attr->name);
    STRCMP_EQUAL("", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribShortNoSep)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("f");
    CHECK(attr != NULL);

    STRCMP_EQUAL("f=", attr->name);
    STRCMP_EQUAL("", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribMandatory)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("cmd=set foo");
    CHECK(attr != NULL);

    STRCMP_EQUAL("cmd=", attr->name);
    STRCMP_EQUAL("set foo", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribMandatoryShortNoVal)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("c=");
    CHECK(attr != NULL);

    STRCMP_EQUAL("c=", attr->name);
    STRCMP_EQUAL("", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribOptional)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("cmd*set foo");
    CHECK(attr != NULL);

    STRCMP_EQUAL("cmd*", attr->name);
    STRCMP_EQUAL("set foo", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribOptionalShortNoVal)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("c*");
    CHECK(attr != NULL);

    STRCMP_EQUAL("c*", attr->name);
    STRCMP_EQUAL("", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribMandatoryWithOptSepInValue)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("cmd=set f*o");
    CHECK(attr != NULL);

    STRCMP_EQUAL("cmd=", attr->name);
    STRCMP_EQUAL("set f*o", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribOptionalWithMandSepInValue)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("cmd*set foo=bar");
    CHECK(attr != NULL);

    STRCMP_EQUAL("cmd*", attr->name);
    STRCMP_EQUAL("set foo=bar", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, NewAttribMulti)
{
    struct transaction_attrib *attr;

    attr = transaction_attrib_new("cmd*set foo");
    CHECK(attr != NULL);

    STRCMP_EQUAL("cmd*", attr->name);
    STRCMP_EQUAL("set foo", attr->value);
    POINTERS_EQUAL(NULL, attr->next);

    attr->next = transaction_attrib_new("cmd=delete foo");
    CHECK(attr->next != NULL);

    STRCMP_EQUAL("cmd=", attr->next->name);
    STRCMP_EQUAL("delete foo", attr->next->value);
    POINTERS_EQUAL(NULL, attr->next->next);

    transaction_attrib_free(&attr);
    POINTERS_EQUAL(NULL, attr);
};

TEST(Transaction, TransactionAttribFromTacAttribNull)
{
    POINTERS_EQUAL(NULL, transaction_attrib_from_tac_attrib(NULL));
}

static void compare_transaction_attribs(struct transaction_attrib exp[],
                                        unsigned exp_len,
                                        struct transaction_attrib *act)
{
    unsigned i;
    for (i = 0; act; act = act->next, i++) {
        STRCMP_EQUAL(exp[i].name, act->name);
        STRCMP_EQUAL(exp[i].value, act->value);

        if (act->next == NULL) {
            LONGS_EQUAL_TEXT(
                exp_len-1, i, "transaction_attrib list unexpectedly short");
        }
        else {
            CHECK_TEXT(
                i < exp_len-1, "transaction_attrib list unexpectedly long");
        }
    }

    /* Final sanity check */
    LONGS_EQUAL_TEXT(exp_len, i, "transaction_attrib list length mismatch");
}

TEST(Transaction, TransactionAttribFromTacAttribSingle)
{
    struct tac_attrib *tac_attrib = NULL;

    tac_add_attrib(&tac_attrib, (char *)"cmd", (char *)"set foo bar");
    CHECK(tac_attrib != NULL);

    struct transaction_attrib *attrib;
    attrib = transaction_attrib_from_tac_attrib(tac_attrib);
    CHECK(attrib != NULL);

    struct transaction_attrib exp_attrib[] = {
        {
            .next     = NULL,
            .name     = "cmd=",
            .value    = "set foo bar",
        },
    };
    compare_transaction_attribs(exp_attrib, ARRAY_SIZE(exp_attrib), attrib);

    transaction_attrib_free(&attrib);
    POINTERS_EQUAL(NULL, attrib);
}

TEST(Transaction, TransactionAttribFromTacAttribMulti)
{
    struct tac_attrib *tac_attrib = NULL;

    tac_add_attrib(&tac_attrib, (char *)"cmd", (char *)"set");
    CHECK(tac_attrib != NULL);
    tac_add_attrib(&tac_attrib, (char *)"cmd-arg", (char *)"foo");
    tac_add_attrib(&tac_attrib, (char *)"cmd-arg", (char *)"bar");
    tac_add_attrib(&tac_attrib, (char *)"cmd-arg", (char *)"baz");

    struct transaction_attrib *attrib;
    attrib = transaction_attrib_from_tac_attrib(tac_attrib);
    CHECK(attrib != NULL);

    /*
     * "next" member is unused by the tests, it is initialised to
     * silence the C++ compiler.
     */
    struct transaction_attrib exp_attrib[] = {
        {
            .next     = NULL,
            .name     = "cmd=",
            .value    = "set",
        },
        {
            .next     = NULL,
            .name     = "cmd-arg=",
            .value    = "foo",
        },
        {
            .next     = NULL,
            .name     = "cmd-arg=",
            .value    = "bar",
        },
        {
            .next     = NULL,
            .name     = "cmd-arg=",
            .value    = "baz",
        },
    };
    compare_transaction_attribs(exp_attrib, ARRAY_SIZE(exp_attrib), attrib);

    transaction_attrib_free(&attrib);
    POINTERS_EQUAL(NULL, attrib);
}
