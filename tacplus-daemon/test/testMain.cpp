/*
	Copyright (c) 2018-2019 AT&T Intellectual Property.
	Copyright (c) 2015 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include "CppUTest/CommandLineTestRunner.h"
extern "C" {
  #include "global.h"
}

static ConnectionControl _connControl;
ConnectionControl *connControl = &_connControl;

int main(int ac, char** av)
{
  return CommandLineTestRunner::RunAllTests(ac, av);
}
