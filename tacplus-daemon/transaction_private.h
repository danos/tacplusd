/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2019 AT&T Intellectual Property.

	SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef _TRANSACTION_PRIVATE_H
#define _TRANSACTION_PRIVATE_H

/*
 * This header leaks the TACACS+ implementation being used (ie. libtac)
 * and is only intended to be included by transaction.c and appropriate UTs.
 */

struct transaction_attrib *transaction_attrib_from_tac_attrib(const struct tac_attrib *);

#endif /*_TRANSACTION_PRIVATE_H */
