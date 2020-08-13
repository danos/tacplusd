/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

#define IS_INADDR_LOOPBACK(I)  ((ntohl(I.s_addr) & 0x7f000000) == 0x7f000000)
#define IS_IN6ADDR_LOOPBACK(I) (memcmp(&I, &in6addr_loopback, sizeof(I)) == 0)

#define SEC_TO_NSECS 1000000000

#define TIMESPEC_VALS_EQ(T,S,N) ((T).tv_sec == S && (T).tv_nsec == N)

#define SET_TIMESPEC_VALS(T,S,N) \
	{                            \
		(T).tv_sec = S;          \
		(T).tv_nsec = N;         \
	}

struct addrinfo *tacplus_addrinfo(const char *, const char *);

char *addrinfo_to_string(const struct addrinfo *);

uint16_t get_addrinfo_port(const struct addrinfo *);

static inline
const char *strOrNil(const char *s)
{
	return (s ? s : "(nil)");
}

bool sockaddr_addr_equal (const struct sockaddr *sa1, const struct sockaddr *sa2);
struct addrinfo *get_interface_addrinfo(const char *ifname, int af);
void free_interface_addrinfo(struct addrinfo **info);
int is_sockaddr_loopback(struct sockaddr *saddr);
int is_interface_up(const char *ifname);
char *get_tty_login_addr(const char *tty);
int new_cb_timer(timer_t *timer, void (*cb) (union sigval), union sigval *user);
int set_timer(timer_t timer, const struct itimerspec *it);
int expire_timer(timer_t timer);
int remaining_timer_interval(timer_t timer, struct timespec *ts);

void cur_mono_time(struct timespec *ts);
struct timespec *timespec_normalise(struct timespec *spec);
struct timespec *timespec_sub(const struct timespec *a,
							  const struct timespec *b,
							  struct timespec *result);
int timespec_cmp(const struct timespec *a, const struct timespec *b);

static inline time_t
timespec_nearest_sec(const struct timespec *ts)
{
	return (ts->tv_nsec >= SEC_TO_NSECS/2) ? ts->tv_sec+1 : ts->tv_sec;
}

#endif /* UTILS_H */
