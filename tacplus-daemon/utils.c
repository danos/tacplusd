/*
	TACACS+ D-Bus Daemon code

	Copyright (c) 2018-2020 AT&T Intellectual Property.
	Copyright (c) 2015-2016 Brocade Communications Systems, Inc.

	SPDX-License-Identifier: GPL-2.0-only
*/

#include <arpa/inet.h>
#include <assert.h>
#include <syslog.h>
#include <stdlib.h>
#include <math.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <utmpx.h>

#include "utils.h"

bool sockaddr_addr_equal (const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	if (sa1->sa_family != sa2->sa_family)
		return false;

	if (sa1->sa_family == AF_INET) {
		struct in_addr *sin1 = &((struct sockaddr_in *)sa1)->sin_addr;
		struct in_addr *sin2 = &((struct sockaddr_in *)sa2)->sin_addr;

		return sin1->s_addr == sin2->s_addr ? true : false;
	}
	else if (sa1->sa_family == AF_INET6) {
		struct in6_addr *sin1 = &((struct sockaddr_in6 *)sa1)->sin6_addr;
		struct in6_addr *sin2 = &((struct sockaddr_in6 *)sa2)->sin6_addr;

		return memcmp(sin1, sin2, sizeof *sin1) == 0 ? true : false;
	}

	return false;
}

struct addrinfo *tacplus_addrinfo(const char *opt_server, const char *opt_port) {
	struct addrinfo *result = NULL;
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};

	int err = getaddrinfo(opt_server, opt_port, &hints, &result);

	if (err != 0) {
		syslog(LOG_ERR, "resolving %s:%s error: %s",
			strOrNil(opt_server), strOrNil(opt_port),
			gai_strerror(err));
		/* TODO: error handling */
		return NULL;
	}

	return result;
}

char *addrinfo_to_string(const struct addrinfo *addr)
{
	char addr_str[INET6_ADDRSTRLEN];

	if (getnameinfo(addr->ai_addr, addr->ai_addrlen, addr_str,
					INET6_ADDRSTRLEN, 0, 0, NI_NUMERICHOST) == 0)
		return strdup(addr_str);
	else
		syslog(LOG_DEBUG, "Could not convert address to string");

	return NULL;
}

uint16_t get_addrinfo_port(const struct addrinfo *ai)
{
	struct sockaddr *sa = ai->ai_addr;

	if (sa->sa_family == AF_INET)
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	else if (sa->sa_family == AF_INET6)
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	else
		return 0;
}

int is_sockaddr_loopback(struct sockaddr *saddr)
{
	switch (saddr->sa_family) {
		case AF_INET:
			return IS_INADDR_LOOPBACK(((struct sockaddr_in *)saddr)->sin_addr);
		case AF_INET6:
			return IS_IN6ADDR_LOOPBACK(((struct sockaddr_in6 *)saddr)->sin6_addr);
	}

	return 0;
}

struct addrinfo *get_interface_addrinfo(const char *ifname, int af)
{
	struct ifaddrs *ifas_head = NULL, *ifa;
	struct addrinfo *info = NULL;
	socklen_t addrlen;
	int ret;

	if ((ret = getifaddrs(&ifas_head))) {
		syslog(LOG_WARNING, "getifaddrs() failed (%i): %s",
			   ret, strerror(errno));
		return NULL;
	}

	for (ifa = ifas_head; ifa; ifa = ifa->ifa_next) {
		if (! ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != af)
			continue;

		if (strncmp(ifname, ifa->ifa_name, IFNAMSIZ))
			continue;

		if (is_sockaddr_loopback(ifa->ifa_addr))
			continue;

		if (! (info = (struct addrinfo *) calloc(1, sizeof(struct addrinfo)))) {
			syslog(LOG_ERR, "get_interface_addrinfo(): addrinfo "
				   "memory allocation failure");
			goto finish;
		}

		addrlen = af == AF_INET ? sizeof(struct sockaddr_in)
								: sizeof(struct sockaddr_in6);

		if (! (info->ai_addr = (struct sockaddr *) malloc(addrlen))) {
			syslog(LOG_ERR, "get_interface_addrinfo(): sockaddr "
				   "memory allocation failure");
			free(info);
			goto finish;
		}

		memcpy(info->ai_addr, ifa->ifa_addr, addrlen);
		info->ai_family = ifa->ifa_addr->sa_family;
		info->ai_addrlen = addrlen;
		break;
	}

	if (! info)
		syslog(LOG_DEBUG, "Interface %s does not exist or has no "
			   "suitable addresses", ifname);

finish:
	freeifaddrs(ifas_head);
	return info;
}

void free_interface_addrinfo(struct addrinfo **info)
{
	if (! info || !*info)
		return;

	free((*info)->ai_addr);
	free(*info);
	*info = NULL;
}

int is_interface_up(const char *ifname)
{
	struct ifreq req = {};
	int fd;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "is_interface_up(%s): failed to open socket (%u): %s",
				ifname, errno, strerror(errno));
		return -1;
	}

	strncat(req.ifr_name, ifname, sizeof(req.ifr_name)-1);
	if (ioctl(fd, SIOCGIFFLAGS, &req) < 0) {
		syslog(LOG_WARNING, "is_interface_up(%s): could not get interface "
			   "status (%u): %s", req.ifr_name, errno, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	return (req.ifr_flags & IFF_UP) ? 1 : 0;
}

void
cur_mono_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC_RAW, ts) < 0) {
		syslog(LOG_ERR, "Error getting current time: %s", strerror(errno));
		SET_TIMESPEC_VALS(*ts, 0, 0);
	}

	timespec_normalise(ts);
}

/*
 * Adjust the timespec spec to ensure that the nanosecond portion is in the
 * range 0-999,999,999.
 */
struct timespec *
timespec_normalise(struct timespec *spec)
{
	while (spec->tv_nsec <= -SEC_TO_NSECS) {
		spec->tv_sec--;
		spec->tv_nsec += SEC_TO_NSECS;
	}

	while (spec->tv_nsec < 0) {
		spec->tv_sec--;
		spec->tv_nsec = SEC_TO_NSECS + spec->tv_nsec;
	}

	while (spec->tv_nsec >= SEC_TO_NSECS) {
		spec->tv_sec++;
		spec->tv_nsec -= SEC_TO_NSECS;
	}

	return spec;
}

/*
 * Subtract time b from a, placing the result in result
 */
struct timespec *
timespec_sub(const struct timespec *a, const struct timespec *b,
			 struct timespec *result)
{
	result->tv_sec = a->tv_sec - b->tv_sec;
	result->tv_nsec = a->tv_nsec - b->tv_nsec;
	return timespec_normalise(result);
}

/*
 * Return -1, 0, or 1 if a represents a time less than, equal to, or
 * greater than the time represented by b, respectively.
 */
int
timespec_cmp(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec > b->tv_sec)
		return 1;
	else if (a->tv_sec < b->tv_sec)
		return -1;

	if (a->tv_nsec > b->tv_nsec)
		return 1;
	else if (a->tv_nsec < b->tv_nsec)
		return -1;

	/* timespecs equal */
	return 0;
}

/*
 * Get the user's remote login address for a given TTY
 *
 * WARNING: this function is not thread safe due to the following calls:
 *  - setutxent()
 *  - getutxline()
 *  - endutxent()
 */
char *
get_tty_login_addr(const char *tty)
{
	struct utmpx tty_utmp = {0};
	char buf[INET6_ADDRSTRLEN] = {0};
	char *zone_index;

	static_assert(sizeof(buf) >= sizeof(struct in6_addr),
				  "buf is used for both inet_pton() and inet_ntop()");

	if (!tty) {
		return NULL;
	}

	strncpy(tty_utmp.ut_line, tty, sizeof tty_utmp.ut_line);

	setutxent();
	struct utmpx *up = getutxline(&tty_utmp);
	endutxent();
	if (!up) {
		syslog(LOG_DEBUG, "getutxline() failed: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	/*
	 * Check for a zone index and terminate prior to the separator, since inet_pton()
	 * won't handle it and would fail.
	 */
	if (up->ut_host && (zone_index = strrchr(up->ut_host, '%')))
		*zone_index = '\0';

	if (!up->ut_host || (inet_pton(AF_INET, up->ut_host, buf) != 1 &&
						 inet_pton(AF_INET6, up->ut_host, buf) != 1)) {
		/* ut_host is a hostname or not set - fallback to ut_addr_v6 */
		int af = (up->ut_addr_v6[1] == 0 &&
				  up->ut_addr_v6[2] == 0 &&
				  up->ut_addr_v6[3] == 0) ? AF_INET : AF_INET6;

		if (inet_ntop(af, up->ut_addr_v6, buf, sizeof buf))
			return strdup(buf);

		/* The best we can do is just return ut_host */
	}

	/* Restore zone index separator */
	if (zone_index)
		*zone_index = '%';

	return strlen(up->ut_host) ? strdup(up->ut_host) : NULL;
}

int
new_cb_timer(timer_t *timer, void (*cb) (union sigval), union sigval *user)
{
	struct sigevent se = {
		.sigev_notify = SIGEV_THREAD,
		.sigev_notify_function = cb
	};

	if (user)
		se.sigev_value = *user;

	int ret = timer_create(CLOCK_MONOTONIC, &se, timer);
	if (ret < 0)
		syslog(LOG_ERR, "timer_create() failed (%d): %s", ret, strerror(errno));

	return ret;
}

int
set_timer(timer_t timer, const struct itimerspec *it)
{
	struct itimerspec discard;

	int ret = timer_settime(timer, 0, it, &discard);
	if (ret < 0)
		syslog(LOG_ERR, "timer_settime() failed (%d): %s", ret, strerror(errno));

	return ret;
}

int
expire_timer(timer_t timer)
{
	struct itimerspec it = {
		.it_value.tv_sec = 0,
		.it_value.tv_nsec = 1
	};

	return set_timer(timer, &it);
}
