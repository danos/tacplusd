SUBDIRS = test

dbusconfdir = $(sysconfdir)/dbus-1/system.d


AM_CFLAGS = $(LIBTAC_CFLAGS) $(LIBTAC_EVENT_CFLAGS) $(SYSTEMD_CFLAGS) $(GLIB_CFLAGS)
AM_CFLAGS += -Wall -Wextra -Werror

sbin_PROGRAMS = tacplusd

tacplusd_SOURCES = \
	queue.c \
	dbus_service.c \
	main.c \
	daemon.c \
	tacplus_srv_conn.c \
	transaction.c \
	parser.c \
	utils.c \
	statistics.c \
	global.c

tacplusd_LDADD = \
	$(LIBTAC_LIBS) \
	$(LIBTAC_EVENT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(GLIB_LIBS) \
	-lpthread \
	-lm \
	-lrt

dist_dbusconf_DATA = net.vyatta.tacplus.conf
