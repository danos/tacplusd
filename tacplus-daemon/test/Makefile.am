AM_CFLAGS = -Wall -Wextra -Werror $(HARDENING_CFLAGS) \
            -I$(top_srcdir)/tacplus-daemon -DVERSION=\"$(VERSION)\" \
            $(LIBTAC_CFLAGS) $(LIBTAC_EVENT_CFLAGS) $(SYSTEMD_CFLAGS) \
            $(GLIB_CFLAGS) -DPROG="\"$(PACKAGE)\""

AM_CXXFLAGS = -std=c++11 -Wall -Wextra -Werror -Wno-missing-field-initializers \
              $(HARDENING_CXXFLAGS) \
              $(cpputest_CFLAGS) -I$(top_srcdir)/tacplus-daemon \
              $(LIBTAC_CFLAGS) $(LIBTAC_EVENT_CFLAGS) $(SYSTEMD_CFLAGS) \
              $(GLIB_CFLAGS) -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\""

AM_CPPFLAGS = $(cpputest_CFLAGS)

AM_LDFLAGS = $(HARDENING_CXXFLAGS)

LDADD = $(cpputest_LIBS) $(LIBTAC_LIBS) $(LIBTAC_EVENT_LIBS) \
        $(SYSTEMD_LIBS) $(GLIB_LIBS) -lpthread -lrt

check_PROGRAMS = queue_tester server_connect_tester utils_tester parser_tester \
                 transaction_tester

utils_tester_SOURCES = utilsTester.cpp ut_utils.c testMain.cpp ../utils.c
utils_tester_LDADD = $(LDADD)
utils_tester_LDFLAGS = -Wl,-wrap,getutxline

parser_tester_SOURCES = parserTester.cpp testMain.cpp ../parser.c \
                        ../tacplus_srv_conn.c ../utils.c ../statistics.c \
                        ../dbus_service.c ../transaction.c ../queue.c \
                        ../global.c

parser_tester_LDADD = $(LDADD)

server_connect_tester_SOURCES = serverConnectTester.cpp testMain.cpp \
                                ut_utils.c ../tacplus_srv_conn.c ../parser.c \
                                ../utils.c ../statistics.c ../dbus_service.c \
                                ../transaction.c ../queue.c ../global.c
server_connect_tester_LDADD = $(LDADD)
server_connect_tester_LDFLAGS = -Wl,-wrap,tac_connect_single  \
                                -Wl,-wrap,cur_mono_time       \
                                -Wl,-wrap,tacplusd_go_online  \
                                -Wl,-wrap,tacplusd_go_offline \
                                -Wl,-wrap,tacplusd_online

queue_tester_SOURCES = queueTester.cpp testMain.cpp ../queue.c
queue_tester_LDADD = $(LDADD)

transaction_tester_SOURCES = transactionTester.cpp testMain.cpp ut_utils.c \
                             ../transaction.c ../tacplus_srv_conn.c \
                             ../parser.c ../utils.c ../statistics.c \
                             ../dbus_service.c ../queue.c ../global.c
transaction_tester_LDADD = $(LDADD)

TESTS = $(check_PROGRAMS)
