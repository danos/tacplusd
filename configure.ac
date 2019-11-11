AC_PREREQ(2.69)

m4_define([VERSION_ID], [m4_esyscmd([
    echo -n `dpkg-parsechangelog | sed -n 's/^Version: //p'`
    ])])

AC_INIT([tacplusd], VERSION_ID, [DL-vyatta-help@att.com])

#AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([1.11.1 foreign no-dist-gzip dist-bzip2 subdir-objects parallel-tests])

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AS
AM_PROG_CC_C_O

PKG_CHECK_MODULES([SYSTEMD],[libsystemd])
PKG_CHECK_MODULES([LIBTAC],[libtac])
PKG_CHECK_MODULES([LIBTAC_EVENT],[libtac-event],
    [AC_DEFINE([HAVE_LIBTAC_EVENT], [1], [libtac-event present])],
    true
)
PKG_CHECK_MODULES([GLIB],[glib-2.0])

AC_CONFIG_FILES([
        Makefile
        tacplus-daemon/Makefile
        tacplus-daemon/test/Makefile
])

PKG_CHECK_MODULES(cpputest, [cpputest], [], [
    dnl Fall back to classic searching. 3.1 on Wheezy doesn't supply .pc
    AC_LANG_CPLUSPLUS
    AC_CHECK_LIB([CppUTest], [main], [
       have_cpputest=yes
       cpputest_LIBS="-lstdc++ -lCppUTest -lCppUTestExt"
       cpputest_CFLAGS=""],
       [AC_MSG_ERROR(cpputest is required for this program)])
    AC_LANG_C ]
)

AC_OUTPUT
