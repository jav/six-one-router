AC_INIT([sixone], [1.0], [])
AM_INIT_AUTOMAKE([-Wall -Werror])
LIBS="-pthread -lpcap"
AC_SUBST(LIBS)
AC_PROG_CC
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([pcap], [pcap_loop])
AC_CONFIG_HEADERS([config.h]) 
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT