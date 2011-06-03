dnl --- Init autoconf
AC_INIT([sixone], [1.0], [])

dnl --- Verify that we are running on FreeBSD
AC_CANONICAL_SYSTEM
UNSUPPORTED_OS="The six-one router currently only builds on FreeBSD."
case "${target_os}" in
  freebsd*)
    echo ===========================================================
    echo Setting up build environment for ${target_cpu} ${target_os}
    echo ===========================================================
    ;;
      *)
    AC_MSG_ERROR($UNSUPPORTED_OS)
  esac

dnl --- Init automake
AM_INIT_AUTOMAKE([-Wall -Werror])

dnl --- Check C keywords and standard types
AC_C_CONST
AC_C_INLINE
AC_C_RESTRICT
AC_C_VOLATILE
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_STRUCT_TM

dnl --- Check compiler, libs and operating system
AC_PROG_CC
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([pcap], [pcap_loop])

dnl --- Files and paths
AC_CONFIG_HEADERS([config.h]) 
AC_CONFIG_FILES([Makefile src/Makefile])

dnl --- Create files
AC_OUTPUT