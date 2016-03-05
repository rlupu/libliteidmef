#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libliteidmef], [0.1], [BUG-REPORT-ADDRESS])

AM_INIT_AUTOMAKE

LT_INIT

AC_CONFIG_SRCDIR([src/idmef_plugin.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset socket strerror strncasecmp])

AC_ARG_ENABLE([debug],
	[  --enable-debug          turn on debugging],
	[case "${enableval}" in
		yes) enable_debug=true;;
		no)  enable_debug=false;;
		*)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]);;
	esac], [enable_debug=false])
AM_CONDITIONAL([DEBUG], [test x$enable_debug = xtrue])

AC_SUBST(enable_debug)
AC_SUBST(DEBUG)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 test/Makefile
						src/libliteidmef-0.1.pc])
AC_OUTPUT
