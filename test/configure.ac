#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([test], [0.1], [BUG-REPORT-ADDRESS])

LT_INIT

AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [pthread_create])
# FIXME: Replace `main' with a function in `-lliteidmef':
AC_CHECK_LIB([liteidmef], [idmef_new])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
