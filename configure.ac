#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rcmd], [0.1.1], [jozef@purpakana.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/rcmd.c])

# Checks for programs.
AC_PROG_CC([gcc])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h unistd.h getopt.hpthread.h libssh/libssh.h libssh/callbacks.h])


AC_MSG_CHECKING([Checking if running on Darwin])

AM_CONDITIONAL([DARWIN], [false])
UNAME=`uname -s`
if test "x$UNAME" = "xDarwin"; then
   AM_CONDITIONAL([DARWIN], [true])
fi



# Checks for library functions.
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
