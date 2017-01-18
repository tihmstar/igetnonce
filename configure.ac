AC_PREREQ([2.69])
AC_INIT([igetnonce], [1.0], [tihmstar@gmail.com])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_SRCDIR([igetnonce/all_igetnonce.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
CFLAGS+=" -std=c11"

# Checks for libraries.
PKG_CHECK_MODULES(libimobiledevice, libimobiledevice-1.0 >= 1.2.1)
PKG_CHECK_MODULES(libirecovery, libirecovery >= 0.2.0)
PKG_CHECK_MODULES(libusbmuxd, libusbmuxd >= 0.29.1)
PKG_CHECK_MODULES(openssl, openssl >= 0.9.8)

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strrchr])

AC_OUTPUT([
Makefile
igetnonce/Makefile
])
