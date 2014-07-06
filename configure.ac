AC_INIT(bruteforce_luks, 1.0)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(src/bruteforce-luks.c)

dnl Check for toolchain and install components
AC_PROG_CC
AC_PROG_INSTALL

dnl Check for standard headers
AC_CHECK_HEADERS([errno.h stdio.h stdlib.h string.h unistd.h])

dnl Check for functions
AC_CHECK_FUNCS([malloc free])
AC_CHECK_FUNCS([perror printf fprintf snprintf])
AC_CHECK_FUNCS([atoi])
AC_CHECK_FUNCS([strlen strncpy])
AC_CHECK_FUNCS([getopt])

dnl Check for libraries
AC_CHECK_LIB(pthread, pthread_create, [], AC_MSG_ERROR([POSIX threads library required]))
AC_CHECK_HEADERS(pthread.h, [], AC_MSG_ERROR([POSIX threads headers required]))

AC_CHECK_LIB(cryptsetup, crypt_activate_by_passphrase, [], AC_MSG_ERROR([cryptsetup library required]))
AC_CHECK_HEADERS(libcryptsetup.h, [], AC_MSG_ERROR([cryptsetup headers required]))

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
