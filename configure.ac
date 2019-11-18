AC_INIT(bruteforce-luks, 1.4.0)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(src/bruteforce-luks.c)

dnl Check for toolchain and install components
AC_PROG_CC
AC_PROG_INSTALL

dnl Check for standard headers
AC_CHECK_HEADERS([ctype.h errno.h locale.h math.h signal.h stdio.h stdlib.h sys/time.h time.h unistd.h wchar.h])

dnl Check for functions
AC_CHECK_FUNCS([calloc malloc realloc free])
AC_CHECK_FUNCS([perror printf fprintf snprintf])
AC_CHECK_FUNCS([fopen fgetc])
AC_CHECK_FUNCS([atoi])
AC_CHECK_FUNCS([setlocale mbstowcs wcsncpy wcstombs])
AC_CHECK_FUNCS([getopt])
AC_CHECK_FUNCS([signal])
AC_CHECK_FUNCS([localtime setitimer strftime time])

dnl Check for libraries
AC_CHECK_LIB(m, pow, [], AC_MSG_ERROR([math library required]))

AC_CHECK_LIB(pthread, pthread_create, [], AC_MSG_ERROR([POSIX threads library required]))
AC_CHECK_HEADERS(pthread.h, [], AC_MSG_ERROR([POSIX threads headers required]))

AC_CHECK_LIB(cryptsetup, crypt_activate_by_passphrase, [], AC_MSG_ERROR([cryptsetup library required]))
AC_CHECK_HEADERS(libcryptsetup.h, [], AC_MSG_ERROR([cryptsetup headers required]))

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
