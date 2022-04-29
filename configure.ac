# Copyright 2022 Stefan Eissing (<stefan@eissing.org>)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

AC_PREREQ([2.69])
AC_INIT([mod_authnz_tailscale], [0.0.1], [stefan@eissing.org])

LT_PREREQ([2.2.6])
LT_INIT()
dnl See versioning rule:
dnl  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 11)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 6)

major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([subdir-objects no-define])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADERS([src/config.h])

AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [Turn on compile time warnings])],
    [werror=$enableval], [werror=no])

AC_ARG_WITH([apxs], [AS_HELP_STRING([--with-apxs],
    [Use APXS executable [default=check]])],
    [request_apxs=$withval], [request_apxs=check])

AC_ARG_WITH([curl], [AS_HELP_STRING([--with-curl], [Use curl from this prefix])],
    [request_curl=$withval], [request_curl=check])

AC_ARG_WITH([jansson], [AS_HELP_STRING([--with-jansson], [Use jansson from this prefix])],
    [request_jansson=$withval], [request_jansson=check])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# extern, we need to find where the apxs is. which then
# can tell us the various directories we need.
#
if test x"$request_apxs" = "xcheck"; then
    AC_PATH_PROG([APXS], [apxs])
    if test "x${APXS}" = "x"; then
        AC_MSG_ERROR("no APXS installation found")
    fi
else
    APXS="$request_apxs"
    AC_MSG_NOTICE("using APXS=$APXS as configured")
fi

AC_SUBST(APR)

prefix="$($APXS -q prefix)"
prefix="${prefix:-/usr}"
AC_SUBST(prefix)

exec_prefix="$($APXS -q exec_prefix)"
AC_SUBST(exec_prefix)
APR_BINDIR="$($APXS -q APR_BINDIR)"
AC_SUBST(APR_BINDIR)
sbindir="$($APXS -q sbindir)"
AC_SUBST(sbindir)
progname="$($APXS -q progname)"
AC_SUBST(progname)
libdir="$($APXS -q libdir)"
AC_SUBST(libdir)
SYSCONF_DIR="$($APXS -q sysconfdir)"
AC_SUBST(SYSCONF_DIR)
LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"
AC_SUBST(LIBEXEC_DIR)

LDFLAGS="-L$libdir $LDFLAGS"
CPPFLAGS="-I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR) $($APXS -q EXTRA_CPPFLAGS) $CPPFLAGS"

HTTPD_VERSION="$($APXS -q HTTPD_VERSION)"
AC_SUBST(HTTPD_VERSION)

APACHECTL="$sbindir/apachectl"
if test ! -x "$APACHECTL"; then
    # rogue distros rename things! =)
    APACHECTL="$sbindir/apache2ctl"
fi
AC_SUBST(APACHECTL)

if test -x "$APACHECTL"; then
    DSO_MODULES="$($APACHECTL -t -D DUMP_MODULES | fgrep '(shared)'| sed 's/_module.*//g'|tr -d \\n)"
    AC_SUBST(DSO_MODULES)
    STATIC_MODULES="$($APACHECTL -t -D DUMP_MODULES | fgrep '(static)'| sed 's/_module.*//g'|tr -d \\n)"
    AC_SUBST(STATIC_MODULES)
else
    AC_MSG_WARN("apachectl not found in '$BINDIR', test suite will not work!")
    APACHECTL=""
fi

# We need a JSON lib, like jansson
#
if test x"$request_jansson" = "xcheck"; then
    AC_CHECK_LIB([jansson], [json_loads], , [AC_MSG_ERROR("library jansson not found")])

    AC_CHECK_HEADER([jansson.h], [],  [AC_MSG_WARN("header jansson.h not found")], [
    #include <jansson_config.h>
    #undef   JSON_INLINE
    #define JSON_INLINE
    #include <jansson.h>
    ])
    JANSSON_PREFIX=""
else
    LDFLAGS="$LDFLAGS -L$request_jansson/lib";
    CFLAGS="$CFLAGS -I$request_jansson/include";
    CPPFLAGS="$CPPFLAGS -I$request_jansson/include";
    JANSSON_PREFIX="$request_jansson"
fi


AC_CHECK_LIB([apr-1], [apr_pool_create_ex], [LIB_APR=apr-1], [AC_MSG_ERROR("library apr-1 not found")])
AC_SUBST(LIB_APR)
AC_CHECK_LIB([aprutil-1], [apr_brigade_create], [LIB_APRUTIL=aprutil-1], [AC_MSG_ERROR("library aprutil-1 not found")])
AC_SUBST(LIB_APRUTIL)

# We need a HTTP client which can talk http:
#
if test x"$request_curl" = "xcheck"; then
    AC_CHECK_LIB([curl], [curl_global_init], , [AC_MSG_ERROR("libcurl not found")])
    curl_config="curl-config"
    AC_CHECK_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
    if  test "x$CURL_CONFIG" = xno; then
        curl_config="${prefix}/bin/curl-config"
        AC_CHECK_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
    fi
else
    curl_config="$request_curl/bin/curl-config"
    AC_PATH_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
fi

AM_CONDITIONAL([FOUND_CURL_CONFIG], [test "x$CURL_CONFIG" = xyes])
AM_COND_IF([FOUND_CURL_CONFIG],,[AC_MSG_ERROR([required program 'curl-config' not found.])])

if test x"$curl_config" = "xcurl-config"; then
    CURL_BIN="curl"
else
    CURL_BIN=$( dirname $curl_config)/curl
fi
AC_SUBST(CURL_BIN)

AC_CHECK_HEADERS([curl/curl.h])

CFLAGS=`$curl_config --cflags`" $CFLAGS"
LDFLAGS=`$curl_config --libs`" $LDFLAGS"

AC_MSG_CHECKING([for curl version >= 7.29])
AC_TRY_COMPILE([#include <curl/curlver.h>],[
#if !defined(LIBCURL_VERSION_MAJOR)
#error "Missing libcurl version"
#endif
#if LIBCURL_VERSION_MAJOR < 7
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif
#if LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR < 29
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif],
      [AC_MSG_RESULT(OK)
       curl_version_ok=yes],
      [AC_MSG_RESULT(FAILED)])

if test x"$curl_version_ok" = "x"; then
    AC_MSG_ERROR([curl from $curl_config must be at least version 7.29.])
fi


GEN_DIR="$PWD/test/gen"
AC_SUBST(GEN_DIR)

HTTP_PORT=5002
AC_SUBST(HTTP_PORT)

HTTPS_PORT=5001
AC_SUBST(HTTPS_PORT)

HTTP_PROXY_PORT=5052
AC_SUBST(HTTP_PROXY_PORT)

HTTPD_USER="$USER"
AC_SUBST(HTTPD_USER)

MODULE_SRC="$PWD/src"
AC_SUBST(MODULE_SRC)

TAILSCALE_DEF_URL="/var/run/tailscale/tailscaled.sock"
AC_SUBST(TAILSCALE_DEF_URL)

WERROR_CFLAGS=""
if test "x$werror" != "xno"; then
    AX_CHECK_COMPILE_FLAG([-Wall], [WERROR_CFLAGS="$WERROR_CFLAGS -Wall"])
    AX_CHECK_COMPILE_FLAG([-Wconversion], [WERROR_CFLAGS="$WERROR_CFLAGS -Wconversion"])
    AX_CHECK_COMPILE_FLAG([-Wextra], [WERROR_CFLAGS="$WERROR_CFLAGS -Wextra"])
    AX_CHECK_COMPILE_FLAG([-Werror], [WERROR_CFLAGS="$WERROR_CFLAGS -Werror"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wmissing-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wstrict-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-declarations], [WERROR_CFLAGS="$WERROR_CFLAGS -Wmissing-declarations"])
    AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [WERROR_CFLAGS="$WERROR_CFLAGS -Wpointer-arith"])
    # we like to use such things...
    #AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdeclaration-after-statement"])
    AX_CHECK_COMPILE_FLAG([-Wformat-security], [WERROR_CFLAGS="$WERROR_CFLAGS -Wformat-security"])
    AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [WERROR_CFLAGS="$WERROR_CFLAGS -Wwrite-strings"])
    AX_CHECK_COMPILE_FLAG([-Wshadow], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG([-Winline], [WERROR_CFLAGS="$WERROR_CFLAGS -Winline"])
    AX_CHECK_COMPILE_FLAG([-Wnested-externs], [WERROR_CFLAGS="$WERROR_CFLAGS -Wnested-externs"])
    AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [WERROR_CFLAGS="$WERROR_CFLAGS -Wfloat-equal"])
    AX_CHECK_COMPILE_FLAG([-Wundef], [WERROR_CFLAGS="$WERROR_CFLAGS -Wundef"])
    AX_CHECK_COMPILE_FLAG([-Wendif-labels], [WERROR_CFLAGS="$WERROR_CFLAGS -Wendif-labels"])
    AX_CHECK_COMPILE_FLAG([-Wempty-body], [WERROR_CFLAGS="$WERROR_CFLAGS -Wempty-body"])
# does not make sense with APR as it prefers char* to void*
#    AX_CHECK_COMPILE_FLAG([-Wcast-align], [WERROR_CFLAGS="$WERROR_CFLAGS -Wcast-align"])
    AX_CHECK_COMPILE_FLAG([-Wvla], [WERROR_CFLAGS="$WERROR_CFLAGS -Wvla"])
    AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [WERROR_CFLAGS="$WERROR_CFLAGS -Wunreachable-code"])
    AX_CHECK_COMPILE_FLAG([-Waddress], [WERROR_CFLAGS="$WERROR_CFLAGS -Waddress"])
    AX_CHECK_COMPILE_FLAG([-Wattributes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wattributes"])
    AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdiv-by-zero"])
    AX_CHECK_COMPILE_FLAG([-Wshorten-64-to-32], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshorten-64-to-32"])
    #AX_CHECK_COMPILE_FLAG([-Wno-sign-compare], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-sign-compare"])
    #AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-unused-parameter"])
    #AX_CHECK_COMPILE_FLAG([-Wno-shadow], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-shadow"])
    #AX_CHECK_COMPILE_FLAG([-Wno-undef], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-undef"])

    AX_CHECK_COMPILE_FLAG(["-std=c89"], [WERROR_CFLAGS="$WERROR_CFLAGS -std=c89"])
    AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdeclaration-after-statement"])

# gcc warnings, considered useful as in https://kristerw.blogspot.de/2017/09/useful-gcc-warning-options-not-enabled.html
#
    #AX_CHECK_COMPILE_FLAG(["-Wduplicated-cond"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wduplicated-cond"])
    #AX_CHECK_COMPILE_FLAG(["-Wduplicated-branches"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wduplicated-branches"])
    #AX_CHECK_COMPILE_FLAG(["-Wlogical-op"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wlogical-op"])
    #AX_CHECK_COMPILE_FLAG(["-Wrestrict"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wrestrict"])
    AX_CHECK_COMPILE_FLAG(["-Wnull-dereference"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wnull-dereference"])
    #AX_CHECK_COMPILE_FLAG(["-Wuseless-cast"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wuseless-cast"])
    #AX_CHECK_COMPILE_FLAG(["-Wjump-misses-init"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wjump-misses-init"])
    AX_CHECK_COMPILE_FLAG(["-Wdouble-promotion"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdouble-promotion"])
    AX_CHECK_COMPILE_FLAG(["-Wshadow"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG(["-Wformat=2"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wformat=2"])

    # This is used by the APR_OFFSET macro
    AX_CHECK_COMPILE_FLAG([-Wno-null-pointer-subtraction], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-null-pointer-subtraction"])
fi
AC_SUBST(WERROR_CFLAGS)

# Do we have a pkg-config?
AC_ARG_VAR([PKGCONFIG], [pkg-config executable])
AC_PATH_PROG([PKGCONFIG], [pkg-config])

export BUILD_SUBDIRS="src test"
AC_SUBST(BUILD_SUBDIRS)

prefix="$($APXS -q prefix)"
prefix="${prefix:-/usr}"
export PREFIX="${prefix}"
LDFLAGS="$LDFLAGS -L$($APXS -q libdir)"
CPPFLAGS="$CPPFLAGS -I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR)"
export SYSCONF_DIR="$($APXS -q sysconfdir)"
export LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"

# Checks for header files.
AC_CHECK_HEADERS([ \
    assert.h \
    stddef.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove memset strcasecmp strchr])

# substitution in generated files
AC_SUBST(PREFIX)
AC_SUBST(SYSCONF_DIR)
AC_SUBST(LIBEXEC_DIR)

AC_CONFIG_FILES([
    Makefile
    src/mod_authnz_tailscale.h
    src/Makefile
    test/Makefile
    test/pyhttpd/config.ini
])

AC_OUTPUT

## Determine the compiler's vendor.

COMPILER_VERSION=`"$CC" --version | head -n1 2>/dev/null`

## IBM xlC test if COMPILER_VERSION is empty
if test x"$COMPILER_VERSION" = "x"; then
   COMPILER_VERSION=`"$CC" -qversion | head -n1 2>/dev/null`
fi

## SunCC test if COMPILER_VERSION is empty
if test x"$COMPILER_VERSION" = "x"; then
   COMPILER_VERSION=`"$CC" -V | had -n1 2>&1`
fi

if test x"$COMPILER_VERSION" != "x"; then
   COMPILER_VERSION="=> $COMPILER_VERSION"
fi

AC_MSG_NOTICE([summary of build options:

    Version:        ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
    Host type:      ${host}
    Install prefix: ${prefix}
    APXS:           ${APXS}
    HTTPD-VERSION:  ${HTTPD_VERSION}
    C compiler:     ${CC} ${COMPILER_VERSION}
    CFLAGS:         ${CFLAGS}
    WARNCFLAGS:     ${WERROR_CFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    CPPFLAGS:       ${CPPFLAGS}
    curl            ${CURL_BIN:--}
    curl-config     ${curl_config:--}
    jansson         ${JANSSON_PREFIX:--}
])
