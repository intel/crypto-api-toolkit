#
# Copyright (C) 2019 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

AC_INIT([cryptoapitoolkit], [1.3])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([dlopen], [disable-static])
AC_LIBTOOL_DLOPEN()

AC_PROG_CXX

AC_ARG_WITH([sgxsdk],
            AC_HELP_STRING([--with-sgxsdk], [Requires SGX SDK. Will default to /opt/intel/sgxsdk]),
            [SGXSDK="${withval}"],
            [echo "--with-sgxsdk option not set. Defaults to /opt/intel/sgxsdk"; SGXSDK="/opt/intel/sgxsdk"])
AC_ARG_WITH([sgxssl],
            AC_HELP_STRING([--with-sgxssl], [Requires SGX SSL. Will default to /opt/intel/sgxssl]),
            [SGXSSL="${withval}"],
            [echo "--with-sgxssl option not set. Defaults to /opt/intel/sgxssl"; SGXSSL="/opt/intel/sgxssl"])

AC_ARG_WITH([toolkit-path],
            AC_HELP_STRING([--with-toolkit-path], [Will default to /opt/intel/cryptoapitoolkit]),
            [TOKENPATH="${withval}"],
            [echo "--with-token-path option not set. Defaults to /opt/intel/cryptoapitoolkit"; TOKENPATH="/opt/intel/cryptoapitoolkit"])

AC_ARG_ENABLE([import-raw-symkey-support],
              AC_HELP_STRING([--enable-import-raw-symkey-support], [Enable importing raw symmetric key. Use with caution/only for test purposes.]),
              [IMPORT_RAW_SYMKEY_SUPPORT="${enableval}"],
              [echo "--import-raw-symkey-support option not set. Defaults to no support for importing raw symmetric key"; IMPORT_RAW_SYMKEY_SUPPORT="no"])

AS_IF([test "x$IMPORT_RAW_SYMKEY_SUPPORT" = "xyes"],
      [AC_DEFINE([IMPORT_RAW_KEY], [], [Support for importing raw symmetric keys])])

AC_ARG_ENABLE([import-raw-symkey-support-for-hmac],
              AC_HELP_STRING([--enable-import-raw-symkey-support-for-hmac], [Enable importing raw symmetric key for HMAC. Use with caution/only for test purposes.]),
              [IMPORT_RAW_SYMKEY_FOR_HMAC_SUPPORT="${enableval}"],
              [echo "--import-raw-symkey-support-for-hmac option not set. Defaults to no support for importing raw symmetric key"; IMPORT_RAW_SYMKEY_FOR_HMAC_SUPPORT="no"])

AS_IF([test "x$IMPORT_RAW_SYMKEY_FOR_HMAC_SUPPORT" = "xyes"],
      [AC_DEFINE([IMPORT_KEY_FOR_HMAC], [], [Support for importing raw symmetric key for HMAC])])

AC_SUBST(SGXSDKDIR, $SGXSDK)
AC_SUBST(SGXSSLDIR, $SGXSSL)
AC_SUBST(CATKTOKENPATH, $TOKENPATH)

AC_PATH_PROG([SGX_EDGER8R], sgx_edger8r, [:], [${SGXSDKDIR}/bin/x64])

if test "$SGX_EDGER8R" = :; then
    AC_MSG_ERROR([This package needs sgx_edger8r])
else
    echo "SGX_EDGER8R present in $SGX_EDGER8R"
fi

AC_PATH_PROG([SGX_SIGN], sgx_sign, [:], [${SGXSDKDIR}/bin/x64])
if test "$SGX_SIGN" = :; then
    AC_MSG_ERROR([This package needs sgx_sign])
else
    echo "SGX_SIGN present in path $SGX_SIGN"
fi

echo "TOKENPATH present in path $TOKENPATH"
AC_DEFINE_UNQUOTED([CRYPTOTOOLKIT_TOKENPATH], "${TOKENPATH}", [Crypto API Toolkit token path] )

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile src/p11/Makefile src/p11/untrusted/Makefile src/p11/trusted/Makefile src/p11Sample/Makefile])

AC_DEFINE_UNQUOTED([INSTALL_DIRECTORY], "${prefix}", [Crypto API Toolkit installation path])

AC_OUTPUT

