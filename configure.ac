#
# Copyright (C) 2019-2020 Intel Corporation. All rights reserved.
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

AC_INIT([cryptoapitoolkit], [2.0])
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

AC_ARG_WITH([token-path],
            AC_HELP_STRING([--with-token-path], [Will default to /opt/intel/cryptoapitoolkit]),
            [TOKENPATH="${withval}"],
            [echo "--with-token-path option not set. Defaults to /opt/intel/cryptoapitoolkit"; TOKENPATH="/opt/intel/cryptoapitoolkit"])

AC_ARG_WITH([p11-kit-path],
            AC_HELP_STRING([--with-p11-kit-path], [Requires p11-kit include directory.]),
            [P11KITINCLUDEPATH="${withval}"],
            [echo "--with-p11-kit-path option not set. Not including PKCS11 headers from p11-kit."; P11KITINCLUDEPATH="no"])

AM_CONDITIONAL(WITH_DCAP, false)

AC_ARG_ENABLE([dcap],
              AC_HELP_STRING([--enable-dcap], [To enable dcap supported build]),
              [
              ENABLE_DCAP="${enableval}"
              ],
              [echo "--enable-dcap option not set. ECDSA quote generation is not enabled"; DCAP_SUPPORT="no"])

AM_CONDITIONAL(WITH_P11_KIT, false)

if test "x$P11KITINCLUDEPATH" != "xno"; then
    AC_CHECK_FILE(${P11KITINCLUDEPATH}/pkcs11.h, , [P11KITINCLUDEPATHDIR=no])
    if test x"$P11KITINCLUDEPATHDIR" = "xno"; then
        AC_MSG_ERROR([This package needs p11-kit include directory path])
    else
        AC_SUBST(P11_KIT_INCLUDE_PATH, $P11KITINCLUDEPATH)
        AM_CONDITIONAL(WITH_P11_KIT, true)
    fi
fi

AS_IF([test "x$ENABLE_DCAP" = "xyes"],
      [
      AC_DEFINE([DCAP_SUPPORT], [], [DCAP SUPPORT])
      AC_SUBST(DCAP_INCLUDE_PATH, "/usr/include")
      AM_CONDITIONAL(WITH_DCAP, true)
      ]
      )

AC_ARG_ENABLE([ephemeral-quote],
              AC_HELP_STRING([--enable-ephemeral-quote], [Requires this option to destroy quote generation key after one unwrap]),
              [EPHEMERAL_QUOTE_SUPPORT="${enableval}"],
              [echo "--with-ephemeral-quote option not set. Quote genration key is not destroyed after one unwrap"; EPHEMERAL_QUOTE_SUPPORT="no"])

AS_IF([test "x$EPHEMERAL_QUOTE_SUPPORT" = "xyes"],
      [AC_DEFINE([EPHEMERAL_QUOTE], [], [EPHEMERAL QUOTE])])

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
AC_DEFINE_UNQUOTED([CRYPTOTOOLKIT_TOKENPATH], "${TOKENPATH}", [Crypto API Toolkit token path])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile src/p11/Makefile src/p11/untrusted/Makefile src/p11/trusted/Makefile src/p11/trusted/SoftHSMv2/Makefile src/p11/trusted/SoftHSMv2/common/Makefile src/p11/trusted/SoftHSMv2/crypto/Makefile src/p11/trusted/SoftHSMv2/data_mgr/Makefile src/p11/trusted/SoftHSMv2/object_store/Makefile src/p11/trusted/SoftHSMv2/session_mgr/Makefile src/p11/trusted/SoftHSMv2/slot_mgr/Makefile src/p11/trusted/SoftHSMv2/handle_mgr/Makefile src/test/Makefile])
#AC_CONFIG_FILES([Makefile src/Makefile src/test/Makefile])

AC_DEFINE_UNQUOTED([INSTALL_DIRECTORY], "${prefix}", [Crypto API Toolkit installation path])

AC_DEFINE([SGXHSM], [], [SGX HSM])
AC_DEFINE_UNQUOTED([DEFAULT_TOKENDIR], "${TOKENPATH}/tokens", [SGXHSM tokendir])
AC_DEFINE_UNQUOTED([DEFAULT_OBJECTSTORE_BACKEND], "file", [SGXHSM default object store])
AC_DEFINE_UNQUOTED([MIN_PIN_LEN], 4, [Minimum PIN length])
AC_DEFINE_UNQUOTED([MAX_PIN_LEN], 16, [Maximum PIN length])
AC_DEFINE_UNQUOTED([MAX_TRANSFER_BYTES], 184320, [(180*1024) This is the maximum size set for concatenated sub directories and files that can be safely copied into enclave based on StackMaxSize=0x40000. If there is a requirement to copy more size than this, StackMaxSize(in enclave's configuration xml) needs to be increased appropriately.])
AC_DEFINE([WITH_AES_GCM], [], [WITH AES GCM])
AC_DEFINE([HAVE_AES_KEY_WRAP], [], [HAVE AES KEY WRAP])
AC_DEFINE([HAVE_AES_KEY_WRAP_PAD], [], [HAVE AES KEY WRAP PAD])
AC_DEFINE([WITH_RAW_PSS], [], [WITH RAW PSS])
AC_DEFINE([WITH_ECC], [], [WITH ECC])
AC_DEFINE([WITH_EDDSA], [], [WITH EDDSA])

AM_CONDITIONAL(AES_UNWRAP_RSA, false)

AC_OUTPUT

