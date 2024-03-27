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

AC_PROG_CXX

AC_ARG_WITH([sgxsdk],
            AS_HELP_STRING([--with-sgxsdk], [Requires SGX SDK. Will default to /opt/intel/sgxsdk]),
            [SGXSDK="${withval}"],
            [echo "--with-sgxsdk option not set. Defaults to /opt/intel/sgxsdk"; SGXSDK="/opt/intel/sgxsdk"])

AC_ARG_WITH([sgxssl],
            AS_HELP_STRING([--with-sgxssl], [Requires SGX SSL. Will default to /opt/intel/sgxssl]),
            [SGXSSL="${withval}"],
            [echo "--with-sgxssl option not set. Defaults to /opt/intel/sgxssl"; SGXSSL="/opt/intel/sgxssl"])

AC_ARG_WITH([token-path],
            AS_HELP_STRING([--with-token-path], [Will default to /opt/intel/cryptoapitoolkit]),
            [TOKENPATH="${withval}"],
            [echo "--with-token-path option not set. Defaults to /opt/intel/cryptoapitoolkit"; TOKENPATH="/opt/intel/cryptoapitoolkit"])

AC_ARG_WITH([p11-kit-path],
            AS_HELP_STRING([--with-p11-kit-path], [Requires p11-kit include directory.]),
            [P11KITINCLUDEPATH="${withval}"],
            [echo "--with-p11-kit-path option not set. Not including PKCS11 headers from p11-kit."; P11KITINCLUDEPATH="no"])

AM_CONDITIONAL(WITH_DCAP, false)

AC_ARG_ENABLE([dcap],
              AS_HELP_STRING([--enable-dcap], [To enable dcap supported build]),
              [
              ENABLE_DCAP="${enableval}"
              ],
              [echo "--enable-dcap option not set. ECDSA quote generation is not enabled"; DCAP_SUPPORT="no"])

AM_CONDITIONAL(WITH_MITIGATION, false)

AC_ARG_ENABLE([mitigation],
              AS_HELP_STRING([--enable-mitigation], [Enable mitigations for CVE-2020-0551 (LVI) and other vulnerabilities]),
              [
              AC_DEFINE([ENABLE_MITIGATION], [], [ENABLE MITIGATION])
              AM_CONDITIONAL(WITH_MITIGATION, true)
              ],
              [echo "--enable-mitigation option not set. Mitigations disabled for CVE-2020-0551 (LVI) and other vulnerabilities"])

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

AC_ARG_ENABLE([multiprocess-support],
              AS_HELP_STRING([--disable-multiprocess-support ], [If the token is not expected to be simultaneously accessed for modification by multiple processes (write/update/delete), this flag can give a performance boost.]),
              [AC_DEFINE([MULTIPROCESS_SUPPORT_DISABLED], [], [MULTIPROCESS SUPPORT DISABLED])],
              [echo "--disable-multiprocess-support option not set. If the token is not expected to be simultaneously accessed for modification by multiple processes (write/update/delete), this flag can give a performance boost."])

AC_ARG_WITH([public-key],
            AS_HELP_STRING([--with-public-key], [Public key to be embedded into CTK build]),
            [PUBKEY="${withval}"],
            [echo "--with-public-key option not set"; PUBKEY=""])

if test "${PUBKEY}" == ""; then
    AC_DEFINE_UNQUOTED([PUBKEY_HASH], "", [RSA public key hash])
    AC_DEFINE([DISABLE_TOKEN_KEY_WRAP], [], [Disable wrapping a token key])
else
    hash=$( (openssl rsa -RSAPublicKey_in -in ${PUBKEY} -modulus -noout | grep 'Modulus=' | cut -d'=' -f 2 | tr -d "\n\r" | xxd -r -p && openssl rsa -RSAPublicKey_in -in ${PUBKEY} -text -noout | grep Exponent | cut -d'x' -f 3 | sed 's/.$//' | tr -d "\n\r") | sha384sum | cut -d' ' -f 1 )
    AC_DEFINE_UNQUOTED([PUBKEY_HASH], "$hash", [RSA public key hash])
    keyLength=$( (openssl rsa -RSAPublicKey_in -in ${PUBKEY} -noout -text | grep "RSA Public-Key:" | cut -d" " -f 3 | cut -c2- | tr -d "\n\r"))
    if test $keyLength != "3072"; then
        AC_MSG_ERROR([Please pass an RSA 3072 bit public key])
    fi
fi

AC_ARG_WITH([private-key],
            AS_HELP_STRING([--with-private-key], [Test purpose only, private key to enable C_Wrapkey calls in p11test.]),
            [PRIVKEY="${withval}"],
            [echo "--with-private-key option not set."; PRIVKEY=""])

if test "${PRIVKEY}" != ""; then
    echo "***************************************************************************************************************"
    echo "************************************************** WARNING ****************************************************"
    echo "***************************************************************************************************************"
    echo "--with-private-key OPTION MUST BE USED FOR TESTING PURPOSES ONLY. DO NOT USE THIS OPTION IN RELEASE/PRODUCTION."
    echo "***************************************************************************************************************"
    echo "***************************************************************************************************************"
    echo "***************************************************************************************************************"
fi

AC_DEFINE_UNQUOTED([PRIVATE_KEY], "${PRIVKEY}", [RSA private key path])
AC_DEFINE_UNQUOTED([PUBLIC_KEY], "${PUBKEY}", [RSA public key path])

AC_ARG_ENABLE([session-key-wrap],
              AS_HELP_STRING([--enable-session-key-wrap ], [This option enables wrapping a session key.]),
              [AC_DEFINE([SESSION_KEY_WRAP_SUPPORT], [], [WRAPPING A SESSION KEY IS SUPPORTED])],
              [echo "--enable-session-key-wrap option not set. Session keys cannot be wrapped."])

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
AM_CONDITIONAL(RSA_OAEP_UNWRAP, false)

AC_OUTPUT

