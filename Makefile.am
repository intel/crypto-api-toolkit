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

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = $(srcdir)/src/p11/trusted/SoftHSMv2/pkcs11/cryptoki.h \
             $(srcdir)/src/p11/trusted/SoftHSMv2/pkcs11/pkcs11.h \
             $(srcdir)/src/p11/trusted/SoftHSMv2/pkcs11/pkcs11f.h \
             $(srcdir)/src/p11/trusted/SoftHSMv2/pkcs11/pkcs11t.h \
             $(srcdir)/src/p11/enclave_config/p11Enclave.config.xml \
             $(srcdir)/src/p11/enclave_config/p11Enclave.edl \
             $(srcdir)/src/p11/enclave_config/p11Enclave_private.pem \
             $(srcdir)/autogen.sh

dist-hook:
	rm -f $(distdir)/src/p11/trusted/p11Enclave_t*
	rm -f $(distdir)/src/p11/untrusted/p11Enclave_u*

SUBDIRS = src

SGXSSL_TLIB = sgx_tsgxssl
SGXSSL_TCRYPTO = sgx_tsgxssl_crypto
SGXSSL_ULIB = sgx_usgxssl

BUILT_SOURCES = PREPARE_SGX_SSL
PREPARE_SGXSSL = src/dep_check/sgxssl/prepare_sgxssl.sh
CHECK_OPENSSL_VERSION = src/dep_check/sgxssl/check_openssl_version.sh

if WITH_MITIGATION
SGXSSLLIBDIR = $(SGXSSLDIR)/lib64/cve_2020_0551_load
TARGET = all
else
SGXSSLLIBDIR = $(SGXSSLDIR)/lib64
endif

PREPARE_SGX_SSL:
	chmod 755 $(PREPARE_SGXSSL)
	chmod 755 $(CHECK_OPENSSL_VERSION)
	test -f $(SGXSSLLIBDIR)/lib$(SGXSSL_TCRYPTO).a && test -f $(SGXSSLLIBDIR)/lib$(SGXSSL_TLIB).a && test -f $(SGXSSLDIR)/lib64/lib$(SGXSSL_ULIB).a  && ./$(CHECK_OPENSSL_VERSION) $(SGXSSLDIR) $(SGXSSLLIBDIR) $(SGXSDKDIR) $ || ./$(PREPARE_SGXSSL) $(SGXSSLDIR) $(TARGET)

clean-local:
	test -z src/dep_check/sgxssl/sgxssl || rm -rf src/dep_check/sgxssl/sgxssl
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/OSSLVersion
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/enclave.so
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/enclave.signed.so
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/App/*.o
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/App/Enclave_u.*
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/Enclave/*.o
	rm -f src/dep_check/sgxssl/OSSLVersionEnclave/Enclave/Enclave_t.*

install-exec-local:
	mkdir -p $(CATKTOKENPATH)/tokens
	chmod -R 1777 $(CATKTOKENPATH)/tokens
	mkdir -p $(prefix)/include
	chmod -R 1777 $(prefix)/include
	cp $(srcdir)/src/p11/trusted/SoftHSMv2/common/QuoteGeneration.h $(srcdir)/src/p11/trusted/SoftHSMv2/common/cryptoki.h $(srcdir)/src/p11/trusted/SoftHSMv2/common/QuoteGenerationDefs.h $(prefix)/include

if !WITH_P11_KIT
	cp $(srcdir)/src/p11/trusted/SoftHSMv2/pkcs11/* $(prefix)/include
endif