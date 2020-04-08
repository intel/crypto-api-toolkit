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

MAINTAINERCLEANFILES =  $(srcdir)/Makefile.in

noinst_DATA = p11Enclave_u.c p11Enclave_u.h

EXTRA_DIST = $(srcdir)/../trusted/SoftHSMv2/pkcs11/*.h \
             $(srcdir)/../enclave_config/*             \
             $(srcdir)/*.h

if WITH_DCAP
AM_CPPFLAGS = -I$(srcdir)/../../../ -I$(srcdir)/../enclave_config -I$(SGXSDKDIR)/include -I$(srcdir)/../trusted/ -I$(srcdir)/../trusted/SoftHSMv2/common -I$(DCAP_INCLUDE_PATH)
DCAP_LIB = -lsgx_dcap_ql
else
AM_CPPFLAGS = -I$(srcdir)/../../../ -I$(srcdir)/../enclave_config -I$(SGXSDKDIR)/include -I$(srcdir)/../trusted/ -I$(srcdir)/../trusted/SoftHSMv2/common/
DCAP_LIB =
endif

if WITH_P11_KIT
AM_CPPFLAGS += -I$(P11_KIT_INCLUDE_PATH)
else
AM_CPPFLAGS += -I$(srcdir)/../trusted/SoftHSMv2/pkcs11/
endif

AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -m64 -std=c++11 -fpie -fpic -fstack-protector -Wformat -Wformat-security -fexceptions -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type
AM_CFLAGS = -D_FORTIFY_SOURCE=2 -m64 -std=c11 -fvisibility=hidden -fpie -fpic -fstack-protector -Wformat -Wformat-security -fexceptions -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type

AM_LDFLAGS = -L$(SGXSSLDIR)/lib64 -lsgx_usgxssl -L$(SGXSDKDIR)/lib64 $(DCAP_LIB) -lsgx_urts -lsgx_uprotected_fs \
             -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie -export-dynamic -module -shared

lib_LTLIBRARIES = libp11sgx.la

BUILT_SOURCES = p11Enclave_u.h
libp11sgx_la_SOURCES =  p11Enclave_u.c                      \
                        Parallel.cpp                        \
                        p11Sgx.cpp                          \
                        EnclaveInterface.cpp                \
                        EnclaveHelpers.cpp                  \
                        P11Provider.cpp                     \
                        Encryption.cpp                      \
                        Decryption.cpp                      \
                        Digest.cpp                          \
                        GPFunctions.cpp                     \
                        KeyManagement.cpp                   \
                        ObjectManagement.cpp                \
                        SessionManagement.cpp               \
                        SignAndMAC.cpp                      \
                        SlotTokenManagement.cpp             \
                        RNG.cpp                             \
                        Verify.cpp                          \
                        DualFunctionCryptoFunctions.cpp     \
                        Directory.cpp                       \
                        QuoteGeneration.cpp

.PHONY: p11Enclave_u.c

p11Enclave_u.h: p11Enclave_u.c

p11Enclave_u.c:
	$(SGX_EDGER8R) --untrusted p11Enclave.edl --search-path $(srcdir)/../../../ --search-path $(srcdir)/../enclave_config --search-path $(SGXSDKDIR)/include --search-path $(SGXSSLDIR)/include

clean-local:
	test -z *.la || rm -rf *.la
	test -z p11Enclave_u.c || rm -rf p11Enclave_u.c
	test -z p11Enclave_u.h || rm -rf p11Enclave_u.h
	test -z *.lo || rm -rf *.lo
