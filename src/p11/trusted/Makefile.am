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

noinst_DATA = p11Enclave_t.c p11Enclave_t.h
AM_CFLAGS = -D_FORTIFY_SOURCE=2 -m64 -Wall -O2 -DOSID=1 -nostdinc -fvisibility=hidden -fpie -fpic -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -include "tsgxsslio.h" -Wno-implicit-function-declaration -std=c11 -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv
AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -std=c++11 -nostdinc++ -fstack-protector -Wformat -Wformat-security -fpie -fpic -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv

if WITH_DCAP
AM_CPPFLAGS = -I$(SGXSSLDIR)/include -I$(SGXSDKDIR)/include -I$(SGXSDKDIR)/include/ipp -I$(SGXSDKDIR)/include/tlibc -I$(SGXSDKDIR)/include/libcxx -I$(SGXSDKDIR)/include/stdc++ -I$(SGXSDKDIR)/include/stlport -I$(DCAP_INCLUDE_PATH) -I$(srcdir)/../include -I$(srcdir)/../enclave_config
else
AM_CPPFLAGS = -I$(SGXSSLDIR)/include -I$(SGXSDKDIR)/include -I$(SGXSDKDIR)/include/ipp -I$(SGXSDKDIR)/include/tlibc -I$(SGXSDKDIR)/include/libcxx -I$(SGXSDKDIR)/include/stdc++ -I$(SGXSDKDIR)/include/stlport -I$(srcdir)/../include -I$(srcdir)/../enclave_config
endif

EXTRA_DIST = $(srcdir)/../include/*.h \
             $(srcdir)/../enclave_config/*.xml \
             $(srcdir)/../enclave_config/*.pem \
             $(srcdir)/../enclave_config/*.edl

noinst_LTLIBRARIES = libp11SgxEnclave.la

libp11SgxEnclave_la_SOURCES =  p11Enclave_t.h \
                               p11Enclave_t.c \
                               p11Enclave.cpp \
                               AsymmetricCrypto.cpp \
                               AsymmetricCrypto.h \
                               AsymmetricKeyCache.cpp \
                               AsymmetricKeyCache.h \
                               ByteBuffer.cpp \
                               ByteBuffer.h \
                               CryptParams.h \
                               EVPContextHandle.cpp \
                               EVPContextHandle.h \
                               EVPCtxStateCache.cpp \
                               EVPCtxStateCache.h \
                               EVPDecrypt.cpp \
                               EVPDecrypt.h \
                               EVPEncrypt.cpp \
                               EVPEncrypt.h \
                               IppContextHandle.cpp \
                               IppContextHandle.h \
                               IppDecrypt.cpp \
                               IppDecrypt.h \
                               IppEncrypt.cpp \
                               IppEncrypt.h \
                               IppStateCache.cpp \
                               IppStateCache.h \
                               HashCrypto.cpp \
                               HashCrypto.h \
                               HashDefs.h \
                               HashStateCache.cpp \
                               HashStateCache.h \
                               IppHash.cpp \
                               IppHash.h \
                               SymmetricCrypto.cpp \
                               SymmetricCrypto.h \
                               SymmetricKeyCache.cpp \
                               SymmetricKeyCache.h

p11Enclave_t.h: p11Enclave_t.c

p11Enclave_t.c: $(SGX_EDGER8R) ../enclave_config/p11Enclave.edl
	$(SGX_EDGER8R) --trusted p11Enclave.edl --search-path $(srcdir)/../enclave_config --search-path $(SGXSDKDIR)/include --search-path $(SGXSSLDIR)/include

all-local: libp11SgxEnclave.la
	@echo "--------------------libp11SgxEnclave.la built-----------------------------"
#   this is a workaround to relink the enclave because the linker flags for the enclave are not handled properly by libtool
#	ls -laR ./.libs/
	$(CXX) .libs/p11Enclave_t.o .libs/p11Enclave.o .libs/AsymmetricCrypto.o .libs/AsymmetricKeyCache.o .libs/ByteBuffer.o .libs/EVPContextHandle.o .libs/EVPCtxStateCache.o .libs/EVPDecrypt.o .libs/EVPEncrypt.o .libs/IppContextHandle.o .libs/IppDecrypt.o .libs/IppEncrypt.o .libs/IppStateCache.o .libs/HashCrypto.o .libs/HashStateCache.o .libs/IppHash.o .libs/SymmetricCrypto.o .libs/SymmetricKeyCache.o -m64 -Wall -O2 -D_FORTIFY_SOURCE=2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie -L/opt/intel/sgxssl/lib64 -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto -L/opt/intel/sgxsdk/lib64 -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wpragmas -Wl,-soname -Wl,libp11SgxEnclave.so.0 -o .libs/libp11SgxEnclave.so.0.0.0
	@$(SGX_SIGN) sign -key $(srcdir)/../enclave_config/p11Enclave_private.pem -enclave ./.libs/libp11SgxEnclave.so.0.0.0 -out ./.libs/libp11SgxEnclave.signed.so -config $(srcdir)/../enclave_config/p11Enclave.config.xml
	@echo "--------------------libp11SgxEnclave.signed.so built-----------------------------"

install-exec-local:
	cp .libs/libp11SgxEnclave.signed.so $(prefix)/lib

uninstall-local:
	rm -f $(prefix)/lib/libp11SgxEnclave.signed.so*
	rm -f $(prefix)/lib/libp11SgxEnclave.so.*

clean-local:
	test -z *.la || rm -rf *.la
	test -z p11Enclave_t.c || rm -rf p11Enclave_t.c
	test -z p11Enclave_t.h || rm -rf p11Enclave_t.h
	test -z *.lo || rm -rf *.lo
