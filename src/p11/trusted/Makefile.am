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

AM_CFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c11 -O3 -Wall -Wno-implicit-function-declaration -nostdinc -include "tsgxsslio.h" -fno-builtin-printf -fvisibility=hidden -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type
AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c++11 -O3 -Wall -nostdinc++ -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type

if WITH_DCAP
AM_CPPFLAGS = -I$(srcdir)/../enclave_config -I$(srcdir)/../../../ -I$(SGXSSLDIR)/include -I$(SGXSDKDIR)/include -I$(SGXSDKDIR)/include/ipp -I$(SGXSDKDIR)/include/tlibc -I$(SGXSDKDIR)/include/libcxx -I$(SGXSDKDIR)/include/stdc++ -I$(SGXSDKDIR)/include/stlport -I$(DCAP_INCLUDE_PATH) -I$(srcdir)/SoftHSMv2/ -I$(srcdir)/SoftHSMv2/common
else
AM_CPPFLAGS = -I$(srcdir)/../enclave_config -I$(srcdir)/../../../ -I$(SGXSSLDIR)/include -I$(SGXSDKDIR)/include -I$(SGXSDKDIR)/include/ipp -I$(SGXSDKDIR)/include/tlibc -I$(SGXSDKDIR)/include/libcxx -I$(SGXSDKDIR)/include/stdc++ -I$(SGXSDKDIR)/include/stlport -I$(srcdir)/SoftHSMv2/ -I$(srcdir)/SoftHSMv2/common
endif

if WITH_P11_KIT
AM_CPPFLAGS += -I$(P11_KIT_INCLUDE_PATH)
else
AM_CPPFLAGS += -I$(srcdir)/SoftHSMv2/pkcs11
endif

EXTRA_DIST = $(srcdir)/../enclave_config/*        \
             $(srcdir)/*.h                        \
             $(srcdir)/SoftHSMv2/*.h              \
             $(srcdir)/SoftHSMv2/common/*.h       \
             $(srcdir)/SoftHSMv2/crypto/*.h       \
             $(srcdir)/SoftHSMv2//data_mgr/*.h    \
             $(srcdir)/SoftHSMv2/handle_mgr/*.h   \
             $(srcdir)/SoftHSMv2/object_store/*.h \
             $(srcdir)/SoftHSMv2/pkcs11/*.h       \
             $(srcdir)/SoftHSMv2/session_mgr/*.h  \
             $(srcdir)/SoftHSMv2/slot_mgr/*.h

noinst_LTLIBRARIES = libp11SgxEnclave.la

libp11SgxEnclave_la_SOURCES = e_pkcs11t.h    \
                              p11Enclave_t.h \
                              p11Enclave_t.c \
                              p11Enclave.cpp

libp11SgxEnclave_la_LIBADD = SoftHSMv2/libsofthsm2.la

SUBDIRS	= SoftHSMv2

BUILT_SOURCES = p11Enclave_t.h

p11Enclave_t.h: p11Enclave_t.c

p11Enclave_t.c: $(SGX_EDGER8R) ../enclave_config/p11Enclave.edl
	$(SGX_EDGER8R) --trusted p11Enclave.edl --search-path $(srcdir)/../../../ --search-path $(srcdir)/../enclave_config --search-path $(SGXSDKDIR)/include --search-path $(SGXSSLDIR)/include

all-local: libp11SgxEnclave.la
	@echo "--------------------libp11SgxEnclave.la built-----------------------------"
#   this is a workaround to relink the enclave because the linker flags for the enclave are not handled properly by libtool
#	ls -laR ./.libs/
	$(CXX) .libs/p11Enclave_t.o                                         \
		   .libs/p11Enclave.o                                           \
		   ./SoftHSMv2/common/Configuration.o                           \
		   ./SoftHSMv2/common/fatal.o                                   \
		   ./SoftHSMv2/common/osmutex.o                                 \
		   ./SoftHSMv2/common/MutexFactory.o                            \
		   ./SoftHSMv2/handle_mgr/Handle.o                              \
		   ./SoftHSMv2/handle_mgr/HandleManager.o                       \
		   ./SoftHSMv2/data_mgr/SecureMemoryRegistry.o                  \
		   ./SoftHSMv2/data_mgr/RFC4880.o                               \
		   ./SoftHSMv2/data_mgr/SecureDataManager.o                     \
		   ./SoftHSMv2/data_mgr/ByteString.o                            \
		   ./SoftHSMv2/crypto/OSSLSHA512.o                              \
		   ./SoftHSMv2/crypto/AsymmetricAlgorithm.o                     \
		   ./SoftHSMv2/crypto/HashAlgorithm.o                           \
		   ./SoftHSMv2/crypto/OSSLEDKeyPair.o                           \
		   ./SoftHSMv2/crypto/OSSLAES.o                                 \
		   ./SoftHSMv2/crypto/OSSLEVPSymmetricAlgorithm.o               \
		   ./SoftHSMv2/crypto/EDPublicKey.o                             \
		   ./SoftHSMv2/crypto/OSSLRSAPrivateKey.o                       \
		   ./SoftHSMv2/crypto/SymmetricAlgorithm.o                      \
		   ./SoftHSMv2/crypto/ECParameters.o                            \
		   ./SoftHSMv2/crypto/OSSLECKeyPair.o                           \
		   ./SoftHSMv2/crypto/OSSLEDDSA.o                               \
		   ./SoftHSMv2/crypto/OSSLEVPMacAlgorithm.o                     \
		   ./SoftHSMv2/crypto/OSSLSHA1.o                                \
		   ./SoftHSMv2/crypto/OSSLSHA224.o                              \
		   ./SoftHSMv2/crypto/OSSLSHA256.o                              \
		   ./SoftHSMv2/crypto/OSSLUtil.o                                \
		   ./SoftHSMv2/crypto/SymmetricKey.o                            \
		   ./SoftHSMv2/crypto/RSAPublicKey.o                            \
		   ./SoftHSMv2/crypto/OSSLSHA384.o                              \
		   ./SoftHSMv2/crypto/OSSLECPublicKey.o                         \
		   ./SoftHSMv2/crypto/OSSLCryptoFactory.o                       \
		   ./SoftHSMv2/crypto/DerUtil.o                                 \
		   ./SoftHSMv2/crypto/RSAParameters.o                           \
		   ./SoftHSMv2/crypto/OSSLComp.o                                \
		   ./SoftHSMv2/crypto/OSSLRSAKeyPair.o                          \
		   ./SoftHSMv2/crypto/AESKey.o                                  \
		   ./SoftHSMv2/crypto/OSSLECDSA.o                               \
		   ./SoftHSMv2/crypto/EDPrivateKey.o                            \
		   ./SoftHSMv2/crypto/OSSLEDPublicKey.o                         \
		   ./SoftHSMv2/crypto/OSSLHMAC.o                                \
		   ./SoftHSMv2/crypto/CryptoFactory.o                           \
		   ./SoftHSMv2/crypto/ECPublicKey.o                             \
		   ./SoftHSMv2/crypto/RSAPrivateKey.o                           \
		   ./SoftHSMv2/crypto/OSSLRSA.o                                 \
		   ./SoftHSMv2/crypto/AsymmetricKeyPair.o                       \
		   ./SoftHSMv2/crypto/OSSLRSAPublicKey.o                        \
		   ./SoftHSMv2/crypto/OSSLEVPHashAlgorithm.o                    \
		   ./SoftHSMv2/crypto/ECPrivateKey.o                            \
		   ./SoftHSMv2/crypto/MacAlgorithm.o                            \
		   ./SoftHSMv2/crypto/OSSLECPrivateKey.o                        \
		   ./SoftHSMv2/crypto/OSSLRNG.o                                 \
		   ./SoftHSMv2/crypto/OSSLEDPrivateKey.o                        \
		   ./SoftHSMv2/P11Objects.o                                     \
		   ./SoftHSMv2/slot_mgr/Token.o                                 \
		   ./SoftHSMv2/slot_mgr/SlotManager.o                           \
		   ./SoftHSMv2/slot_mgr/Slot.o                                  \
		   ./SoftHSMv2/object_store/OSToken.o                           \
		   ./SoftHSMv2/object_store/ObjectStore.o                       \
		   ./SoftHSMv2/object_store/ObjectFile.o                        \
		   ./SoftHSMv2/object_store/FindOperation.o                     \
		   ./SoftHSMv2/object_store/UUID.o                              \
		   ./SoftHSMv2/object_store/SessionObjectStore.o                \
		   ./SoftHSMv2/object_store/SessionObject.o                     \
		   ./SoftHSMv2/object_store/OSAttribute.o                       \
		   ./SoftHSMv2/object_store/ObjectStoreToken.o                  \
		   ./SoftHSMv2/object_store/Directory.o                         \
		   ./SoftHSMv2/object_store/Generation.o                        \
		   ./SoftHSMv2/object_store/File.o                              \
		   ./SoftHSMv2/main.o                                           \
		   ./SoftHSMv2/access.o                                         \
           ./SoftHSMv2/EnclaveSecureUtils.o                             \
		   ./SoftHSMv2/SoftHSM.o                                        \
		   ./SoftHSMv2/session_mgr/Session.o                            \
		   ./SoftHSMv2/session_mgr/SessionManager.o                     \
		   ./SoftHSMv2/P11Attributes.o                                  \
		   -m64 -Wall -O2 -D_FORTIFY_SOURCE=2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie -L$(SGXSSLDIR)/lib64/cve_2020_0551_load -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto -L$(SGXSDKDIR)/lib64 -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -lsgx_tprotected_fs -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wpragmas -Wl,-soname -Wl,libp11SgxEnclave.so.0 -o .libs/libp11SgxEnclave.so.0.0.0
		@$(SGX_SIGN) sign -key $(srcdir)/../enclave_config/p11Enclave_private.pem -enclave ./.libs/libp11SgxEnclave.so.0.0.0 -out ./.libs/libp11SgxEnclave.signed.so -config $(srcdir)/../enclave_config/p11Enclave.config.xml
		@echo "--------------------libp11SgxEnclave.signed.so built-----------------------------"

install-exec-local:
	cp .libs/libp11SgxEnclave.signed.so $(prefix)/lib

uninstall-local:
	rm -f $(prefix)/lib/libp11SgxEnclave.signed.so* \
	rm -f $(prefix)/lib/libp11SgxEnclave.so.*       \
    rm -f $(prefix)/include/cryptoki.h              \
    rm -f $(prefix)/include/pkcs11t.h               \
    rm -f $(prefix)/include/pkcs11.h                \
    rm -f $(prefix)/include/pkcs11f.h               \
    rm -f $(prefix)/include/QuoteGeneration.h       \
    rm -f $(prefix)/include/QuoteGenerationDefs.h

clean-local:
	test -z *.la || rm -rf *.la
	test -z p11Enclave_t.c || rm -rf p11Enclave_t.c
	test -z p11Enclave_t.h || rm -rf p11Enclave_t.h
	test -z *.lo || rm -rf *.lo
