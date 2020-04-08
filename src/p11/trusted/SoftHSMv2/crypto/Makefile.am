MAINTAINERCLEANFILES =  $(srcdir)/Makefile.in

AM_CPPFLAGS =   -I$(srcdir)/..                  \
                -I$(srcdir)/../common           \
                -I$(srcdir)/../data_mgr         \
                -I$(SGXSSLDIR)/include          \
                -I$(SGXSDKDIR)/include          \
                -I$(SGXSDKDIR)/include/tlibc    \
                -I$(SGXSDKDIR)/include/libcxx   \
                -I$(SGXSDKDIR)/include/stdc++   \
                -I$(SGXSDKDIR)/include/stlport 

if WITH_P11_KIT
AM_CPPFLAGS += -I$(P11_KIT_INCLUDE_PATH)
else
AM_CPPFLAGS += -I$(srcdir)/../pkcs11
endif

AM_CFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c11 -O3 -Wall -Wno-implicit-function-declaration -nostdinc -fno-builtin-printf -fvisibility=hidden -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type
AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c++11 -O3 -Wall -nostdinc++ -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type

noinst_LTLIBRARIES =    libsofthsm_crypto.la
libsofthsm_crypto_la_SOURCES =  AESKey.cpp              \
                                AsymmetricAlgorithm.cpp \
                                AsymmetricKeyPair.cpp   \
                                CryptoFactory.cpp       \
                                DerUtil.cpp             \
                                ECParameters.cpp        \
                                ECPublicKey.cpp         \
                                ECPrivateKey.cpp        \
                                EDPublicKey.cpp         \
                                EDPrivateKey.cpp        \
                                HashAlgorithm.cpp       \
                                MacAlgorithm.cpp        \
                                RSAParameters.cpp       \
                                RSAPrivateKey.cpp       \
                                RSAPublicKey.cpp        \
                                SymmetricAlgorithm.cpp  \
                                SymmetricKey.cpp

EXTRA_DIST =    $(srcdir)/*.h   \
                $(srcdir)/*.cpp

# Compile with support of OpenSSL
libsofthsm_crypto_la_SOURCES += OSSLAES.cpp                     \
                                OSSLComp.cpp                    \
                                OSSLCryptoFactory.cpp           \
                                OSSLECDSA.cpp                   \
                                OSSLECKeyPair.cpp               \
                                OSSLECPrivateKey.cpp            \
                                OSSLECPublicKey.cpp             \
                                OSSLEDDSA.cpp                   \
                                OSSLEDKeyPair.cpp               \
                                OSSLEDPrivateKey.cpp            \
                                OSSLEDPublicKey.cpp             \
                                OSSLEVPHashAlgorithm.cpp        \
                                OSSLEVPMacAlgorithm.cpp         \
                                OSSLEVPSymmetricAlgorithm.cpp   \
                                OSSLHMAC.cpp                    \
                                OSSLRNG.cpp                     \
                                OSSLRSA.cpp                     \
                                OSSLRSAKeyPair.cpp              \
                                OSSLRSAPrivateKey.cpp           \
                                OSSLRSAPublicKey.cpp            \
                                OSSLSHA1.cpp                    \
                                OSSLSHA224.cpp                  \
                                OSSLSHA256.cpp                  \
                                OSSLSHA384.cpp                  \
                                OSSLSHA512.cpp                  \
                                OSSLUtil.cpp
