MAINTAINERCLEANFILES =  $(srcdir)/Makefile.in

if WITH_DCAP
AM_CPPFLAGS =   -I$(srcdir)/..                              \
                -I$(DCAP_INCLUDE_PATH)                      \
                -I$(SGXSDKDIR)/include                      \
                -I$(srcdir)/../p11/trusted/SoftHSMv2/common
DCAP_LIB = -lsgx_dcap_ql
else
AM_CPPFLAGS =   -I$(srcdir)/..                              \
                -I$(SGXSDKDIR)/include                      \
                -I$(srcdir)/../p11/trusted/SoftHSMv2/common
DCAP_LIB =
endif

if WITH_P11_KIT
AM_CPPFLAGS += -I$(P11_KIT_INCLUDE_PATH)
else
AM_CPPFLAGS += -I$(srcdir)/../p11/trusted/SoftHSMv2/pkcs11
endif

AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -m64 -std=c++11 -fpie -fpic -fstack-protector -Wformat -Wformat-security -fexceptions -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type

noinst_PROGRAMS =  p11test

p11test_SOURCES =   p11test.cpp                 \
                    SymmetricAlgorithmTests.cpp \
                    DigestTests.cpp             \
                    InitTests.cpp               \
                    InfoTests.cpp               \
                    RandomTests.cpp             \
                    SessionTests.cpp            \
                    TokenTests.cpp              \
                    UserTests.cpp               \
                    ObjectTests.cpp             \
                    SignVerifyTests.cpp         \
                    AsymEncryptDecryptTests.cpp \
                    AsymWrapUnwrapTests.cpp     \
                    UnsupportedAPITests.cpp     \
                    TestsBase.cpp               \
                    TestsNoPINInitBase.cpp

if AES_UNWRAP_RSA
AM_LDFLAGS = -ldl $(DCAP_LIB) -L../p11/untrusted/.libs -lp11sgx -lcppunit -no-install -pthread -L/usr/local/lib -lssl -lcrypto -static -Wl,-z,relro -Wl,-z,now
else
AM_LDFLAGS = -ldl $(DCAP_LIB) -L../p11/untrusted/.libs -lp11sgx -lcppunit -no-install -pthread -static -Wl,-z,relro -Wl,-z,now -L/usr/local/lib
endif

EXTRA_DIST =    $(srcdir)/*.h
