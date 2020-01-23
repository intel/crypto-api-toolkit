MAINTAINERCLEANFILES =  $(srcdir)/Makefile.in

AM_CPPFLAGS =   -I$(srcdir)/..                      \
                -I$(srcdir)/../common               \
                -I$(srcdir)/../crypto               \
                -I$(srcdir)/../data_mgr             \
                -I$(srcdir)/../pkcs11               \
                -I$(srcdir)/../..                   \
                -I$(builddir)/../../../trusted/     \
                -I$(srcdir)/../../../../../         \
                -I$(SGXSDKDIR)/include              \
                -I$(SGXSDKDIR)/include/tlibc        \
                -I$(SGXSDKDIR)/include/libcxx       \
                -I$(SGXSDKDIR)/include/stdc++       \
                -I$(SGXSDKDIR)/include/stlport

AM_CFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c11 -O3 -Wall -Wno-implicit-function-declaration -nostdinc -fno-builtin-printf -fvisibility=hidden -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type
AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c++11 -O3 -Wall -nostdinc++ -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type

noinst_LTLIBRARIES =    libsofthsm_objectstore.la
libsofthsm_objectstore_la_SOURCES =	ObjectStore.cpp         \
                                    UUID.cpp                \
                                    Directory.cpp           \
                                    File.cpp                \
                                    Generation.cpp          \
                                    OSAttribute.cpp         \
                                    OSToken.cpp             \
                                    ObjectFile.cpp          \
                                    SessionObject.cpp       \
                                    SessionObjectStore.cpp  \
                                    FindOperation.cpp       \
                                    ObjectStoreToken.cpp

EXTRA_DIST = $(srcdir)/*.h
