MAINTAINERCLEANFILES =  $(srcdir)/Makefile.in

AM_CPPFLAGS =   -I$(srcdir)/common               \
                -I$(srcdir)/crypto               \
                -I$(srcdir)/data_mgr             \
                -I$(srcdir)/handle_mgr           \
                -I$(srcdir)/object_store         \
                -I$(srcdir)/session_mgr          \
                -I$(srcdir)/slot_mgr             \
                -I$(srcdir)/..                   \
                -I$(builddir)/..                 \
                -I$(srcdir)/../../../../         \
                -I$(SGXSSLDIR)/include           \
                -I$(SGXSDKDIR)/include           \
                -I$(SGXSDKDIR)/include/tlibc     \
                -I$(SGXSDKDIR)/include/libcxx    \
                -I$(SGXSDKDIR)/include/stdc++    \
                -I$(SGXSDKDIR)/include/stlport

if WITH_P11_KIT
AM_CPPFLAGS += -I$(P11_KIT_INCLUDE_PATH)
else
AM_CPPFLAGS += -I$(srcdir)/pkcs11
endif

AM_CFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c11 -O3 -Wall -Wno-implicit-function-declaration -nostdinc -fno-builtin-printf -fvisibility=hidden -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type
AM_CXXFLAGS = -D_FORTIFY_SOURCE=2 -DOSID=1 -m64 -std=c++11 -O3 -Wall -nostdinc++ -fstack-protector -fpie -fpic -Wformat -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -Wreturn-type -Werror=return-type

noinst_LTLIBRARIES =	libsofthsm2.la

libsofthsm2_la_SOURCES =    access.cpp             \
                            main.cpp               \
                            P11Attributes.cpp      \
                            P11Objects.cpp         \
                            EnclaveSecureUtils.cpp \
                            SoftHSM.cpp

libsofthsm2_la_LIBADD =     common/libsofthsm_common.la             \
                            crypto/libsofthsm_crypto.la             \
                            data_mgr/libsofthsm_datamgr.la          \
                            handle_mgr/libsofthsm_handlemgr.la      \
                            object_store/libsofthsm_objectstore.la  \
                            session_mgr/libsofthsm_sessionmgr.la    \
                            slot_mgr/libsofthsm_slotmgr.la

SUBDIRS =   common          \
            crypto          \
            data_mgr        \
            object_store    \
            session_mgr     \
            slot_mgr        \
            handle_mgr
