/*
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Copyright (c) 2014 Red Hat
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 AsymWrapUnwrapTests.h

 Contains test cases for C_WrapKey and C_UnwrapKey
 using asymmetrical algorithms (RSA)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ASYMWRAPUNWRAPTESTS_H
#define _SOFTHSM_V2_ASYMWRAPUNWRAPTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class AsymWrapUnwrapTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(AsymWrapUnwrapTests);
	CPPUNIT_TEST(testRsaWrapUnwrap);
#ifdef SGXHSM
    CPPUNIT_TEST(testRsaWrapUnwrapTokenObject);
#endif
#ifdef DCAP_SUPPORT
    // When this test executes, please make sure the DCAP Quote Provider and
    // Quote Generation setup is done properly (you might need to run it with sudo
    // if your Quote Generation setup requires that privilege).
    CPPUNIT_TEST(testQuoteGeneration);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
	void testRsaWrapUnwrap();
#ifdef DCAP_SUPPORT
    void testQuoteGeneration();
#endif
#ifdef SGXHSM
    void testRsaWrapUnwrapTokenObject();
#endif

protected:
	CK_RV generateAesKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE &hKey);
	CK_RV generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#ifdef SGXHSM
    CK_RV generateRsaKeyPairTokenObject(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#endif
	void rsaWrapUnwrap(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey);
#ifdef DCAP_SUPPORT
    bool computeSHA256Hash(const CK_SESSION_HANDLE& hSession,
                           std::vector<CK_BYTE>&    data,
                           std::vector<CK_BYTE>&    hashedData);
    bool customQuoteEcdsa(const CK_MECHANISM_TYPE& mechanismType,
                          const CK_SESSION_HANDLE& hSession,
                          const CK_OBJECT_HANDLE&  hKey);
    bool customQuoteEcdsaTokenObject(const CK_MECHANISM_TYPE& mechanismType,
                                     const CK_SESSION_HANDLE& hSession,
                                     const CK_OBJECT_HANDLE&  hKey);
    bool customQuoteEcdsaSingleUse(const CK_MECHANISM_TYPE& mechanismType,
                                   const CK_SESSION_HANDLE& hSession,
                                   const CK_OBJECT_HANDLE&  hPublicKey,
                                   const CK_OBJECT_HANDLE&  hPrivateKey);
#endif
#ifdef SGXHSM
    void rsaWrapUnwrapTokenObject(CK_MECHANISM_TYPE mechanismType,
                                  CK_SESSION_HANDLE hSession,
                                  CK_OBJECT_HANDLE  hPublicKey,
                                  CK_OBJECT_HANDLE  hPrivateKey);
#endif
};

#endif // !_SOFTHSM_V2_ASYMWRAPUNWRAPTESTS_H
