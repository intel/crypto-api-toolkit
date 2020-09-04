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
 * Copyright (c) 2012 SURFnet
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
 AsymEncryptDecryptTests.h

 Contains test cases for C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt
 using asymmetrical algorithms (i.e., RSA)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ASYMENCRYPTDECRYPTTESTS_H
#define _SOFTHSM_V2_ASYMENCRYPTDECRYPTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class AsymEncryptDecryptTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(AsymEncryptDecryptTests);
	CPPUNIT_TEST(testRsaEncryptDecrypt);
	CPPUNIT_TEST_SUITE_END();

public:
	void testRsaEncryptDecrypt();
    void testNullTemplate();

protected:
	CK_RV generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
	void rsaEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey);
	void rsaOAEPParams(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey);

    /*
        rsaWrapUnwrapWithAes is one of the SKC's flows that does wrap of RSA_Private_Key with AES_Key (using standard openssl)
        and unwraps the RSA_Private_Key into CTK (using C_UnwrapKey).

        This test verifies if the RSA_Private_Key is the same before wrapping and after unwrapping.
        The test does sample encrypt of a buffer using RSA_Key before wrapping and then does decrypt post unwrap using the unwrapped key.

        NOTE: OPENSSL NEEDS TO BE INSTALLED TO RUN THIS TEST.

        Enable AES_UNWRAP_RSA in configure.ac using the below two lines.

        AM_CONDITIONAL(AES_UNWRAP_RSA, true)
        AC_DEFINE([AES_UNWRAP_RSA], [], [AES_UNWRAP_RSA])
    */
#ifdef AES_UNWRAP_RSA
    CK_RV rsaWrapUnwrapWithAes(const CK_SESSION_HANDLE& hSession);
#endif
};

#endif // !_SOFTHSM_V2_ASYMENCRYPTDECRYPTTESTS_H
