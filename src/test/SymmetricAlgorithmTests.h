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
 SymmetricAlgorithmTests.h

 Contains test cases for symmetrical algorithms (i.e., AES and DES)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H
#define _SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class SymmetricAlgorithmTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(SymmetricAlgorithmTests);
	CPPUNIT_TEST(testAesEncryptDecrypt);
#if 0 // Unsupported by Crypto API Toolkit
	CPPUNIT_TEST(testDesEncryptDecrypt);
#endif // Unsupported by Crypto API Toolkit
    CPPUNIT_TEST(testAesWrapUnwrap);
#ifdef SGXHSM
    CPPUNIT_TEST(testAesWrapUnwrapTokenObject);
#ifdef WITH_AES_GCM
    CPPUNIT_TEST(testAesGcmEncryptDecrypt);
#endif
#endif
    CPPUNIT_TEST(testNullTemplate);
#if 0 // Unsupported by Crypto API Toolkit
    CPPUNIT_TEST(testNonModifiableDesKeyGeneration);
#endif // Unsupported by Crypto API Toolkit
    CPPUNIT_TEST(testCheckValue);
    CPPUNIT_TEST(testAesCtrOverflow);
#if 0 // Unsupported by Crypto API Toolkit
    CPPUNIT_TEST(testGenericKey);
#endif // Unsupported by Crypto API Toolkit
    CPPUNIT_TEST(testRsaWrapWithAes);
    CPPUNIT_TEST_SUITE_END();

public:
	void testAesEncryptDecrypt();
    void testRsaWrapWithAes();
#ifdef SGXHSM
    void testAesWrapUnwrapTokenObject();
#ifdef WITH_AES_GCM
    void testAesGcmEncryptDecrypt();
#endif
#endif
#if 0 // Unsupported by Crypto API Toolkit
	void testDesEncryptDecrypt();
#endif // Unsupported by Crypto API Toolkit
	void testAesWrapUnwrap();
	void testNullTemplate();
#if 0 // Unsupported by Crypto API Toolkit
	void testNonModifiableDesKeyGeneration();
#endif // Unsupported by Crypto API Toolkit
	void testCheckValue();
	void testAesCtrOverflow();
#if 0 // Unsupported by Crypto API Toolkit
	void testGenericKey();
#endif // Unsupported by Crypto API Toolkit

protected:
#if 0 // Unsupported by Crypto API Toolkit
	CK_RV generateGenericKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif // Unsupported by Crypto API Toolkit
	CK_RV generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
	CK_RV generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
	CK_RV generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif
	CK_RV generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif // Unsupported by Crypto API Toolkit
	void encryptDecrypt(
			CK_MECHANISM_TYPE mechanismType,
			size_t sizeOfIV,
			CK_SESSION_HANDLE hSession,
			CK_OBJECT_HANDLE hKey,
			size_t messageSize,
			bool isSizeOK=true);
#if 0 // Unsupported by Crypto API Toolkit
	void aesWrapUnwrapGeneric(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
#endif // Unsupported by Crypto API Toolkit
    void aesWrapUnwrap(CK_MECHANISM_TYPE mechanismType, 
                       CK_SESSION_HANDLE hSession, 
                       CK_OBJECT_HANDLE hKey, 
                       CK_OBJECT_HANDLE hKeyData);
	void aesWrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV generateRsaPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
    void encryptDecryptAfterWrapUnwrap(CK_MECHANISM_TYPE     mechanismType,
                                       CK_SESSION_HANDLE     hSession,
                                       CK_OBJECT_HANDLE      hKey,
                                       CK_OBJECT_HANDLE      hKeyNew);
    void encryptDecrypt_BlockSizeCBCPADAfterWrapUnwrap(CK_MECHANISM_TYPE     mechanismType,
                                                       CK_SESSION_HANDLE     hSession,
                                                       CK_OBJECT_HANDLE      hKey,
                                                       CK_OBJECT_HANDLE      hKeyNew);
    void encryptDecrypt_NonBlockSizeCBCPADAfterWrapUnwrap(CK_MECHANISM_TYPE     mechanismType,
                                                          CK_SESSION_HANDLE     hSession,
                                                          CK_OBJECT_HANDLE      hKey,
                                                          CK_OBJECT_HANDLE      hKeyNew);
#ifdef SGXHSM
    CK_RV generateAesKeyTokenObject(CK_SESSION_HANDLE hSession,
                                    CK_BBOOL bToken,
                                    CK_BBOOL bPrivate,
                                    CK_OBJECT_HANDLE &hKey);
    void aesWrapUnwrapTokenObject(CK_MECHANISM_TYPE mechanismType);
    void aesWrapUnwrapInSameSession(CK_MECHANISM_TYPE mechanismType,
                                    CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE  hKey,
                                    CK_OBJECT_HANDLE  hKeyData);
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
	void aesWrapUnwrapGost(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
	CK_RV generateGostPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey);
#endif
#endif // Unsupported by Crypto API Toolkit
};

#endif // !_SOFTHSM_V2_SYMENCRYPTDECRYPTTESTS_H
