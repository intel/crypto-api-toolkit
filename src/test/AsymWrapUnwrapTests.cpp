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
 AsymWrapUnwrapTests.cpp

 Contains test cases for C_WrapKey and C_UnwrapKey
 using asymmetrical algorithms (RSA)
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "AsymWrapUnwrapTests.h"
#ifdef DCAP_SUPPORT
#include "QuoteGeneration.h"
#endif
// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(AsymWrapUnwrapTests);

// Generate throw-away (session) symmetric key
CK_RV AsymWrapUnwrapTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bTrue) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV AsymWrapUnwrapTests::generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 2048;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
    return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
                                             pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
                                             prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
                                             &hPuk, &hPrk) );
}

void AsymWrapUnwrapTests::rsaWrapUnwrap(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_BYTE cipherText[2048];
	CK_ULONG ulCipherTextLen;
	CK_BYTE symValue[64];
	CK_ULONG ulSymValueLen = sizeof(symValue);
	CK_BYTE unwrappedValue[64];
	CK_ULONG ulUnwrappedValueLen = sizeof(unwrappedValue);
	CK_OBJECT_HANDLE symKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE unwrappedKey = CK_INVALID_HANDLE;
	CK_RV rv;
	CK_ULONG wrappedLenEstimation;

	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE unwrapTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_ATTRIBUTE valueTemplate[] = {
		{ CKA_VALUE, &symValue, ulSymValueLen }
	};

	CK_MECHANISM_INFO mechInfo;

	if (mechanismType == CKM_RSA_PKCS_OAEP)
	{
		mechanism.pParameter = &oaepParams;
		mechanism.ulParameterLen = sizeof(oaepParams);
	}

	// Generate temporary symmetric key and remember it's value
	rv = generateAesKey(hSession, symKey);
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, symKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE)) );
#ifdef SGXHSM
    CPPUNIT_ASSERT(rv==CKR_ATTRIBUTE_TYPE_INVALID);
#else
    CPPUNIT_ASSERT(rv==CKR_OK);
    ulSymValueLen = valueTemplate[0].ulValueLen;
#endif

	// CKM_RSA_PKCS Wrap/Unwrap support
	rv = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, CKM_RSA_PKCS, &mechInfo) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_WRAP);
	CPPUNIT_ASSERT(mechInfo.flags&CKF_UNWRAP);

    rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, NULL_PTR, hPublicKey, symKey, NULL_PTR, &wrappedLenEstimation) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD==rv);

	// Estimate wrapped length
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, NULL_PTR, &wrappedLenEstimation) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	CPPUNIT_ASSERT(wrappedLenEstimation>0);

	// This should always fail because wrapped data have to be longer than 0 bytes
	ulCipherTextLen = 0;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_BUFFER_TOO_SMALL);

	// Do real wrapping
	ulCipherTextLen = sizeof(cipherText);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);
	// Check length 'estimation'
	CPPUNIT_ASSERT(wrappedLenEstimation>=ulCipherTextLen);

	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hPrivateKey, cipherText, ulCipherTextLen, unwrapTemplate, sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE), &unwrappedKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

#ifdef SGXHSM
    //Encryption with the key used for wrappping
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, &mechanism, hPublicKey) );
    CPPUNIT_ASSERT(rv==CKR_OBJECT_HANDLE_INVALID);

    //Decryption with the key used for wrapping
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, &mechanism, hPrivateKey) );
    CPPUNIT_ASSERT(rv==CKR_OBJECT_HANDLE_INVALID);
#endif

	valueTemplate[0].pValue = &unwrappedValue;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, unwrappedKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE)) );
#ifdef SGXHSM
    CPPUNIT_ASSERT(rv==CKR_ATTRIBUTE_TYPE_INVALID);
#else
    CPPUNIT_ASSERT(rv==CKR_OK);
    ulUnwrappedValueLen = valueTemplate[0].ulValueLen;

    CPPUNIT_ASSERT(ulSymValueLen == ulUnwrappedValueLen);
    CPPUNIT_ASSERT(memcmp(symValue, unwrappedValue, ulSymValueLen) == 0);
#endif

}

void AsymWrapUnwrapTests::testRsaWrapUnwrap()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token public/private key pairs.
	rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPublicKey,hPrivateKey);
    CPPUNIT_ASSERT(rv == CKR_OK);

	rsaWrapUnwrap(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
    hPublicKey = CK_INVALID_HANDLE;
    hPrivateKey = CK_INVALID_HANDLE;

    rv = generateRsaKeyPair(hSessionRW,IN_SESSION,IS_PUBLIC,IN_SESSION,IS_PUBLIC,hPublicKey,hPrivateKey);
    CPPUNIT_ASSERT(rv == CKR_OK);
	rsaWrapUnwrap(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
}

#ifdef DCAP_SUPPORT
bool AsymWrapUnwrapTests::customQuoteEcdsa(const CK_MECHANISM_TYPE& mechanismType,
                                           const CK_SESSION_HANDLE& hSession,
                                           const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV                   rv                 = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism          = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                quotePublicKeyLen  = 0UL;
    CK_LONG                 qlPolicy           = SGX_QL_PERSISTENT;
    bool                    result             = false;
    std::vector<CK_BYTE>    quotePublicKey;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteParams =
    {
        qlPolicy
    };

    do
    {
        pMechanism->pParameter = &quoteParams;
        pMechanism->ulParameterLen = sizeof(quoteParams);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pMechanism,
                                      NULL_PTR,
                                      hKey,
                                      NULL_PTR,
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_OK == rv);

        quotePublicKey.resize(quotePublicKeyLen);
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pMechanism,
                                      NULL_PTR,
                                      hKey,
                                      quotePublicKey.data(),
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_OK == rv);

        CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParams = reinterpret_cast<CK_RSA_PUBLIC_KEY_PARAMS*>(quotePublicKey.data());
        uint32_t pubKeySize = rsaPublicKeyParams->ulModulusLen + rsaPublicKeyParams->ulExponentLen;
        uint32_t fullPublicKeySize = sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + rsaPublicKeyParams->ulModulusLen + rsaPublicKeyParams->ulExponentLen;

        sgx_quote_t* sgxQuote  = reinterpret_cast<sgx_quote_t*>(quotePublicKey.data() + fullPublicKeySize);
        uint32_t     quoteSize = quotePublicKeyLen - fullPublicKeySize;

        std::vector<CK_BYTE> quote;
        quote.resize(quoteSize);

        memcpy(&quote[0], sgxQuote, quoteSize);

        // Extract the public key and verify its hash
        const uint32_t HASH_LENGTH = 32;
        std::vector<CK_BYTE> publicKeyHashInQuote(HASH_LENGTH, 0);
        std::vector<CK_BYTE> publicKeyData(pubKeySize, 0);

        // Fill the hash vector
        memcpy(publicKeyHashInQuote.data(),
               sgxQuote->report_body.report_data.d,
               HASH_LENGTH);

        // Fill the data vector
        memcpy(publicKeyData.data(),
               quotePublicKey.data() + sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
               pubKeySize);

        // Compute hash of publicKeyData..
        std::vector<CK_BYTE> hashedData;

        computeSHA256Hash(hSession, publicKeyData, hashedData);

        CPPUNIT_ASSERT (publicKeyHashInQuote == hashedData);

        result = true;
    } while (false);

    return result;
}

bool AsymWrapUnwrapTests::customQuoteEcdsaTokenObject(const CK_MECHANISM_TYPE& mechanismType,
                                                      const CK_SESSION_HANDLE& hSession,
                                                      const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV                   rv                 = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism          = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                quotePublicKeyLen  = 0UL;
    CK_LONG                 qlPolicy           = SGX_QL_PERSISTENT;
    bool                    result             = false;
    std::vector<CK_BYTE>    quotePublicKey;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteParams =
    {
        qlPolicy
    };

    do
    {
        pMechanism->pParameter = &quoteParams;
        pMechanism->ulParameterLen = sizeof(quoteParams);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pMechanism,
                                      NULL_PTR,
                                      hKey,
                                      NULL_PTR,
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_KEY_FUNCTION_NOT_PERMITTED == rv);

        result = true;
    } while (false);

    return result;
}

bool AsymWrapUnwrapTests::customQuoteEcdsaSingleUse(const CK_MECHANISM_TYPE& quoteMechanismType,
                                                    const CK_SESSION_HANDLE& hSession,
                                                    const CK_OBJECT_HANDLE&  hPublicKey,
                                                    const CK_OBJECT_HANDLE&  hPrivateKey)
{
    CK_RV                   rv                 = CKR_GENERAL_ERROR;
    CK_MECHANISM            quoteMechanism     = { quoteMechanismType, NULL_PTR, 0 };
    CK_ULONG                quotePublicKeyLen  = 0UL;
    CK_LONG                 qlPolicy           = SGX_QL_PERSISTENT;
    bool                    result             = false;
    CK_OBJECT_HANDLE        symKey             = CK_INVALID_HANDLE;
    CK_ULONG                wrappedLen         = 0UL;
    CK_OBJECT_HANDLE        unwrappedKey       = CK_INVALID_HANDLE;
    CK_BBOOL                bFalse             = CK_FALSE;
    CK_BBOOL                bTrue              = CK_TRUE;
    CK_OBJECT_CLASS         keyClass           = CKO_SECRET_KEY;
    CK_KEY_TYPE             keyType            = CKK_AES;
    std::vector<CK_BYTE>    quotePublicKey;
    CK_MECHANISM_PTR        pQuoteMechanism((CK_MECHANISM_PTR)&quoteMechanism);
    std::vector<CK_BYTE>    wrappedData;

    CK_ATTRIBUTE unwrapTemplate[] = { { CKA_CLASS,       &keyClass, sizeof(keyClass) },
                                      { CKA_KEY_TYPE,    &keyType,  sizeof(keyType)  },
                                      { CKA_TOKEN,       &bFalse,   sizeof(bFalse)   },
                                      { CKA_SENSITIVE,   &bFalse,   sizeof(bFalse)   },
                                      { CKA_EXTRACTABLE, &bTrue,    sizeof(bTrue)    }
                                    };

    CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteParams =
    {
        qlPolicy
    };

    do
    {
        CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS;
        CK_MECHANISM      mechanism     = { mechanismType, NULL_PTR, 0 };

        // Generate temporary symmetric key and remember it's value
        rv = generateAesKey(hSession, symKey);
        CPPUNIT_ASSERT(CKR_OK == rv);

        // Wrapping before generating quote using this key
        // This will not stop the key from being used for quote generation
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hPublicKey,
                                      symKey,
                                      NULL_PTR,
                                      &wrappedLen));

        CPPUNIT_ASSERT(CKR_OK == rv);
        wrappedData.resize(wrappedLen);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hPublicKey,
                                      symKey,
                                      wrappedData.data(),
                                      &wrappedLen));
        CPPUNIT_ASSERT(CKR_OK == rv);

        // Generate quote
        pQuoteMechanism->pParameter = &quoteParams;
        pQuoteMechanism->ulParameterLen = sizeof(quoteParams);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pQuoteMechanism,
                                      NULL_PTR,
                                      hPublicKey,
                                      NULL_PTR,
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_OK == rv);

        quotePublicKey.resize(quotePublicKeyLen);
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pQuoteMechanism,
                                      NULL_PTR,
                                      hPublicKey,
                                      quotePublicKey.data(),
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_OK == rv);

        // Encryption should fail
        rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession,
                                          &mechanism,
                                          hPublicKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // Decryption should fail
        rv = CRYPTOKI_F_PTR(C_DecryptInit(hSession,
                                          &mechanism,
                                          hPrivateKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // Wrapping should fail
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hPublicKey,
                                      symKey,
                                      NULL_PTR,
                                      &wrappedLen));
        CPPUNIT_ASSERT (CKR_WRAPPING_KEY_HANDLE_INVALID == rv);

        // Quote generation should fail
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pQuoteMechanism,
                                      NULL_PTR,
                                      hPublicKey,
                                      NULL_PTR,
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_KEY_HANDLE_INVALID == rv);

        // Signing should fail
        rv = CRYPTOKI_F_PTR(C_SignInit(hSession,
                                       &mechanism,
                                       hPrivateKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // Verifying should fail
        rv = CRYPTOKI_F_PTR(C_VerifyInit(hSession,
                                         &mechanism,
                                         hPublicKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // 1 st unwrap operation allowed
        rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession,
                                         &mechanism,
                                         hPrivateKey,
                                         wrappedData.data(),
                                         wrappedLen,
                                         unwrapTemplate,
                                         sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE),
                                         &unwrappedKey) );
        CPPUNIT_ASSERT(CKR_OK == rv);

        unwrappedKey = CK_INVALID_HANDLE;
        rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession,
                                         &mechanism,
                                         hPrivateKey,
                                         wrappedData.data(),
                                         wrappedLen,
                                         unwrapTemplate,
                                         sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE),
                                         &unwrappedKey) );
#ifdef EPHEMERAL_QUOTE
        // 2 nd unwrap operation should fail as key is destroyed
        CPPUNIT_ASSERT(CKR_UNWRAPPING_KEY_HANDLE_INVALID == rv);
#else
        // 2 nd unwrap operation should pass as key is not destroyed
        CPPUNIT_ASSERT(CKR_OK == rv);
#endif

        // As key is deleted
        // Encryption should fail
        rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession,
                                          &mechanism,
                                          hPublicKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // Decryption should fail
        rv = CRYPTOKI_F_PTR(C_DecryptInit(hSession,
                                          &mechanism,
                                          hPrivateKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // Wrapping should fail
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hPublicKey,
                                      symKey,
                                      NULL_PTR,
                                      &wrappedLen));
        CPPUNIT_ASSERT (CKR_WRAPPING_KEY_HANDLE_INVALID == rv);

        // Quote generation should fail
        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      pQuoteMechanism,
                                      NULL_PTR,
                                      hPublicKey,
                                      NULL_PTR,
                                      &quotePublicKeyLen));
        CPPUNIT_ASSERT (CKR_KEY_HANDLE_INVALID == rv);

        // Signing should fail
        rv = CRYPTOKI_F_PTR(C_SignInit(hSession,
                                       &mechanism,
                                       hPrivateKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        // Verifying should fail
        rv = CRYPTOKI_F_PTR(C_VerifyInit(hSession,
                                         &mechanism,
                                         hPublicKey));
        CPPUNIT_ASSERT (CKR_OBJECT_HANDLE_INVALID == rv);

        result = true;
    } while (false);

    return result;
}

void AsymWrapUnwrapTests::testQuoteGeneration()
{
    CK_MECHANISM_TYPE mechanismType	= CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY;

    CK_RV             rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR(C_Finalize(NULL_PTR));

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR(C_Initialize(NULL_PTR));
    CPPUNIT_ASSERT(rv == CKR_OK);

    // Open session
    rv = CRYPTOKI_F_PTR(C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession));
    CPPUNIT_ASSERT(rv == CKR_OK);

    // Login USER into the session so we can create a private object
    rv = CRYPTOKI_F_PTR(C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length));
    CPPUNIT_ASSERT(rv == CKR_OK);

    CK_KEY_TYPE     rsaKeyType           = CKK_RSA;
    CK_OBJECT_CLASS rsaPublicKeyClass    = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS rsaPrivateKeyClass   = CKO_PRIVATE_KEY;
    CK_UTF8CHAR     rsaPublicKeyLabel[]  = "RSA Public Key Label";
    CK_UTF8CHAR     rsaPrivateKeyLabel[] = "RSA Private Key Label";
    CK_UTF8CHAR     id[] = "1";
    CK_BBOOL        bTrue = CK_TRUE;
    CK_BBOOL        bFalse = CK_FALSE;

    CK_ULONG modulusBits = 2048;

    CK_ATTRIBUTE asymKeyAttribs[] = {{ CKA_TOKEN,           &bFalse,            sizeof(bFalse) },
                                     { CKA_ENCRYPT,         &bTrue,             sizeof(bTrue) },
                                     { CKA_VERIFY,          &bTrue,             sizeof(bTrue) },
                                     { CKA_WRAP,            &bTrue,             sizeof(bTrue) },
                                     { CKA_MODULUS_BITS,    &modulusBits,       sizeof(modulusBits) },
                                     { CKA_KEY_TYPE,        &rsaKeyType,        sizeof(rsaKeyType)   },
                                     { CKA_CLASS,           &rsaPublicKeyClass, sizeof(rsaPublicKeyClass)  },
                                     { CKA_LABEL,           rsaPublicKeyLabel,  sizeof(rsaPublicKeyLabel)-1 },
                                     { CKA_ID,              &id[0],             sizeof(id) },
                                     };

    CK_ATTRIBUTE asymPrivateKeyAttribs[] = {{ CKA_TOKEN,       &bFalse,             sizeof(bFalse) },
                                            { CKA_DECRYPT,     &bTrue,              sizeof(bTrue) },
                                            { CKA_SIGN,        &bTrue,              sizeof(bTrue) },
                                            { CKA_UNWRAP,      &bTrue,              sizeof(bTrue) },
                                            { CKA_KEY_TYPE,    &rsaKeyType,         sizeof(rsaKeyType)   },
                                            { CKA_CLASS,       &rsaPrivateKeyClass, sizeof(rsaPrivateKeyClass)  },
                                            { CKA_LABEL,       rsaPrivateKeyLabel,  sizeof(rsaPrivateKeyLabel)-1 },
                                            { CKA_ID,          &id[0],              sizeof(id) },
                                            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
                                            };
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE        hAsymKey            = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE        hAsymPrivateKey     = CK_INVALID_HANDLE;

    rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession,
                                          &mechanism,
                                          asymKeyAttribs,
                                          sizeof(asymKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                          asymPrivateKeyAttribs,
                                          sizeof(asymPrivateKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                          &hAsymKey,
                                          &hAsymPrivateKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    bool result = customQuoteEcdsa(mechanismType, hSession, hAsymKey);
    CPPUNIT_ASSERT(result == true);
    rv = C_DestroyObject(hSession, hAsymKey);
    CPPUNIT_ASSERT(CKR_OK == rv);
    rv = C_DestroyObject(hSession, hAsymPrivateKey);
    CPPUNIT_ASSERT(CKR_OK == rv);

    hAsymKey            = CK_INVALID_HANDLE;
    hAsymPrivateKey     = CK_INVALID_HANDLE;

    rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession,
                                          &mechanism,
                                          asymKeyAttribs,
                                          sizeof(asymKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                          asymPrivateKeyAttribs,
                                          sizeof(asymPrivateKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                          &hAsymKey,
                                          &hAsymPrivateKey));

    // The key used for quote generation for single use
    result = customQuoteEcdsaSingleUse(mechanismType, hSession, hAsymKey, hAsymPrivateKey);
    CPPUNIT_ASSERT(true == result);
    rv = C_DestroyObject(hSession, hAsymKey);
    CPPUNIT_ASSERT(CKR_OK == rv);
    rv = C_DestroyObject(hSession, hAsymPrivateKey);
    CPPUNIT_ASSERT(CKR_OK == rv);

    // The key used for quote generation has to be a session key
    asymKeyAttribs[0].pValue = &bTrue;
    asymPrivateKeyAttribs[0].pValue = &bTrue;

    rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession,
                                          &mechanism,
                                          asymKeyAttribs,
                                          sizeof(asymKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                          asymPrivateKeyAttribs,
                                          sizeof(asymPrivateKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                          &hAsymKey,
                                          &hAsymPrivateKey));
    CPPUNIT_ASSERT(CKR_OK == rv);

    result = customQuoteEcdsaTokenObject(mechanismType, hSession, hAsymKey);
    CPPUNIT_ASSERT(true == result);
    rv = C_DestroyObject(hSession, hAsymKey);
    CPPUNIT_ASSERT(CKR_OK == rv);
    rv = C_DestroyObject(hSession, hAsymPrivateKey);
    CPPUNIT_ASSERT(CKR_OK == rv);
}

bool AsymWrapUnwrapTests::computeSHA256Hash(const CK_SESSION_HANDLE& hSession,
                                            std::vector<CK_BYTE>&    data,
                                            std::vector<CK_BYTE>&    hashedData)
{
    CK_RV               rv             = CKR_GENERAL_ERROR;
    CK_MECHANISM        mechanism      = { CKM_SHA256, NULL_PTR, 0 };
    bool                result         = false;
    CK_MECHANISM_PTR    pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        rv = CRYPTOKI_F_PTR(C_DigestInit(hSession, pMechanism));
        CPPUNIT_ASSERT (CKR_OK == rv);

        rv =  CRYPTOKI_F_PTR(C_DigestUpdate(hSession, data.data(), data.size()));
        CPPUNIT_ASSERT (CKR_OK == rv);

        CK_ULONG hashedDataSize = 0;
        rv =  CRYPTOKI_F_PTR(C_DigestFinal(hSession, NULL_PTR, &hashedDataSize));
        CPPUNIT_ASSERT (CKR_OK == rv);

        hashedData.resize(hashedDataSize);
        rv =  CRYPTOKI_F_PTR(C_DigestFinal(hSession, hashedData.data(), &hashedDataSize));
        CPPUNIT_ASSERT (CKR_OK == rv);

        result = true;
    } while (false);

    return result;
}
#endif

#ifdef SGXHSM
CK_RV AsymWrapUnwrapTests::generateRsaKeyPairTokenObject(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ULONG bits = 2048;
    CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
    CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
    CK_BYTE id[] = { 123 } ; // dummy
    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_UTF8CHAR rsaPblicKeyLabel[] = "RSA Public key unWrapped with AES Key";
    CK_UTF8CHAR rsaPrivateKeyLabel[] = "RSA Private key unWrapped with AES Key";
    CK_ATTRIBUTE pukAttribs[] = { { CKA_TOKEN,           &bTokenPuk,       sizeof(bTokenPuk)          },
                                  { CKA_PRIVATE,         &bPrivatePuk,     sizeof(bPrivatePuk)        },
                                  { CKA_ENCRYPT,         &bTrue,           sizeof(bTrue)              },
                                  { CKA_VERIFY,          &bFalse,          sizeof(bFalse)             },
                                  { CKA_WRAP,            &bTrue,           sizeof(bTrue)              },
                                  { CKA_MODULUS_BITS,    &bits,            sizeof(bits)               },
                                  { CKA_PUBLIC_EXPONENT, &pubExp[0],       sizeof(pubExp)             },
                                  { CKA_LABEL,           rsaPblicKeyLabel, sizeof(rsaPblicKeyLabel)-1 },
                                };
    CK_ATTRIBUTE prkAttribs[] = { { CKA_TOKEN,     &bTokenPrk,         sizeof(bTokenPrk)            },
                                  { CKA_PRIVATE,   &bPrivatePrk,       sizeof(bPrivatePrk)          },
                                  { CKA_SUBJECT,   &subject[0],        sizeof(subject)              },
                                  { CKA_ID,        &id[0],             sizeof(id)                   },
                                  { CKA_SENSITIVE, &bTrue,             sizeof(bTrue)                },
                                  { CKA_DECRYPT,   &bTrue,             sizeof(bTrue)                },
                                  { CKA_SIGN,      &bFalse,            sizeof(bFalse)               },
                                  { CKA_UNWRAP,    &bTrue,             sizeof(bTrue)                },
                                  { CKA_LABEL,     rsaPrivateKeyLabel, sizeof(rsaPrivateKeyLabel)-1 },
                                };

    hPuk = CK_INVALID_HANDLE;
    hPrk = CK_INVALID_HANDLE;
    return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
                                             pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
                                             prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
                                             &hPuk, &hPrk) );
}

void AsymWrapUnwrapTests::testRsaWrapUnwrapTokenObject()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSessionRW;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // Open read-write session
    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // Login USER into the sessions so we can create a private objects
    rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

    // Generate all combinations of session/token public/private key pairs.
    rv = generateRsaKeyPairTokenObject(hSessionRW,ON_TOKEN,IS_PUBLIC,ON_TOKEN,IS_PUBLIC,hPublicKey,hPrivateKey);
    CPPUNIT_ASSERT(rv==CKR_OK);

    rsaWrapUnwrapTokenObject(CKM_RSA_PKCS,hSessionRW,hPublicKey,hPrivateKey);


    rv = CRYPTOKI_F_PTR( C_Logout(hSessionRW) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    //Close Session
    rv = CRYPTOKI_F_PTR( C_CloseSession(hSessionRW));
    CPPUNIT_ASSERT(rv==CKR_OK);

    //Testing with token opbject in a new session
    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // Open read-write session
    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // Login USER into the sessions so we can create a private objects
    rv = CRYPTOKI_F_PTR( C_Login(hSessionRW, CKU_USER, m_userPin1, m_userPin1Length) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    CK_UTF8CHAR rsaPublicKeyLabel[] = "RSA Public key unWrapped with AES Key";
    CK_ATTRIBUTE publicKeyTemplate[] = { { CKA_LABEL, rsaPublicKeyLabel, sizeof(rsaPublicKeyLabel)-1 },
                                       };

    CK_UTF8CHAR rsaPrivateKeyLabel[] = "RSA Private key unWrapped with AES Key";
    CK_ATTRIBUTE privateKeyTemplate[] = { { CKA_LABEL, rsaPrivateKeyLabel, sizeof(rsaPrivateKeyLabel)-1 },
                                        };

    rv = C_FindObjectsInit(hSessionRW, &publicKeyTemplate[0], 1);
    CPPUNIT_ASSERT(rv==CKR_OK);

    CK_OBJECT_HANDLE hPublicKeyFromToken = CK_INVALID_HANDLE;
    CK_ULONG ulObjectCount = 0;

    rv = C_FindObjects(hSessionRW, &hPublicKeyFromToken, 1, &ulObjectCount);
    CPPUNIT_ASSERT(rv==CKR_OK);

    CPPUNIT_ASSERT(ulObjectCount == 1);

    rv = C_FindObjectsFinal(hSessionRW);
    CPPUNIT_ASSERT(rv==CKR_OK);

    rv = C_FindObjectsInit(hSessionRW, &privateKeyTemplate[0], 1);
    CPPUNIT_ASSERT(rv==CKR_OK);

    CK_OBJECT_HANDLE hPrivateKeyFromToken = CK_INVALID_HANDLE;
    ulObjectCount = 0;

    rv = C_FindObjects(hSessionRW, &hPrivateKeyFromToken, 1, &ulObjectCount);
    CPPUNIT_ASSERT(rv==CKR_OK);

    CPPUNIT_ASSERT(ulObjectCount == 1);

    rv = C_FindObjectsFinal(hSessionRW);
    CPPUNIT_ASSERT(rv==CKR_OK);

    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    //Encryption with the key used for wrappping
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSessionRW, &mechanism, hPublicKeyFromToken) );
    CPPUNIT_ASSERT(rv==CKR_OBJECT_HANDLE_INVALID);

    //Decryption with the key used for wrapping
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSessionRW, &mechanism, hPrivateKeyFromToken) );
    CPPUNIT_ASSERT(rv==CKR_OBJECT_HANDLE_INVALID);
    
    C_DestroyObject(hSessionRW, hPublicKeyFromToken);
    C_DestroyObject(hSessionRW, hPrivateKeyFromToken);

    C_CloseSession(hSessionRW);
}

void AsymWrapUnwrapTests::rsaWrapUnwrapTokenObject(CK_MECHANISM_TYPE mechanismType,
                                                   CK_SESSION_HANDLE hSession,
                                                   CK_OBJECT_HANDLE hPublicKey,
                                                   CK_OBJECT_HANDLE hPrivateKey)
{
    CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen;
    CK_BYTE symValue[64];
    CK_OBJECT_HANDLE symKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrappedKey = CK_INVALID_HANDLE;
    CK_RV rv;
    CK_ULONG wrappedLenEstimation;

    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ATTRIBUTE unwrapTemplate[] = { { CKA_CLASS,      &keyClass, sizeof(keyClass) },
                                      { CKA_KEY_TYPE,    &keyType, sizeof(keyType)  },
                                      { CKA_TOKEN,       &bFalse,  sizeof(bFalse)   },
                                      { CKA_SENSITIVE,   &bFalse,  sizeof(bFalse)   },
                                      { CKA_EXTRACTABLE, &bTrue,   sizeof(bTrue)    }
                                    };

    CK_MECHANISM_INFO mechInfo;

    CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };

    if (mechanismType == CKM_RSA_PKCS_OAEP)
    {
        mechanism.pParameter = &oaepParams;
        mechanism.ulParameterLen = sizeof(oaepParams);
    }

    // Generate temporary symmetric key and remember it's value
    rv = generateAesKey(hSession, symKey);
    CPPUNIT_ASSERT(rv==CKR_OK);

    //Encryption
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, &mechanism, hPublicKey) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    ulCipherTextLen = sizeof(cipherText);
    rv =CRYPTOKI_F_PTR( C_Encrypt(hSession, plainText, sizeof(plainText), cipherText, &ulCipherTextLen) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // CKM_RSA_PKCS Wrap/Unwrap support
    rv = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, CKM_RSA_PKCS, &mechInfo) );
    CPPUNIT_ASSERT(rv==CKR_OK);
    CPPUNIT_ASSERT(mechInfo.flags&CKF_WRAP);
    CPPUNIT_ASSERT(mechInfo.flags&CKF_UNWRAP);

    // Estimate wrapped length
    rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, NULL_PTR, &wrappedLenEstimation) );
    CPPUNIT_ASSERT(rv==CKR_OK);
    CPPUNIT_ASSERT(wrappedLenEstimation>0);

    // Do real wrapping
    ulCipherTextLen = sizeof(cipherText);
    rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    // Check length 'estimation'
    CPPUNIT_ASSERT(wrappedLenEstimation>=ulCipherTextLen);

    rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hPrivateKey, cipherText, ulCipherTextLen, unwrapTemplate, sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE), &unwrappedKey) );
    CPPUNIT_ASSERT(rv==CKR_OK);

    //Encryption with public key used for wrappping
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, &mechanism, hPublicKey) );
    CPPUNIT_ASSERT(rv==CKR_OBJECT_HANDLE_INVALID);

    //Decryption with private key
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, &mechanism, hPrivateKey) );
    CPPUNIT_ASSERT(rv==CKR_OBJECT_HANDLE_INVALID);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSession, symKey));
    CPPUNIT_ASSERT(rv==CKR_OK);
}
#endif
