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
 AsymEncryptDecryptTests.cpp

 Contains test cases for C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt
 using asymmetrical algorithms (i.e., RSA)
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "AsymEncryptDecryptTests.h"

#ifdef AES_UNWRAP_RSA
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#endif

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;


CPPUNIT_TEST_SUITE_REGISTRATION(AsymEncryptDecryptTests);

#ifdef AES_UNWRAP_RSA
bool writeData(const std::string& fileName, const std::stringstream& data)
{
    std::ofstream fileHandle(fileName, std::ios::binary);

    if (!fileHandle.is_open())
    {
        return false;
    }

    fileHandle << data.rdbuf();
    fileHandle.close();

    return true;
}

std::vector<CK_BYTE> getSampleEncryptedData(const CK_MECHANISM_TYPE& mechanismType,
                                            const CK_SESSION_HANDLE& hSession,
                                            const CK_OBJECT_HANDLE&  hKey,
                                            unsigned char *          sourceBuffer,
                                            const int&               sourceBufferSize)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    CK_RV                   rv                  = CKR_GENERAL_ERROR;
    CK_ULONG                bytesDone           = 0;
    CK_ULONG                encryptedBytes      = 0;
    uint32_t                tagBits             = 0;
    uint32_t                tagBytes            = 0;
    bool                    result              = false;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    destBuffer(sourceBufferSize);

    if (CKM_AES_GCM == mechanismType)
    {
        tagBytes = 16;
        tagBits  = tagBytes * 8;
    }

    CK_AES_CTR_PARAMS   ctrParams =
    {
        128,
        {
            0x01, 0x02, 0x03, 0x30, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        }
    };

    CK_BYTE gcmIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    };
    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };
    CK_BYTE gcmAAD[] = {
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2
    };
    CK_GCM_PARAMS gcmParams =
    {
        &gcmIV[0],
        sizeof(gcmIV),
        sizeof(gcmIV) * 8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        tagBits
    };

    do
    {
        switch (mechanismType)
        {
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
                pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;
            case CKM_AES_CTR:
                pMechanism->pParameter = &ctrParams;
                pMechanism->ulParameterLen = sizeof(ctrParams);
                break;
            case CKM_AES_GCM:
                pMechanism->pParameter = &gcmParams;
                pMechanism->ulParameterLen = sizeof(gcmParams);
                break;
            default:
                break;
        }

        rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, pMechanism, hKey));
        if (CKR_OK != rv)
        {
            destBuffer.clear();
            break;
        }

        rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,
                                             sourceBuffer,
                                             sourceBufferSize, NULL_PTR, &bytesDone));
        if (CKR_OK != rv)
        {
            destBuffer.clear();
            break;
        }
        destBuffer.resize(bytesDone);

        rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,
                                             sourceBuffer,
                                             sourceBufferSize, destBuffer.data(), &bytesDone));
        if (CKR_OK != rv)
        {
            destBuffer.clear();
            break;
        }
        bytesDone = 0;

        rv = CRYPTOKI_F_PTR( C_EncryptFinal(hSession, NULL_PTR, &bytesDone));
        if (CKR_OK != rv)
        {
            destBuffer.clear();
            break;
        }

        encryptedBytes = destBuffer.size();
        destBuffer.resize(destBuffer.size() + bytesDone);

        rv = CRYPTOKI_F_PTR( C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone));
        if (CKR_OK != rv)
        {
            destBuffer.clear();
            break;
        }
        destBuffer.resize(encryptedBytes + bytesDone);

    } while(false);

    return destBuffer;
}

CK_RV AsymEncryptDecryptTests::rsaWrapUnwrapWithAes(const CK_SESSION_HANDLE& hSession)
{
    CK_MECHANISM mechanismRsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ULONG     bits         = 2048;
    CK_BYTE      pubExp[]     = {0x01, 0x00, 0x01};
    CK_BYTE      subject[]    = { 0x12, 0x34 };
    CK_BYTE      idRsa[]      = { 123 };
    CK_BBOOL     bFalse       = CK_FALSE;
    CK_BBOOL     bTrue        = CK_TRUE;

    CK_ATTRIBUTE pukAttribs[] = {
                                    { CKA_TOKEN,           &bFalse,    sizeof(bFalse) },
                                    { CKA_PRIVATE,         &bFalse,    sizeof(bFalse) },
                                    { CKA_ENCRYPT,         &bTrue,     sizeof(bTrue) },
                                    { CKA_VERIFY,          &bTrue,     sizeof(bTrue) },
                                    { CKA_WRAP,            &bTrue,     sizeof(bTrue) },
                                    { CKA_MODULUS_BITS,    &bits,      sizeof(bits) },
                                    { CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
                                };

    CK_ATTRIBUTE prkAttribs[] = {
                                    { CKA_TOKEN,     &bFalse,     sizeof(bFalse) },
                                    { CKA_PRIVATE,   &bFalse,     sizeof(bFalse) },
                                    { CKA_SUBJECT,   &subject[0], sizeof(subject) },
                                    { CKA_ID,        &idRsa[0],   sizeof(idRsa) },
                                    { CKA_SENSITIVE, &bTrue,      sizeof(bTrue) },
                                    { CKA_DECRYPT,   &bTrue,      sizeof(bTrue) },
                                    { CKA_SIGN,      &bTrue,      sizeof(bTrue) },
                                    { CKA_UNWRAP,    &bTrue,      sizeof(bTrue) }
    };

    CK_RV            rv          = CKR_FUNCTION_FAILED;
    CK_OBJECT_HANDLE hPublicKey  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

    rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanismRsa,
                                           pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
                                           prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
                                           &hPublicKey, &hPrivateKey) );
    if (CKR_OK != rv)
    {
        std::cout << "C_GenerateKeyPair Failed" << std::endl;
        return rv;
    }

    CK_MECHANISM_TYPE  mechanismType = CKM_AES_CTR;
    const CK_MECHANISM mechanism     = { mechanismType, NULL_PTR, 0 };
    CK_ULONG           bytesDone     = 0;
    CK_MECHANISM_PTR   pMechanism((CK_MECHANISM_PTR)&mechanism);

    CK_AES_CTR_PARAMS ctrParams =
    {
        128,
        {
            0x01, 0x02, 0x03, 0x30, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        }
    };

    pMechanism->pParameter = &ctrParams;
    pMechanism->ulParameterLen = sizeof(ctrParams);

    CK_OBJECT_HANDLE    hKey            = CK_INVALID_HANDLE;
    CK_MECHANISM        mechanismAES    = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_KEY_TYPE         aesKeyType      = CKK_AES;
    CK_OBJECT_CLASS     aesKeyClass     = CKO_SECRET_KEY;
    CK_ULONG            keyLength       = 16;
    CK_UTF8CHAR         aesKeyLabel[]   = "AES Key Label";
    CK_UTF8CHAR         aesKeyId[]      = "AES Key ID";

    CK_ATTRIBUTE        keyAttribs[]    = {{ CKA_ENCRYPT,       &bTrue,       sizeof(bTrue)     },
                                           { CKA_DECRYPT,       &bTrue,       sizeof(bTrue)     },
                                           { CKA_WRAP,          &bTrue,       sizeof(bTrue)     },
                                           { CKA_UNWRAP,        &bTrue,       sizeof(bTrue)     },
                                           { CKA_VALUE_LEN,     &keyLength,   sizeof(keyLength) },
                                           { CKA_KEY_TYPE,      &aesKeyType,  sizeof(aesKeyType)   },
                                           { CKA_CLASS,         &aesKeyClass, sizeof(aesKeyClass)  },
                                           { CKA_LABEL,         aesKeyLabel,  sizeof(aesKeyLabel)-1 },
                                           { CKA_ID,            aesKeyId,     sizeof(aesKeyId)-1 }
                                           };

    rv = CRYPTOKI_F_PTR(C_GenerateKey(hSession,
                                       &mechanismAES,
                                       keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                       &hKey));
    if (CKR_OK != rv)
    {
        std::cout << "C_GenerateKey Failed" << std::endl;
        return rv;
    }

    ERR_load_BIO_strings();
    unsigned long  e = RSA_F4;

    BIGNUM* bne = BN_new();
    if (BN_set_word(bne,e) != 1)
    {
        std::cout << "BN_set_word Failed" << std::endl;
        return rv;
    }

    RSA* rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, 2048, bne, NULL) != 1)
    {
        std::cout << "RSA_generate_key_ex Failed" << std::endl;
        return rv;
    }

    BN_clear_free(bne);

    EVP_PKEY* pkey = EVP_PKEY_new();

    PKCS8_PRIV_KEY_INFO * p8inf = nullptr;

    if (EVP_PKEY_set1_RSA(pkey, rsa))
    {
        p8inf = EVP_PKEY2PKCS8(pkey);
    }

    p8inf = EVP_PKEY2PKCS8(pkey);

    if (!p8inf)
    {
        std::cout << "EVP_PKEY2PKCS8 Failed" << std::endl;
        return rv;
    }

    int len = 0;

    if ((len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL)) < 0)
    {
        std::cout << "i2d_PKCS8_PRIV_KEY_INFO Failed" << std::endl;
        return rv;
    }

    unsigned char *privateKey = new unsigned char[len];
    int copiedBytes = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &privateKey);
    privateKey -= copiedBytes;

    // Write RSA private key into file before encrypting with sym key.
    std::stringstream sstr;
    sstr.write(reinterpret_cast<char*>(privateKey), len);

    // [HARD CODED filePath] --> Update this if needed.
    std::string fileName = "/opt/intel/rsaUnwrapWithAes/BeforeEnc.txt";
    if (!writeData(fileName, sstr))
    {
        std::cout << "File write Failed! " << std::endl;
    }

    //************************************** QUICK VERIFICATION - Reverse path start ********************************************

    const unsigned char* privateKeyCopy = privateKey;
    PKCS8_PRIV_KEY_INFO *pInfo = d2i_PKCS8_PRIV_KEY_INFO(NULL, &privateKeyCopy, len);

    EVP_PKEY *evpKey = EVP_PKCS82PKEY(pInfo);
    RSA *rsaNew = EVP_PKEY_get1_RSA(evpKey);

    //******************************* QUICK VERIFICATION - Reverse path end ***************************************************

    std::vector<CK_BYTE> wrappedKey = getSampleEncryptedData(mechanismType, hSession, hKey, privateKey, len);

    CK_OBJECT_HANDLE importedKey         = CK_INVALID_HANDLE;
    CK_KEY_TYPE     rsaKeyType           = CKK_RSA;
    CK_OBJECT_CLASS rsaPrivateKeyClass   = CKO_PRIVATE_KEY;
    CK_UTF8CHAR     rsaPrivateKeyLabel[] = "RSA key unWrapped with AES Key";
    CK_UTF8CHAR     id[]                 = "1";

    CK_ATTRIBUTE asymPrivateKeyAttribs[] = {{ CKA_TOKEN,    &bTrue,              sizeof(bTrue) },
                                            { CKA_DECRYPT,  &bTrue,              sizeof(bTrue) },
                                            { CKA_SIGN,     &bTrue,              sizeof(bTrue) },
                                            { CKA_UNWRAP,   &bTrue,              sizeof(bTrue) },
                                            { CKA_KEY_TYPE, &rsaKeyType,         sizeof(rsaKeyType)   },
                                            { CKA_CLASS,    &rsaPrivateKeyClass, sizeof(rsaPrivateKeyClass)  },
                                            { CKA_LABEL,    rsaPrivateKeyLabel,  sizeof(rsaPrivateKeyLabel)-1 },
                                            { CKA_ID,       &id[0],              sizeof(id) }
                                            };

    rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession,
                                     pMechanism,
                                     hKey,
                                     wrappedKey.data(),
                                     wrappedKey.size(),
                                     asymPrivateKeyAttribs,
                                     sizeof(asymPrivateKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                     &importedKey));
    if (CKR_OK != rv)
    {
        std::cout << "UnWrapKey Failed" << std::endl;
        return rv;
    }

    //********************************** SAMPLE ENCRYPT **********************************

    uint32_t             rsaBlockSize = RSA_size(rsa);
    std::vector<CK_BYTE> destBuffer(rsaBlockSize, 1);
    std::vector<CK_BYTE> sourceBuffer(40, 1);

    RSA_blinding_on(rsa, nullptr);

    unsigned int bytesCopied = 0;
    int encDataSize = RSA_public_encrypt(sourceBuffer.size(),
                                            sourceBuffer.data(),
                                            destBuffer.data(),
                                            rsa,
                                            4);
    RSA_blinding_off(rsa);
    destBuffer.resize(encDataSize);

    CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };

    CK_MECHANISM_TYPE  mechanismTypeEnc = CKM_RSA_PKCS_OAEP;
    CK_MECHANISM mechanismDec        = { mechanismTypeEnc, &oaepParams, sizeof(oaepParams) };

    //********************************** SAMPLE DECRYPT **********************************

    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, &mechanismDec, importedKey));
    if (CKR_OK != rv)
    {
        std::cout << "C_DecryptInit Failed rv = " << rv << std::endl;
        return rv;
    }

    std::vector<CK_BYTE> decryptedBuffer;
    bytesDone = 0;

    rv = CRYPTOKI_F_PTR( C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), NULL_PTR, &bytesDone));
    if (CKR_OK != rv)
    {
        std::cout << "C_Decrypt Failed" << std::endl;
        return rv;
    }

    decryptedBuffer.resize(bytesDone);
    rv = CRYPTOKI_F_PTR( C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), decryptedBuffer.data(), &bytesDone));
    if (CKR_OK != rv)
    {
        std::cout << "C_Decrypt Failed" << std::endl;
        return rv;
    }

    decryptedBuffer.resize(bytesDone);

    if (sourceBuffer != decryptedBuffer)
    {
        std::cout << "SourceBuffer and decryptedBuffer doesn't match!" << std::endl;
        return rv;
    }

    rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, importedKey));
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey));
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPublicKey));
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrivateKey));
    if (CKR_OK != rv)
    {
        return rv;
    }

    return CKR_OK;
}
#endif

CK_RV AsymEncryptDecryptTests::generateRsaKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
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
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
    return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
                                             pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
                                             prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
                                             &hPuk, &hPrk) );
}

void AsymEncryptDecryptTests::rsaEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, 1, NULL_PTR, 0 };
	CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,0x0C, 0x0D, 0x0F };
	CK_BYTE cipherText[256];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[256];
	CK_ULONG ulRecoveredTextLen;
	CK_RV rv;

	if (mechanismType == CKM_RSA_PKCS_OAEP)
	{
		mechanism.pParameter = &oaepParams;
		mechanism.ulParameterLen = sizeof(oaepParams);
	}

	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulCipherTextLen = sizeof(cipherText);
	rv =CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText),cipherText,&ulCipherTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hPrivateKey) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,cipherText,ulCipherTextLen,recoveredText,&ulRecoveredTextLen) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CPPUNIT_ASSERT(memcmp(plainText, &recoveredText[ulRecoveredTextLen-sizeof(plainText)], sizeof(plainText)) == 0);
}

// Check that RSA OAEP mechanism properly validates all input parameters
void AsymEncryptDecryptTests::rsaOAEPParams(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey)
{
	// This is only supported combination of parameters
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_OAEP, NULL, 0 };
	CK_RV rv;

	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	mechanism.pParameter = &oaepParams;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	mechanism.ulParameterLen = sizeof(oaepParams);

	oaepParams.hashAlg = CKM_AES_CBC;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.hashAlg = CKM_SHA_1;
	oaepParams.mgf = CKG_MGF1_SHA256;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.mgf = CKG_MGF1_SHA1;
	oaepParams.source = CKZ_DATA_SPECIFIED - 1;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.source = CKZ_DATA_SPECIFIED;
	oaepParams.pSourceData = &oaepParams;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.ulSourceDataLen = sizeof(oaepParams);
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);

	oaepParams.pSourceData = NULL;
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hPublicKey) );
	CPPUNIT_ASSERT(rv==CKR_ARGUMENTS_BAD);
}

void AsymEncryptDecryptTests::testRsaEncryptDecrypt()
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

#ifdef AES_UNWRAP_RSA
    rv = rsaWrapUnwrapWithAes(hSessionRW);
    CPPUNIT_ASSERT(CKR_OK == rv);
#endif

    rsaOAEPParams(hSessionRO,hPublicKey);
    rsaEncryptDecrypt(CKM_RSA_PKCS,hSessionRO,hPublicKey,hPrivateKey);
    rsaEncryptDecrypt(CKM_RSA_X_509,hSessionRO,hPublicKey,hPrivateKey);
    rsaEncryptDecrypt(CKM_RSA_PKCS_OAEP,hSessionRO,hPublicKey,hPrivateKey);
}

void AsymEncryptDecryptTests::testNullTemplate()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    CK_MECHANISM mechanismRsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hPublicKey  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
    CK_ULONG     bits         = 2048;
    CK_BYTE      pubExp[]     = {0x01, 0x00, 0x01};
    CK_BYTE      subject[]    = { 0x12, 0x34 };
    CK_BYTE      idRsa[]      = { 123 };
    CK_BBOOL     bFalse       = CK_FALSE;
    CK_BBOOL     bTrue        = CK_TRUE;

    CK_ATTRIBUTE pukAttribs[] = {
                                    { CKA_TOKEN,           &bFalse,    sizeof(bFalse) },
                                    { CKA_PRIVATE,         &bFalse,    sizeof(bFalse) },
                                    { CKA_ENCRYPT,         &bTrue,     sizeof(bTrue) },
                                    { CKA_VERIFY,          &bTrue,     sizeof(bTrue) },
                                    { CKA_WRAP,            &bTrue,     sizeof(bTrue) },
                                    { CKA_MODULUS_BITS,    &bits,      sizeof(bits) },
                                    { CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
                                };

    CK_ATTRIBUTE prkAttribs[] = {
                                    { CKA_TOKEN,     &bFalse,     sizeof(bFalse) },
                                    { CKA_PRIVATE,   &bFalse,     sizeof(bFalse) },
                                    { CKA_SUBJECT,   &subject[0], sizeof(subject) },
                                    { CKA_ID,        &idRsa[0],   sizeof(idRsa) },
                                    { CKA_SENSITIVE, &bTrue,      sizeof(bTrue) },
                                    { CKA_DECRYPT,   &bTrue,      sizeof(bTrue) },
                                    { CKA_SIGN,      &bTrue,      sizeof(bTrue) },
                                    { CKA_UNWRAP,    &bTrue,      sizeof(bTrue) }
                                 };

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Open read-write session
    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Login USER into the sessions so we can create a private objects
    rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Check public key CK_ATTRIBUTE_PTR arguments for NULL_PTR and ulCount more than zero
    rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanismRsa,
                                           nullptr, 1,
                                           prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
                                           &hPublicKey, &hPrivateKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

    // Check private key CK_ATTRIBUTE_PTR arguments for NULL_PTR and ulCount more than zero
    rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanismRsa,
                                           pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
                                           nullptr, 1,
                                           &hPublicKey, &hPrivateKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

    // Log out
    rv = CRYPTOKI_F_PTR( C_Logout(hSession) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Close Session
    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession));
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Finalize
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
    CPPUNIT_ASSERT(CKR_OK == rv);
}