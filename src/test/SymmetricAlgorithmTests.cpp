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
 SymmetricAlgorithmTests.cpp

 Contains test cases for symmetrical algorithms (i.e., AES and DES)
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <climits>
//#include <iomanip>
#include "SymmetricAlgorithmTests.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;

#define NR_OF_BLOCKS_IN_TEST 0x10001

CPPUNIT_TEST_SUITE_REGISTRATION(SymmetricAlgorithmTests);

#if 0 // Unsupported by Crypto API Toolkit
CK_RV SymmetricAlgorithmTests::generateGenericKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
    return  CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
                                          keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
                                          &hKey) );
}
#endif // Unsupported by Crypto API Toolkit

CK_RV SymmetricAlgorithmTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
    return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
                                         keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
                                         &hKey) );
}

#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
CK_RV SymmetricAlgorithmTests::generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV SymmetricAlgorithmTests::generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES2_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}
#endif

CK_RV SymmetricAlgorithmTests::generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}
#endif // Unsupported by Crypto API Toolkit

void SymmetricAlgorithmTests::encryptDecrypt(
		const CK_MECHANISM_TYPE mechanismType,
		const size_t blockSize,
		const CK_SESSION_HANDLE hSession,
		const CK_OBJECT_HANDLE hKey,
		const size_t messageSize,
		const bool isSizeOK)
{
	class PartSize {// class to get random size for part
	private:        // we want to know for sure that no part length is causing any problem.
		const int blockSize;
		const unsigned* pRandom;// point to memory with random data. We are using the data to be encrypted.
		const unsigned* pBack;// point to memory where random data ends.
		int current;// the current size.
	public:
		PartSize(
				const int _blockSize,
				const std::vector<CK_BYTE>* pvData) :
					blockSize(_blockSize),
					pRandom((const unsigned*)&pvData->front()),
					pBack((const unsigned*)&pvData->back()),
					current(blockSize*4){};
		int getCurrent() {// current part size
			return current;
		}
		int getNext() {// get next part size.
			// Check if we do not have more random data
			if ((pRandom+sizeof(unsigned)-1) > pBack) {
				current = blockSize*4;
				return current;
			}
			const unsigned random(*(pRandom++));
			// Bit shift to handle 32- and 64-bit systems.
			// Just want a simple random part length,
			// not a perfect random number (bit shifting will
			// give some loss of precision).
			current = ((unsigned long)random >> 20)*blockSize*0x100/(UINT_MAX >> 20) + 1;
			//std::cout << "New random " << std::hex << random << " current " << std::hex << std::setfill('0') << std::setw(4) << current << " block size " << std::hex << blockSize << std::endl;
			return current;
		}
	};

	const std::vector<CK_BYTE> vData(messageSize);
	std::vector<CK_BYTE> vEncryptedData;
	std::vector<CK_BYTE> vEncryptedDataParted;
	PartSize partSize(blockSize, &vData);

	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GenerateRandom(hSession, (CK_BYTE_PTR)&vData.front(), messageSize) ) );

	const CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_MECHANISM_PTR pMechanism((CK_MECHANISM_PTR)&mechanism);
	CK_AES_CTR_PARAMS ctrParams =
	{
		32,
		{
			0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		}
	};
	CK_BYTE gcmIV[] = {
		0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
		0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
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
		sizeof(gcmIV)*8,
		&gcmAAD[0],
		sizeof(gcmAAD),
		16*8
	};

	switch (mechanismType)
	{
		case CKM_DES_CBC:
		case CKM_DES_CBC_PAD:
		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
			pMechanism->pParameter = (CK_VOID_PTR)&vData.front();
			pMechanism->ulParameterLen = blockSize;
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

	// Single-part encryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptInit(hSession,pMechanism,hKey) ) );
	{
		CK_ULONG ulEncryptedDataLen;
		const CK_RV rv( CRYPTOKI_F_PTR( C_Encrypt(hSession,(CK_BYTE_PTR)&vData.front(),messageSize,NULL_PTR,&ulEncryptedDataLen) ) );
		if ( isSizeOK ) {
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
			vEncryptedData.resize(ulEncryptedDataLen);
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_Encrypt(hSession,(CK_BYTE_PTR)&vData.front(),messageSize,&vEncryptedData.front(),&ulEncryptedDataLen) ) );
			vEncryptedData.resize(ulEncryptedDataLen);
		} else {
			CPPUNIT_ASSERT_EQUAL_MESSAGE("C_Encrypt should fail with C_CKR_DATA_LEN_RANGE", (CK_RV)CKR_DATA_LEN_RANGE, rv);
			vEncryptedData = vData;
		}
	}

	// Multi-part encryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptInit(hSession,pMechanism,hKey) ) );

	for ( std::vector<CK_BYTE>::const_iterator i(vData.begin()); i<vData.end(); i+=partSize.getCurrent() ) {
		const CK_ULONG lPartLen( i+partSize.getNext()<vData.end() ? partSize.getCurrent() : vData.end()-i );
		CK_ULONG ulEncryptedPartLen;
		CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,(CK_BYTE_PTR)&(*i),lPartLen,NULL_PTR,&ulEncryptedPartLen) ) );
		const size_t oldSize( vEncryptedDataParted.size() );
		vEncryptedDataParted.resize(oldSize+ulEncryptedPartLen);
		CK_BYTE dummy;
		const CK_BYTE_PTR pEncryptedPart( ulEncryptedPartLen>0 ? &vEncryptedDataParted.at(oldSize) : &dummy );
		CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,(CK_BYTE_PTR)&(*i),lPartLen,pEncryptedPart,&ulEncryptedPartLen) ) );
		vEncryptedDataParted.resize(oldSize+ulEncryptedPartLen);
	}
	{
		CK_ULONG ulLastEncryptedPartLen;
		const CK_RV rv( CRYPTOKI_F_PTR( C_EncryptFinal(hSession,NULL_PTR,&ulLastEncryptedPartLen) ) );
		if ( isSizeOK ) {
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
			const size_t oldSize( vEncryptedDataParted.size() );
			CK_BYTE dummy;
			vEncryptedDataParted.resize(oldSize+ulLastEncryptedPartLen);
			const CK_BYTE_PTR pLastEncryptedPart( ulLastEncryptedPartLen>0 ? &vEncryptedDataParted.at(oldSize) : &dummy );
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptFinal(hSession,pLastEncryptedPart,&ulLastEncryptedPartLen) ) );
			vEncryptedDataParted.resize(oldSize+ulLastEncryptedPartLen);
		} else {
			CPPUNIT_ASSERT_EQUAL_MESSAGE("C_EncryptFinal should fail with C_CKR_DATA_LEN_RANGE", (CK_RV)CKR_DATA_LEN_RANGE, rv);
			vEncryptedDataParted = vData;
		}
	}

	// Single-part decryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptInit(hSession,pMechanism,hKey) ) );

	{
		CK_ULONG ulDataLen;
		const CK_RV rv( CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataLen) ) );
		if ( isSizeOK ) {
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
			std::vector<CK_BYTE> vDecryptedData(ulDataLen);
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedData.front(),&ulDataLen) ) );
			vDecryptedData.resize(ulDataLen);
			CPPUNIT_ASSERT_MESSAGE("C_Encrypt C_Decrypt does not give the original", vData==vDecryptedData);
		} else {
			CPPUNIT_ASSERT_EQUAL_MESSAGE( "C_Decrypt should fail with CKR_ENCRYPTED_DATA_LEN_RANGE", (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
		}
	}

	// Multi-part decryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptInit(hSession,pMechanism,hKey) ) );
	{
		std::vector<CK_BYTE> vDecryptedData;
		CK_BYTE dummy;
		for ( std::vector<CK_BYTE>::iterator i(vEncryptedDataParted.begin()); i<vEncryptedDataParted.end(); i+=partSize.getCurrent()) {
			const CK_ULONG ulPartLen( i+partSize.getNext()<vEncryptedDataParted.end() ? partSize.getCurrent() : vEncryptedDataParted.end()-i );
			CK_ULONG ulDecryptedPartLen;
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&(*i),ulPartLen,NULL_PTR,&ulDecryptedPartLen) ) );
			const size_t oldSize( vDecryptedData.size() );
			vDecryptedData.resize(oldSize+ulDecryptedPartLen);
			const CK_BYTE_PTR pDecryptedPart( ulDecryptedPartLen>0 ? &vDecryptedData.at(oldSize) : &dummy );
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&(*i),ulPartLen,pDecryptedPart,&ulDecryptedPartLen) ) );
			vDecryptedData.resize(oldSize+ulDecryptedPartLen);
		}
		{
			CK_ULONG ulLastPartLen;
			const CK_RV rv( CRYPTOKI_F_PTR( C_DecryptFinal(hSession,NULL_PTR,&ulLastPartLen) ) );
			if ( isSizeOK ) {
				CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
				const size_t oldSize( vDecryptedData.size() );
				vDecryptedData.resize(oldSize+ulLastPartLen);
				const CK_BYTE_PTR pLastPart( ulLastPartLen>0 ? &vDecryptedData.at(oldSize) : &dummy );
				CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptFinal(hSession,pLastPart,&ulLastPartLen) ) );
				vDecryptedData.resize(oldSize+ulLastPartLen);
				CPPUNIT_ASSERT_MESSAGE("C_EncryptUpdate/C_EncryptFinal C_DecryptUpdate/C_DecryptFinal does not give the original", vData==vDecryptedData);
			} else {
				CPPUNIT_ASSERT_EQUAL_MESSAGE( "C_EncryptFinal should fail with CKR_ENCRYPTED_DATA_LEN_RANGE", (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
			}
		}
	}
}

CK_RV SymmetricAlgorithmTests::generateRsaPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 2048;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pubAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE privAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
	hKey = CK_INVALID_HANDLE;
	CK_RV rv;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
			       pubAttribs, sizeof(pubAttribs)/sizeof(CK_ATTRIBUTE),
			       privAttribs, sizeof(privAttribs)/sizeof(CK_ATTRIBUTE),
			       &hPub, &hKey) );
	if (hPub != CK_INVALID_HANDLE)
	{
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
	}
	return rv;
}

#if 0 // Unsupported by Crypto API Toolkit

#ifdef WITH_GOST
CK_RV SymmetricAlgorithmTests::generateGostPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BYTE param_a[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
	CK_BYTE param_b[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pubAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_GOSTR3410_PARAMS, &param_a[0], sizeof(param_a) },
		{ CKA_GOSTR3411_PARAMS, &param_b[0], sizeof(param_b) }
	};
	CK_ATTRIBUTE privAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
	hKey = CK_INVALID_HANDLE;
	CK_RV rv;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
			       pubAttribs, sizeof(pubAttribs)/sizeof(CK_ATTRIBUTE),
			       privAttribs, sizeof(privAttribs)/sizeof(CK_ATTRIBUTE),
			       &hPub, &hKey) );
	if (hPub != CK_INVALID_HANDLE)
	{
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
	}
	return rv;
}
#endif

void SymmetricAlgorithmTests::aesWrapUnwrapGeneric(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
	CK_BYTE keyPtr[128];
	CK_ULONG keyLen =
		mechanismType == CKM_AES_KEY_WRAP_PAD ? 125UL : 128UL;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) }, // Wrapping is allowed even on sensitive objects
		{ CKA_VALUE, keyPtr, keyLen }
	};
	CK_OBJECT_HANDLE hSecret;
	CK_RV rv;

	rv = CRYPTOKI_F_PTR( C_GenerateRandom(hSession, keyPtr, keyLen) );
    CPPUNIT_ASSERT(rv == CKR_OK);

	hSecret = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hSecret != CK_INVALID_HANDLE);

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	CK_ULONG zero = 0UL;
	CK_ULONG rndKeyLen = keyLen;
	if (mechanismType == CKM_AES_KEY_WRAP_PAD)
		rndKeyLen =  (keyLen + 7) & ~7;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_KEY_UNEXTRACTABLE);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	attribs[0].pValue = &bTrue;

	hSecret = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hSecret != CK_INVALID_HANDLE);

	// Estimate wrapped length
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(wrappedLen == rndKeyLen + 8);

	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	CPPUNIT_ASSERT(wrappedPtr != NULL_PTR);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(wrappedLen == rndKeyLen + 8);

	// This should always fail because wrapped data have to be longer than 0 bytes
	zero = 0;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &zero) );
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	CK_ATTRIBUTE nattribs[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hNew;

	hNew = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nattribs, sizeof(nattribs)/sizeof(CK_ATTRIBUTE), &hNew) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hNew != CK_INVALID_HANDLE);


	free(wrappedPtr);
	wrappedPtr = NULL_PTR;
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif // Unsupported by Crypto API Toolkit

void SymmetricAlgorithmTests::aesWrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	CK_RV rv = generateRsaPrivateKey(hSession, CK_TRUE, CK_TRUE, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BYTE_PTR prkAttrPtr = NULL_PTR;
#ifndef SGXHSM
	CK_ULONG prkAttrLen = 0UL;
#endif
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
#ifndef SGXHSM
        { CKA_PRIME_2, NULL_PTR, 0UL }
#endif
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_RSA);

#ifndef SGXHSM
	prkAttrLen = prkAttribs[2].ulValueLen;
	prkAttrPtr = (CK_BYTE_PTR) malloc(2 * prkAttrLen);
	CPPUNIT_ASSERT(prkAttrPtr != NULL_PTR);
	prkAttribs[2].pValue = prkAttrPtr;
	prkAttribs[2].ulValueLen = prkAttrLen;
#endif

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
#ifndef SGXHSM
    CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);
#endif

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	CPPUNIT_ASSERT(wrappedPtr != NULL_PTR);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    CK_BYTE keyPtr[256];
    CK_ULONG keyLen = 256;

    rv = CRYPTOKI_F_PTR ( C_GenerateRandom(hSession, keyPtr, keyLen) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CK_ATTRIBUTE nPrkAttribsRestricted[] = { { CKA_CLASS,       &privateClass, sizeof(privateClass) },
                                             { CKA_KEY_TYPE,    &keyType,      sizeof(keyType)      },
                                             { CKA_TOKEN,       &bFalse,       sizeof(bFalse)       },
                                             { CKA_PRIVATE,     &bTrue,        sizeof(bTrue)        },
                                             { CKA_DECRYPT,     &bTrue,        sizeof(bTrue)        },
                                             { CKA_SIGN,        &bFalse,       sizeof(bFalse)       },
                                             { CKA_UNWRAP,      &bTrue,        sizeof(bTrue)        },
                                             { CKA_SENSITIVE,   &bFalse,       sizeof(bFalse)       },
                                             { CKA_EXTRACTABLE, &bTrue,        sizeof(bTrue)        },
                                             { CKA_VALUE,       keyPtr,        keyLen}
                                           };

    hPrk = CK_INVALID_HANDLE;
    rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribsRestricted, sizeof(nPrkAttribsRestricted)/sizeof(CK_ATTRIBUTE), &hPrk) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

    nPrkAttribsRestricted[9].type = CKA_VALUE_LEN;
    nPrkAttribsRestricted[9].pValue = &keyLen;
    nPrkAttribsRestricted[9].ulValueLen = sizeof(keyLen);

    hPrk = CK_INVALID_HANDLE;
    rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribsRestricted, sizeof(nPrkAttribsRestricted)/sizeof(CK_ATTRIBUTE), &hPrk) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

    nPrkAttribsRestricted[9].type = CKA_PRIVATE_EXPONENT;
    nPrkAttribsRestricted[9].pValue = nullptr;
    nPrkAttribsRestricted[9].ulValueLen = 0;

    hPrk = CK_INVALID_HANDLE;
    rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribsRestricted, sizeof(nPrkAttribsRestricted)/sizeof(CK_ATTRIBUTE), &hPrk) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);

    CK_ULONG bits = 4092;
    nPrkAttribsRestricted[9].type = CKA_MODULUS_BITS;
    nPrkAttribsRestricted[9].pValue = &bits;
    nPrkAttribsRestricted[9].ulValueLen = sizeof(bits);

    hPrk = CK_INVALID_HANDLE;
    rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribsRestricted, sizeof(nPrkAttribsRestricted)/sizeof(CK_ATTRIBUTE), &hPrk) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

    CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	hPrk = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

#ifndef SGXHSM
	prkAttribs[2].pValue = prkAttrPtr + prkAttrLen;
#endif
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_RSA);
#ifndef SGXHSM
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);
	CPPUNIT_ASSERT(memcmp(prkAttrPtr, prkAttrPtr + prkAttrLen, prkAttrLen) == 0);
#endif

#ifdef SGXHSM
    rv = CRYPTOKI_F_PTR ( C_GenerateRandom(hSession, keyPtr, keyLen) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CK_ATTRIBUTE pTemplate[] = { { CKA_PRIME_2, NULL_PTR, 0UL }
                               };

    rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPrk, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

    pTemplate[0].type = CKA_VALUE;
    pTemplate[0].pValue = keyPtr;
    pTemplate[0].ulValueLen = 0;

    rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPrk, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

    memset(keyPtr, keyLen, 0);
    rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

    keyLen = 512;
    pTemplate[0].type = CKA_VALUE_LEN;
    pTemplate[0].pValue = &keyLen;
    pTemplate[0].ulValueLen = sizeof(keyLen);

    rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hPrk, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);
#endif

	free(wrappedPtr);
	free(prkAttrPtr);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

#ifdef WITH_GOST
void SymmetricAlgorithmTests::aesWrapUnwrapGost(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	CK_RV rv = generateGostPrivateKey(hSession, CK_TRUE, CK_TRUE, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_GOSTR3410;
	CK_BYTE_PTR prkAttrPtr = NULL_PTR;
	CK_ULONG prkAttrLen = 0UL;
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE, NULL_PTR, 0UL }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_GOSTR3410);

	prkAttrLen = prkAttribs[2].ulValueLen;
	prkAttrPtr = (CK_BYTE_PTR) malloc(2 * prkAttrLen);
	CPPUNIT_ASSERT(prkAttrPtr != NULL_PTR);
	prkAttribs[2].pValue = prkAttrPtr;
	prkAttribs[2].ulValueLen = prkAttrLen;

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	CPPUNIT_ASSERT(wrappedPtr != NULL_PTR);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	hPrk = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	prkAttribs[2].pValue = prkAttrPtr + prkAttrLen;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_GOSTR3410);
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);
	CPPUNIT_ASSERT(memcmp(prkAttrPtr, prkAttrPtr + prkAttrLen, prkAttrLen) == 0);

	free(wrappedPtr);
	free(prkAttrPtr);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif

void SymmetricAlgorithmTests::testAesEncryptDecrypt()
{
	CK_RV rv;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
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

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateAesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// AES allways have the block size of 128 bits (0x80 bits 0x10 bytes).
	// with padding all message sizes could be encrypted-decrypted.
	// without padding the message size must be a multiple of the block size.
	const int blockSize(0x10);
	encryptDecrypt(CKM_AES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_AES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_AES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_AES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_AES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
#if 0 // Unsupported by Crypto API Toolkit
	encryptDecrypt(CKM_AES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_AES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
#endif
	encryptDecrypt(CKM_AES_CTR,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_AES_CTR,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_AES_CTR,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
#ifdef WITH_AES_GCM
	encryptDecrypt(CKM_AES_GCM,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_AES_GCM,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_AES_GCM,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
#endif
}

void SymmetricAlgorithmTests::testAesWrapUnwrap()
{
	CK_RV rv;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the session so we can create a private object
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE hKeyData = CK_INVALID_HANDLE;

    // Generate a wrapping session public key
    rv = generateAesKey(hSession, IN_SESSION, IS_PUBLIC, hKey);
        CPPUNIT_ASSERT(rv == CKR_OK);
    rv = generateAesKey(hSession, IN_SESSION, IS_PUBLIC, hKeyData);
        CPPUNIT_ASSERT(rv == CKR_OK);
            
    aesWrapUnwrap(CKM_AES_CTR, hSession, hKey, hKeyData);
#ifdef WITH_AES_GCM	
    aesWrapUnwrap(CKM_AES_GCM, hSession, hKey, hKeyData);
#endif	
    aesWrapUnwrap(CKM_AES_CBC, hSession, hKey, hKeyData);
    aesWrapUnwrap(CKM_AES_CBC_PAD, hSession, hKey, hKeyData);
#ifdef HAVE_AES_KEY_WRAP
#if 0 // Unsupported by Crypto API Toolkit
    aesWrapUnwrapGeneric(CKM_AES_KEY_WRAP, hSession, hKey);
#endif // Unsupported by Crypto API Toolkit
    aesWrapUnwrapRsa(CKM_AES_KEY_WRAP, hSession, hKey);
#endif
#ifdef WITH_GOST
	aesWrapUnwrapGost(CKM_AES_KEY_WRAP, hSession, hKey);
#endif

#ifdef HAVE_AES_KEY_WRAP_PAD
#if 0 // Unsupported by Crypto API Toolkit
	aesWrapUnwrapGeneric(CKM_AES_KEY_WRAP_PAD, hSession, hKey);
#endif // Unsupported by Crypto API Toolkit
	aesWrapUnwrapRsa(CKM_AES_KEY_WRAP_PAD, hSession, hKey);
#ifdef WITH_GOST
	aesWrapUnwrapGost(CKM_AES_KEY_WRAP_PAD, hSession, hKey);
#endif
#endif
}

#if 0 // Unsupported by Crypto API Toolkit
void SymmetricAlgorithmTests::testDesEncryptDecrypt()
{
	CK_RV rv;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
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

	// 3DES and DES always have the block size of 64 bits (0x40 bits 0x8 bytes).
	// with padding all message sizes could be encrypted-decrypted.
	// without padding the message size must be a multiple of the block size.
	const int blockSize(0x8);

#ifndef WITH_FIPS
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	encryptDecrypt(CKM_DES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_DES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_DES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_DES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);

	CK_OBJECT_HANDLE hKey2 = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDes2Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey2);
	CPPUNIT_ASSERT(rv == CKR_OK);

	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
#endif

	CK_OBJECT_HANDLE hKey3 = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDes3Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey3);
	CPPUNIT_ASSERT(rv == CKR_OK);

	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
}
#endif // Unsupported by Crypto API Toolkit

void SymmetricAlgorithmTests::testNullTemplate()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
#if 0 // Unsupported by Crypto API Toolkit
	CK_MECHANISM mechanism1 = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
#endif // Unsupported by Crypto API Toolkit

	CK_MECHANISM mechanism2 = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

#if 0 // Unsupported by Crypto API Toolkit
	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism1, NULL_PTR, 0, &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
#endif // Unsupported by Crypto API Toolkit

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism2, NULL_PTR, 0, &hKey) );
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCOMPLETE);
}

#if 0 // Unsupported by Crypto API Toolkit
void SymmetricAlgorithmTests::testNonModifiableDesKeyGeneration()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bToken = IN_SESSION;

	CK_ATTRIBUTE keyAttribs[] =
		{
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
		&hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// The C_GenerateKey call failed if CKA_MODIFIABLE was bFalse
	// This was a bug in the SoftHSM implementation
	keyAttribs[2].pValue = &bFalse;
	keyAttribs[2].ulValueLen = sizeof(bFalse);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
		&hKey) );
	// The call would fail with CKR_ATTRIBUTE_READ_ONLY
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now create a template where the CKA_MODIFIABLE attribute is last in the list
	CK_ATTRIBUTE keyAttribs1[] =
	{
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue) }
	};

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs1, sizeof(keyAttribs1) / sizeof(CK_ATTRIBUTE),
		&hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now when CKA_MODIFIABLE is bFalse the key generation succeeds
	keyAttribs1[2].pValue = &bFalse;
	keyAttribs1[2].ulValueLen = sizeof(bFalse);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs1, sizeof(keyAttribs1) / sizeof(CK_ATTRIBUTE),
		&hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif // Unsupported by Crypto API Toolkit

void SymmetricAlgorithmTests::testCheckValue()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_ULONG bytes = 16;
	CK_BYTE pCheckValue[] = { 0x2b, 0x84, 0xf6 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
		{ CKA_CHECK_VALUE, &pCheckValue, sizeof(pCheckValue) }
	};

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			   keyAttribs, 8,
			   &hKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

	keyAttribs[7].ulValueLen = 0;
	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			   keyAttribs, 8,
			   &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ATTRIBUTE checkAttrib[] = {
		{ CKA_CHECK_VALUE, &pCheckValue, sizeof(pCheckValue) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hKey, checkAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(checkAttrib[0].ulValueLen == 0);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			   keyAttribs, 7,
			   &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	checkAttrib[0].ulValueLen = sizeof(pCheckValue);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hKey, checkAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(checkAttrib[0].ulValueLen == 3);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SymmetricAlgorithmTests::testAesCtrOverflow()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the session so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate a session keys.
	rv = generateAesKey(hSession,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_MECHANISM mechanism = { CKM_AES_CTR, NULL_PTR, 0 };
	CK_AES_CTR_PARAMS ctrParams =
	{
		2,
		{
			0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		}
	};
	mechanism.pParameter = &ctrParams;
	mechanism.ulParameterLen = sizeof(ctrParams);

	CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x00 };
	std::vector<CK_BYTE> vEncryptedData;
	std::vector<CK_BYTE> vEncryptedDataParted;
	std::vector<CK_BYTE> vDecryptedData;
	std::vector<CK_BYTE> vDecryptedDataParted;
	CK_ULONG ulEncryptedDataLen;
	CK_ULONG ulEncryptedPartLen;
	CK_ULONG ulDataLen;
	CK_ULONG ulDataPartLen;

	// Single-part encryption
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText),NULL_PTR,&ulEncryptedDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_DATA_LEN_RANGE, rv );
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText)-1,NULL_PTR,&ulEncryptedDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedData.resize(ulEncryptedDataLen);
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText)-1,&vEncryptedData.front(),&ulEncryptedDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedData.resize(ulEncryptedDataLen);

	// Multi-part encryption
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,plainText,sizeof(plainText)-1,NULL_PTR,&ulEncryptedPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedDataParted.resize(ulEncryptedPartLen);
	rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,plainText,sizeof(plainText)-1,&vEncryptedDataParted.front(),&ulEncryptedPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedDataParted.resize(ulEncryptedPartLen);
	rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,plainText,1,NULL_PTR,&ulEncryptedPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_DATA_LEN_RANGE, rv );

	// Single-part decryption
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size()+1,NULL_PTR,&ulDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedData.resize(ulDataLen);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedData.front(),&ulDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedData.resize(ulDataLen);

	// Multi-part decryption
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedDataParted.resize(ulDataPartLen);
	rv = CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedDataParted.front(),&ulDataPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedDataParted.resize(ulDataPartLen);
	rv = CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&vEncryptedData.front(),1,NULL_PTR,&ulDataPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
}

#if 0 // Unsupported by Crypto API Toolkit
void SymmetricAlgorithmTests::testGenericKey()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the session so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate a session key.
	rv = generateGenericKey(hSession,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif // Unsupported by Crypto API Toolkit

void SymmetricAlgorithmTests::aesWrapUnwrap(CK_MECHANISM_TYPE mechanismType,
                                            CK_SESSION_HANDLE hSession,
                                            CK_OBJECT_HANDLE  hKey,
                                            CK_OBJECT_HANDLE  hKeyData)
{
    CK_RV                   rv       = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism       = { mechanismType, NULL_PTR, 0 };
    CK_OBJECT_HANDLE        hUnwrappedKey   = CK_INVALID_HANDLE;
    CK_BBOOL                bTrue           = CK_TRUE;
    CK_ULONG                wrappedLen      = 0UL;
    CK_KEY_TYPE             aesKeyType      = CKK_AES;
    CK_OBJECT_CLASS         aesKeyClass     = CKO_SECRET_KEY;
    CK_UTF8CHAR             aesKeyLabel[]   = "AES Key Label For Wrap/Unwrap";
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    wrappedData;

    CK_AES_CTR_PARAMS ctrParams =
    {
        128,
        {
            0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
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
    CK_BYTE gcmAAD[] = {   hKey,
                                   
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2
    };
    CK_ULONG tagBits = 128;
    CK_GCM_PARAMS gcmParams =
    {
        &gcmIV[0],
        sizeof(gcmIV),
        sizeof(gcmIV) * 8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        tagBits
    };

        switch (mechanismType)
        {
            case CKM_AES_CBC_PAD:
            case CKM_AES_CBC:
                pMechanism->pParameter     = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;
            case CKM_AES_CTR:
                pMechanism->pParameter      = &ctrParams;
                pMechanism->ulParameterLen  = sizeof(ctrParams);
                break;
            case CKM_AES_GCM:
                pMechanism->pParameter      = &gcmParams;
                pMechanism->ulParameterLen  = sizeof(gcmParams);
                break;
            default:
                break;
        }

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      NULL_PTR,
                                      hKey,
                                      hKeyData,
                                      NULL_PTR,
                                      &wrappedLen));
        CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hKey,
                                      hKeyData,
                                      NULL_PTR,
                                      &wrappedLen));
        CPPUNIT_ASSERT(rv == CKR_OK);

        wrappedData.resize(wrappedLen);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hKey,
                                      hKeyData,
                                      wrappedData.data(),
                                      &wrappedLen));
        CPPUNIT_ASSERT(rv == CKR_OK);

        CK_BYTE keyPtr[16];
        CK_ULONG keyLen = 16;

        rv = CRYPTOKI_F_PTR ( C_GenerateRandom(hSession, keyPtr, keyLen) );
        CPPUNIT_ASSERT(rv == CKR_OK);

        CK_ATTRIBUTE keyAttribsRestricted[] = { { CKA_ENCRYPT,  &bTrue,       sizeof(bTrue)         },
                                                { CKA_DECRYPT,  &bTrue,       sizeof(bTrue)         },
                                                { CKA_WRAP,     &bTrue,       sizeof(bTrue)         },
                                                { CKA_UNWRAP,   &bTrue,       sizeof(bTrue)         },
                                                { CKA_KEY_TYPE, &aesKeyType,  sizeof(aesKeyType)    },
                                                { CKA_CLASS,    &aesKeyClass, sizeof(aesKeyClass)   },
                                                { CKA_LABEL,    aesKeyLabel,  sizeof(aesKeyLabel)-1 },
                                                { CKA_VALUE,    keyPtr,       keyLen                }
                                              };

        hUnwrappedKey = CK_INVALID_HANDLE;
        rv = CRYPTOKI_F_PTR(C_UnwrapKey(hSession,
                                        &mechanism,
                                        hKey,
                                        wrappedData.data(),
                                        wrappedLen,
                                        keyAttribsRestricted,
                                        sizeof(keyAttribsRestricted) / sizeof(CK_ATTRIBUTE),
                                        &hUnwrappedKey));
        CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);

        keyAttribsRestricted[7].type = CKA_VALUE_LEN;
        keyAttribsRestricted[7].pValue = &keyLen;
        keyAttribsRestricted[7].ulValueLen = sizeof(keyLen);

        hUnwrappedKey   = CK_INVALID_HANDLE;
        rv = CRYPTOKI_F_PTR(C_UnwrapKey(hSession,
                                        &mechanism,
                                        hKey,
                                        wrappedData.data(),
                                        wrappedLen,
                                        keyAttribsRestricted,
                                        sizeof(keyAttribsRestricted) / sizeof(CK_ATTRIBUTE),
                                        &hUnwrappedKey));
        CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_READ_ONLY);

        hUnwrappedKey = CK_INVALID_HANDLE;
        CK_ATTRIBUTE keyAttribs[] = { { CKA_ENCRYPT,  &bTrue,       sizeof(bTrue)         },
                                      { CKA_DECRYPT,  &bTrue,       sizeof(bTrue)         },
                                      { CKA_WRAP,     &bTrue,       sizeof(bTrue)         },
                                      { CKA_UNWRAP,   &bTrue,       sizeof(bTrue)         },
                                      { CKA_KEY_TYPE, &aesKeyType,  sizeof(aesKeyType)    },
                                      { CKA_CLASS,    &aesKeyClass, sizeof(aesKeyClass)   },
                                      { CKA_LABEL,    aesKeyLabel,  sizeof(aesKeyLabel)-1 }
                                    };

        rv = CRYPTOKI_F_PTR(C_UnwrapKey(hSession,
                                        &mechanism,
                                        hKey,
                                        wrappedData.data(),
                                        wrappedLen,
                                        keyAttribs,
                                        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                        &hUnwrappedKey));
        CPPUNIT_ASSERT(rv == CKR_OK);

#ifdef SGXHSM
        CK_ATTRIBUTE pTemplate[] = { { CKA_VALUE, keyPtr, keyLen }
                                   };

        rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hUnwrappedKey, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
        CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

        memset(keyPtr, keyLen, 0);
        rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hUnwrappedKey, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
        CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);

        keyLen = 24;
        pTemplate[0].type = CKA_VALUE_LEN;
        pTemplate[0].pValue = &keyLen;
        pTemplate[0].ulValueLen = sizeof(keyLen);

        rv = CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hUnwrappedKey, pTemplate, sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)) );
        CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_TYPE_INVALID);
#endif
        switch (mechanismType)
        {
            case CKM_AES_CBC_PAD:
                encryptDecrypt_BlockSizeCBCPADAfterWrapUnwrap(mechanismType, hSession, hKeyData, hUnwrappedKey);
                encryptDecrypt_NonBlockSizeCBCPADAfterWrapUnwrap(mechanismType, hSession, hKeyData, hUnwrappedKey);
                break;
            default:
                encryptDecryptAfterWrapUnwrap(mechanismType, hSession, hKeyData, hUnwrappedKey);
                break;
        }

        rv =  CRYPTOKI_F_PTR(C_DestroyObject(hSession, hUnwrappedKey));
        CPPUNIT_ASSERT(rv == CKR_OK);
}

void SymmetricAlgorithmTests::encryptDecryptAfterWrapUnwrap(CK_MECHANISM_TYPE     mechanismType,
                                                            CK_SESSION_HANDLE     hSession,
                                                            CK_OBJECT_HANDLE      hKey,
                                                            CK_OBJECT_HANDLE      hKeyNew)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    CK_RV                   rv           = CKR_GENERAL_ERROR;
    CK_ULONG                bytesDone           = 0;
    CK_ULONG                encryptedBytes      = 0;
    uint32_t                tagBits             = 0;
    uint32_t                tagBytes            = 0;
    const uint32_t          sourceBufferSize    = 16;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    sourceBuffer(sourceBufferSize, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());
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
            return;
    }

    rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession, pMechanism, hKey));
    CPPUNIT_ASSERT(rv == CKR_OK);
    
    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data(), sourceBufferSize, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data(), sourceBufferSize, destBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    encryptedBytes = destBuffer.size();
    destBuffer.resize(destBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(encryptedBytes + bytesDone);
    bytesDone = 0;
    std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);
    CK_ULONG decryptedBytes = 0;
    
    rv = CRYPTOKI_F_PTR(C_DecryptInit(hSession, pMechanism, hKeyNew));
    CPPUNIT_ASSERT(rv == CKR_OK);

    // tagBytes will be 0 for non GCM mechanisms
    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data(), sourceBufferSize + tagBytes, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(bytesDone);  // bytesDone will be 0 for GCM(DecryptUpdate) as it is AEAD cipher..

    // tagBytes will be 0 for non GCM mechanisms
    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data(), sourceBufferSize + tagBytes, decryptedBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);
    decryptedBytes = decryptedBuffer.size();
    bytesDone = 0;
    rv = CRYPTOKI_F_PTR(C_DecryptFinal(hSession, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);
    
    decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptFinal(hSession, decryptedBuffer.data() /* + decryptedBytes*/, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBytes + bytesDone);
    bytesDone = 0;

    CPPUNIT_ASSERT (memcmp(sourceBuffer.data(), decryptedBuffer.data(),sourceBufferSize) == 0);
}

void SymmetricAlgorithmTests::encryptDecrypt_BlockSizeCBCPADAfterWrapUnwrap(CK_MECHANISM_TYPE     mechanismType,
                                                                            CK_SESSION_HANDLE     hSession,
                                                                            CK_OBJECT_HANDLE      hKey,
                                                                            CK_OBJECT_HANDLE      hKeyNew)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    const uint32_t          sourceBufferSize    = 16;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    sourceBuffer(sourceBufferSize, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());

    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };

    CPPUNIT_ASSERT(mechanismType == CKM_AES_CBC_PAD);

    pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
    pMechanism->ulParameterLen = sizeof(cbcIV);

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_ULONG bytesDone = 0;
    CK_ULONG encryptedBytes = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession, pMechanism, hKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data(), 15, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data(), 15, destBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 1, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(destBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 1, destBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    encryptedBytes = destBuffer.size();
    destBuffer.resize(destBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(encryptedBytes + bytesDone);
    bytesDone = 0;

    // Decryption!
    std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);
    CK_ULONG decryptedBytes = 0;

    rv = CRYPTOKI_F_PTR(C_DecryptInit(hSession, pMechanism, hKeyNew));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data(), 15, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data(), 15, decryptedBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBytes = decryptedBuffer.size();
    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, decryptedBuffer.data() + decryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBytes = decryptedBuffer.size();
    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_DecryptFinal(hSession, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptFinal(hSession, decryptedBuffer.data() + decryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBytes + bytesDone);
    bytesDone = 0;

    CPPUNIT_ASSERT(sourceBuffer == decryptedBuffer);
}

void SymmetricAlgorithmTests::encryptDecrypt_NonBlockSizeCBCPADAfterWrapUnwrap(CK_MECHANISM_TYPE  mechanismType,
                                                                               CK_SESSION_HANDLE  hSession,
                                                                               CK_OBJECT_HANDLE   hKey,
                                                                               CK_OBJECT_HANDLE   hKeyNew)
                            {
    const CK_MECHANISM      mechanism = { mechanismType, NULL_PTR, 0 };
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    sourceBuffer(18, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());

    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };

    CPPUNIT_ASSERT(mechanismType == CKM_AES_CBC_PAD);

    pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
    pMechanism->ulParameterLen = sizeof(cbcIV);

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_ULONG bytesDone = 0;
    CK_ULONG encryptedBytes = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession, pMechanism, hKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data(), 15, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data(), 15, destBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);
    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 3, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(destBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 3, destBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    encryptedBytes = destBuffer.size();
    destBuffer.resize(destBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    destBuffer.resize(encryptedBytes + bytesDone);
    bytesDone = 0;

    // Decryption!
    std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);
    CK_ULONG decryptedBytes = 0;

    rv = CRYPTOKI_F_PTR(C_DecryptInit(hSession, pMechanism, hKeyNew));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data(), 15, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data(), 15, decryptedBuffer.data(), &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBytes = decryptedBuffer.size();
    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, decryptedBuffer.data() + decryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBytes = decryptedBuffer.size();
    bytesDone = 0;

    rv = CRYPTOKI_F_PTR(C_DecryptFinal(hSession, NULL_PTR, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

    rv = CRYPTOKI_F_PTR(C_DecryptFinal(hSession, decryptedBuffer.data() + decryptedBytes, &bytesDone));
    CPPUNIT_ASSERT(rv == CKR_OK);

    decryptedBuffer.resize(decryptedBytes + bytesDone);
    CPPUNIT_ASSERT (sourceBuffer == decryptedBuffer);

    bytesDone = 0;
}

std::vector<CK_BYTE> getEncryptedData(CK_MECHANISM_TYPE    mechanismType,
                                      CK_SESSION_HANDLE    hSession,
                                      CK_OBJECT_HANDLE     hKey,
                                      unsigned char *      sourceBuffer,
                                      const int&           sourceBufferSize)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                bytesDone           = 0;
    CK_ULONG                encryptedBytes      = 0;
    uint32_t                tagBits             = 0;
    uint32_t                tagBytes            = 0;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    destBuffer(sourceBufferSize);
    CK_RV 					rv;

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
        
        rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession, pMechanism, hKey));
        CPPUNIT_ASSERT(rv == CKR_OK);

        rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer, sourceBufferSize, NULL_PTR, &bytesDone));

        CPPUNIT_ASSERT(rv == CKR_OK);
        
        destBuffer.resize(bytesDone);

        rv = CRYPTOKI_F_PTR(C_EncryptUpdate(hSession, sourceBuffer, sourceBufferSize, destBuffer.data(), &bytesDone));

        CPPUNIT_ASSERT(rv == CKR_OK);
        bytesDone = 0;

        rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, NULL_PTR, &bytesDone));

        CPPUNIT_ASSERT(rv == CKR_OK);
        encryptedBytes = destBuffer.size();
        destBuffer.resize(destBuffer.size() + bytesDone);

        rv = CRYPTOKI_F_PTR(C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone));

        CPPUNIT_ASSERT(rv == CKR_OK);
        destBuffer.resize(encryptedBytes + bytesDone);

    } while(false);

    return destBuffer;
}

void SymmetricAlgorithmTests::testRsaWrapWithAes()
{
	/*
	//// test uses some OpenSSL calls directly. We will revisit this later

    CK_MECHANISM_TYPE mechanismType				= CKM_AES_CTR;
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };

    CK_RV                   rv;
    CK_SESSION_HANDLE hSession;
    CK_ULONG                bytesDone           = 0;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

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
    CPPUNIT_ASSERT(rv==CKR_OK);

    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

    rv = generateAesKey(hSession,IN_SESSION,IS_PUBLIC,hKey);
    CK_AES_CTR_PARAMS   ctrParams =
    {
        128,
        {
            0x01, 0x02, 0x03, 0x30, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        }
    };

    pMechanism->pParameter = &ctrParams;
    pMechanism->ulParameterLen = sizeof(ctrParams);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
#endif
        ERR_load_BIO_strings();
        unsigned long  e = RSA_F4;

        BIGNUM* bne = BN_new();
        if (BN_set_word(bne,e) != 1)
        {
            std::cout << "BN_set_word Failed" << std::endl;
            exit(0);
        }

        RSA* rsa = RSA_new();
        if (RSA_generate_key_ex(rsa, 2048, bne, NULL) != 1)
        {
            std::cout << "RSA_generate_key_ex Failed" << std::endl;
            exit(0);
        }

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
            exit(0);
        }

        int len = 0;

        if ((len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL)) < 0)
        {
            std::cout << "i2d_PKCS8_PRIV_KEY_INFO Failed" << std::endl;
            exit(0);
        }

        unsigned char *privateKey = new unsigned char[len];
        int copiedBytes = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &privateKey);
        privateKey -= copiedBytes;

        // Write RSA private key into file before encrypting with sym key.
        std::stringstream sstr;
        sstr.write(reinterpret_cast<char*>(privateKey), len);

        //************************************** QUICK VERIFICATION - Reverse path ********************************************


        const unsigned char* privateKeyCopy = privateKey;
        PKCS8_PRIV_KEY_INFO *pInfo = d2i_PKCS8_PRIV_KEY_INFO(NULL, &privateKeyCopy, len);

        EVP_PKEY *evpKey = EVP_PKCS82PKEY(pInfo);
        RSA *rsaNew = EVP_PKEY_get1_RSA(evpKey);


        //**********************************************************************************
        std::vector<CK_BYTE> wrappedKey = getEncryptedData(mechanismType, hSession, hKey, privateKey, len);

        CK_OBJECT_HANDLE importedKey =  CK_INVALID_HANDLE;
        CK_KEY_TYPE     rsaKeyType           = CKK_RSA;
        CK_OBJECT_CLASS rsaPrivateKeyClass   = CKO_PRIVATE_KEY;
        CK_UTF8CHAR     rsaPrivateKeyLabel[] = "RSA key unWrapped with AES Key";
        CK_UTF8CHAR     id[] = "1";
        CK_BBOOL        bTrue                = CK_TRUE;

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
                                          
        CPPUNIT_ASSERT(rv == CKR_OK);

        //********************************** SAMPLE Encryption and Decryption **********************************

        uint32_t             rsaBlockSize = RSA_size(rsa);
        std::vector<CK_BYTE> destBuffer(rsaBlockSize, 1);
        std::vector<CK_BYTE> sourceBuffer(40, 1);

        RSA_blinding_on(rsa, nullptr);

        unsigned int bytesCopied = 0;
        int encDataSize = RSA_public_encrypt(sourceBuffer.size(), sourceBuffer.data(), destBuffer.data(), rsa, 1);
        RSA_blinding_off(rsa);
        destBuffer.resize(encDataSize);

        CK_MECHANISM_TYPE  mechanismTypeEnc = CKM_RSA_PKCS;
        CK_MECHANISM mechanism1        = { mechanismTypeEnc, NULL_PTR, 0 };

        rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism1,importedKey) );
        
        CPPUNIT_ASSERT(rv == CKR_OK);

        std::vector<CK_BYTE> decryptedBuffer;
           bytesDone = 0;

        rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,destBuffer.data(), destBuffer.size(), NULL_PTR, &bytesDone) );
        CPPUNIT_ASSERT(rv == CKR_OK);

        decryptedBuffer.resize(bytesDone);
        rv = CRYPTOKI_F_PTR( C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), decryptedBuffer.data(), &bytesDone) );
        CPPUNIT_ASSERT(rv == CKR_OK);
        CPPUNIT_ASSERT (memcmp(sourceBuffer.data(), decryptedBuffer.data(),sourceBuffer.size()) == 0);
    
        rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, importedKey) );
        CPPUNIT_ASSERT(rv == CKR_OK);
		*/

        //**********************************************************************************
}

#ifdef SGXHSM
void SymmetricAlgorithmTests::aesWrapUnwrapInSameSession(CK_MECHANISM_TYPE mechanismType,
                                                         CK_SESSION_HANDLE hSession,
                                                         CK_OBJECT_HANDLE  hKey,
                                                         CK_OBJECT_HANDLE  hKeyData)
{
    CK_RV                   rv       = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism       = { mechanismType, NULL_PTR, 0 };
#ifndef SGXHSM
    CK_BBOOL                bTrue           = CK_TRUE;
#endif
    CK_ULONG                wrappedLen      = 0UL;
#ifndef SGXHSM
    CK_KEY_TYPE             aesKeyType      = CKK_AES;
    CK_OBJECT_CLASS         aesKeyClass     = CKO_SECRET_KEY;
    CK_UTF8CHAR             aesKeyLabel[]   = "AES Key Label For Wrap/Unwrap";
#endif
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    wrappedData;

    CK_AES_CTR_PARAMS ctrParams =
    {
        128,
        {
            0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
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
    CK_ULONG tagBits = 128;
    CK_GCM_PARAMS gcmParams =
    {
        &gcmIV[0],
        sizeof(gcmIV),
        sizeof(gcmIV) * 8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        tagBits
    };

        switch (mechanismType)
        {
            case CKM_AES_CBC_PAD:
            case CKM_AES_CBC:
                pMechanism->pParameter     = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;
            case CKM_AES_CTR:
                pMechanism->pParameter      = &ctrParams;
                pMechanism->ulParameterLen  = sizeof(ctrParams);
                break;
            case CKM_AES_GCM:
                pMechanism->pParameter      = &gcmParams;
                pMechanism->ulParameterLen  = sizeof(gcmParams);
                break;
            default:
                break;
        }

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hKey,
                                      hKeyData,
                                      NULL_PTR,
                                      &wrappedLen));
        CPPUNIT_ASSERT(CKR_OK == rv);

        wrappedData.resize(wrappedLen);

        rv = CRYPTOKI_F_PTR(C_WrapKey(hSession,
                                      &mechanism,
                                      hKey,
                                      hKeyData,
                                      wrappedData.data(),
                                      &wrappedLen));
        CPPUNIT_ASSERT(CKR_OK == rv);

        //Encryption using the key used for wrapping should fail
        rv = CRYPTOKI_F_PTR(C_EncryptInit(hSession, pMechanism, hKey));
        CPPUNIT_ASSERT(CKR_OBJECT_HANDLE_INVALID == rv);

        //Decryption using the key used for wrapping should fail
        rv = CRYPTOKI_F_PTR(C_DecryptInit(hSession, pMechanism, hKey));
        CPPUNIT_ASSERT(CKR_OBJECT_HANDLE_INVALID == rv);
}

CK_RV SymmetricAlgorithmTests::generateAesKeyTokenObject(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
    CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_ULONG bytes = 16;
    CK_BBOOL bTrue = CK_TRUE;
    CK_RV rv = CKR_OK;
    CK_UTF8CHAR aesKeyLabel[] = "aes key used for Encryption/Decryption after wrapping";

    CK_ATTRIBUTE keyAttribs[] = { { CKA_TOKEN,       &bToken,     sizeof(bToken) },
                                  { CKA_PRIVATE,     &bPrivate,   sizeof(bPrivate) },
                                  { CKA_ENCRYPT,     &bTrue,      sizeof(bTrue) },
                                  { CKA_DECRYPT,     &bTrue,      sizeof(bTrue) },
                                  { CKA_WRAP,        &bTrue,      sizeof(bTrue) },
                                  { CKA_UNWRAP,      &bTrue,      sizeof(bTrue) },
                                  { CKA_EXTRACTABLE, &bTrue,      sizeof(bTrue) },
                                  { CKA_VALUE_LEN,   &bytes,      sizeof(bytes) },
                                  { CKA_LABEL,       aesKeyLabel, sizeof(aesKeyLabel)-1 },
                                };

    hKey = CK_INVALID_HANDLE;
    rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
                                       keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
                                       &hKey) );

    return rv;
}


void SymmetricAlgorithmTests::testAesWrapUnwrapTokenObject()
{
    aesWrapUnwrapTokenObject(CKM_AES_CTR);
#ifdef WITH_AES_GCM
    aesWrapUnwrapTokenObject(CKM_AES_GCM);
#endif
    aesWrapUnwrapTokenObject(CKM_AES_CBC);
    aesWrapUnwrapTokenObject(CKM_AES_CBC_PAD);
}

void SymmetricAlgorithmTests::aesWrapUnwrapTokenObject(CK_MECHANISM_TYPE mechanismType)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Open session
    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Login USER into the session so we can create a private object
    rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hKeyData = CK_INVALID_HANDLE;

    // Generate a wrapping session public key
    rv = generateAesKeyTokenObject(hSession, ON_TOKEN, IS_PUBLIC, hKey);
    CPPUNIT_ASSERT(CKR_OK == rv);
    rv = generateAesKey(hSession, IN_SESSION, IS_PUBLIC, hKeyData);
    CPPUNIT_ASSERT(CKR_OK == rv);

    aesWrapUnwrapInSameSession(mechanismType, hSession, hKey, hKeyData);

    rv = CRYPTOKI_F_PTR( C_Logout(hSession) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Close Session
    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession));
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Testing with token opbject in a new session
    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Open session
    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Login USER into the session so we can create a private object
    rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    CK_UTF8CHAR aesKeyLabel[] = "aes key used for Encryption/Decryption after wrapping";
    CK_ATTRIBUTE pKeyTemplate[] = { { CKA_LABEL, aesKeyLabel, sizeof(aesKeyLabel)-1 },
                                  };

    rv = CRYPTOKI_F_PTR(C_FindObjectsInit(hSession, &pKeyTemplate[0], 1));
    CPPUNIT_ASSERT(CKR_OK == rv);

    CK_OBJECT_HANDLE aesKeyFromToken = CK_INVALID_HANDLE;
    CK_ULONG ulObjectCount = 0;

    rv = CRYPTOKI_F_PTR(C_FindObjects(hSession, &aesKeyFromToken, 1, &ulObjectCount));
    CPPUNIT_ASSERT(CKR_OK == rv);

    CPPUNIT_ASSERT(1 == ulObjectCount);

    rv = CRYPTOKI_F_PTR(C_FindObjectsFinal(hSession));
    CPPUNIT_ASSERT(CKR_OK == rv);

    CK_MECHANISM mechanism = { CKM_AES_CTR, NULL_PTR, 0 };
    //Encryption with the key used for wrappping
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, &mechanism, aesKeyFromToken) );
    CPPUNIT_ASSERT(CKR_OBJECT_HANDLE_INVALID == rv);

    //Decryption with the key used for wrapping
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, &mechanism, aesKeyFromToken) );
    CPPUNIT_ASSERT(CKR_OBJECT_HANDLE_INVALID == rv);

    C_DestroyObject(hSession, aesKeyFromToken);

    C_CloseSession(hSession);
}
#ifdef WITH_AES_GCM
void SymmetricAlgorithmTests::testAesGcmEncryptDecrypt()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;
    const int blockSize(0x10);

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    // Initialize the library and start the test.
    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Open session
    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    // Login USER into the session so we can create a private object
    rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
    CPPUNIT_ASSERT(CKR_OK == rv);

    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

    rv = generateAesKey(hSession, IN_SESSION, IS_PUBLIC, hKey);
    CPPUNIT_ASSERT(CKR_OK == rv);

    const CK_MECHANISM_TYPE mechanismType = CKM_AES_GCM;
    CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
    CK_MECHANISM_PTR pMechanism((CK_MECHANISM_PTR)&mechanism);

    CK_BYTE gcmIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    };

    CK_BYTE gcmAAD[] = {
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2
    };

    // C_EncryptInit and C_DecryptInit with pIV NULL and ulIvLen not 0
    CK_GCM_PARAMS gcmParams =
    {
        NULL,
        sizeof(gcmIV),
        sizeof(gcmIV)*8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        16*8
    };

    pMechanism->pParameter = &gcmParams;
    pMechanism->ulParameterLen = sizeof(gcmParams);

    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

    // C_EncryptInit and C_DecryptInit with pIV not NULL and ulIvLen 0
    gcmParams.pIv = &gcmIV[0];
    gcmParams.ulIvLen = 0;
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

    // C_EncryptInit and C_DecryptInit with pIV NULL and ulIvLen 0
    gcmParams.pIv = NULL;
    encryptDecrypt(CKM_AES_GCM, blockSize, hSession, hKey, blockSize*NR_OF_BLOCKS_IN_TEST-1);
    encryptDecrypt(CKM_AES_GCM, blockSize, hSession, hKey, blockSize*NR_OF_BLOCKS_IN_TEST+1);
    encryptDecrypt(CKM_AES_GCM, blockSize, hSession, hKey, blockSize*NR_OF_BLOCKS_IN_TEST);

    // C_EncryptInit and C_DecryptInit with pAAD NULL and ulAADLen not 0
    gcmParams.pIv = &gcmIV[0];
    gcmParams.ulIvLen = sizeof(gcmIV);
    gcmParams.pAAD = NULL;

    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

    // C_EncryptInit and C_DecryptInit with pAAD not NULL and ulAADLen 0
    gcmParams.pAAD = &gcmAAD[0];
    gcmParams.ulAADLen = 0;
    rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);
    rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession, pMechanism, hKey) );
    CPPUNIT_ASSERT(CKR_ARGUMENTS_BAD == rv);

    // C_EncryptInit and C_DecryptInit with pAAD NULL and ulAADLen 0
    gcmParams.pAAD = NULL;
    encryptDecrypt(CKM_AES_GCM, blockSize, hSession, hKey, blockSize*NR_OF_BLOCKS_IN_TEST-1);
    encryptDecrypt(CKM_AES_GCM, blockSize, hSession, hKey, blockSize*NR_OF_BLOCKS_IN_TEST+1);
    encryptDecrypt(CKM_AES_GCM, blockSize, hSession, hKey, blockSize*NR_OF_BLOCKS_IN_TEST);
}
#endif
#endif