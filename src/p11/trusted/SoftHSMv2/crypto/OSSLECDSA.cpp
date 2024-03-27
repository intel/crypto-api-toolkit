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
 * Copyright (c) 2010 SURFnet bv
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
 OSSLECDSA.cpp

 OpenSSL ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "OSSLECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Signing functions
bool OSSLECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::ECDSA)
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		return false;
	}

	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		return false;
	}

	// Perform the signature operation
	size_t len = pk->getOrderLength() * 2;

	if (len == 0)
	{
		return false;
	}

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx)
    {
        return false;
    }

    const char sig_name[] = "SHA2-256";
    if (!EVP_DigestSignInit_ex(ctx, NULL, sig_name, NULL, NULL, pkey, NULL))
	{
		EVP_MD_CTX_free(ctx);
        ctx = NULL;
		return false;
	}

	signature.resize(len);
	memset(&signature[0], 0, len);

	int ret = EVP_DigestSign(ctx, &signature[0], &len, dataToSign.const_byte_str(), dataToSign.size());

    EVP_MD_CTX_free(ctx);
    ctx = NULL;

	if (!ret)
	{
		return false;
	}

	signature.resize(len);

	return true;
}

bool OSSLECDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	// ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool OSSLECDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	// ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool OSSLECDSA::signFinal(ByteString& /*signature*/)
{
	// ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::ECDSA)
	{
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLECPublicKey::type))
	{
		return false;
	}

	OSSLECPublicKey* pk = (OSSLECPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		return false;
	}

	// Perform the verify operation
	size_t len = pk->getOrderLength() * 2;
	if (len == 0)
	{
		return false;
	}

	if (signature.size() > len)
	{
		return false;
	}

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx)
    {
        return false;
    }

    const char sig_name[] = "SHA2-256";
    if (!EVP_DigestVerifyInit_ex(ctx, NULL, sig_name, NULL, NULL, pkey, NULL))
	{
		EVP_MD_CTX_free(ctx);
        ctx = NULL;
		return false;
	}

	int ret = EVP_DigestVerify(ctx, signature.const_byte_str(), signature.size(), originalData.const_byte_str(), originalData.size());

    EVP_MD_CTX_free(ctx);
    ctx = NULL;

	if (!ret)
	{
		return false;
	}

	return true;
}

bool OSSLECDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	// ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool OSSLECDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	// ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool OSSLECDSA::verifyFinal(const ByteString& /*signature*/)
{
	// ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	// ERROR_MSG("ECDSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/,
			const CK_MECHANISM_TYPE /* hashAlgo */)
{
	// ERROR_MSG("ECDSA does not support decryption");

	return false;
}

// Key factory
bool OSSLECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		// ERROR_MSG("Invalid parameters supplied for ECDSA key generation");

		return false;
	}

    ECParameters* params = (ECParameters*) parameters;
	EC_GROUP* grp = OSSL::byteString2grp(params->getEC());

    if (grp == NULL)
    {
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_keygen_init(ctx);

    if (!ctx)
    {
        return false;
    }

    int curve_id = EC_GROUP_get_curve_name(grp);
    OSSL_PARAM ossl_params[2];

    if (curve_id == NID_X9_62_prime256v1)
    {
        ossl_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"P-256", 0);
    }
    else if (curve_id == NID_secp384r1)
    {
        ossl_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"P-384", 0);
    }
    else if (curve_id == NID_secp521r1)
    {
        ossl_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"P-521", 0);
    }
    else
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

    ossl_params[1] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(ctx, ossl_params))
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

	// Create an asymmetric key-pair object to return
	OSSLECKeyPair* kp = new OSSLECKeyPair();

	((OSSLECPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLECPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

unsigned long OSSLECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLECKeyPair* kp = new OSSLECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;

		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLECPublicKey* pub = new OSSLECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLECPrivateKey* priv = new OSSLECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLECDSA::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLECDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
