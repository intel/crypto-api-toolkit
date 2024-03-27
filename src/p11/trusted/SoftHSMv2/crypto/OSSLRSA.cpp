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
 OSSLRSA.cpp

 OpenSSL RSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLRSA.h"
#include "OSSLUtil.h"
#include "CryptoFactory.h"
#include "RSAParameters.h"
#include "OSSLRSAKeyPair.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// Constructor
OSSLRSA::OSSLRSA()
{
}

// Destructor
OSSLRSA::~OSSLRSA()
{
}

// Signing functions
bool OSSLRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		   ByteString& signature, const AsymMech::Type mechanism,
		   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
    // Check if the private key is the right type
    if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
    {
        return false;
    }

    // In case of PKCS #1 signing the length of the input data may not exceed 40% of the
    // modulus size
    OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;

    size_t sigLen = osslKey->getN().size();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(osslKey->getOSSLKey(), NULL);

    if (!ctx)
    {
        return false;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Separate implementation for RSA PKCS #1 signing without hash computation

		size_t allowedLen = osslKey->getN().size() - 11;

		if (dataToSign.size() > allowedLen)
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		const RSA_PKCS_PSS_PARAMS *pssParam = (RSA_PKCS_PSS_PARAMS*)param;

		// Separate implementation for RSA PKCS #1 signing without hash computation

		if (pssParam == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

		size_t allowedLen;
		const EVP_MD* hash = NULL;

		switch (pssParam->hashAlg)
		{
		case HashAlgo::SHA1:
			hash = EVP_sha1();
			allowedLen = 20;
			break;
		case HashAlgo::SHA224:
			hash = EVP_sha224();
			allowedLen = 28;
			break;
		case HashAlgo::SHA256:
			hash = EVP_sha256();
			allowedLen = 32;
			break;
		case HashAlgo::SHA384:
			hash = EVP_sha384();
			allowedLen = 48;
			break;
		case HashAlgo::SHA512:
			hash = EVP_sha512();
			allowedLen = 64;
			break;
		default:
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

		if (dataToSign.size() != allowedLen)
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

		if (pssParam->sLen > ((privateKey->getBitLength()+6)/8-2-allowedLen))
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }

        if (hash && (EVP_PKEY_CTX_set_signature_md(ctx, hash) <= 0))
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Separate implementation for raw RSA signing

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

		if (dataToSign.size() != osslKey->getN().size())
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }
	}
	else
	{
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
	}

    signature.resize(osslKey->getN().size());

    int ret = EVP_PKEY_sign(ctx, &signature[0], &sigLen, (unsigned char*) dataToSign.const_byte_str(), dataToSign.size());

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if (ret <= 0)
    {
        return false;
    }

    signature.resize(sigLen);

    return true;
}

bool OSSLRSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
		       const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

    OSSL_PARAM params[2], *p = params;
    std::string osslPadding;
    std::string hashAlgo;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_MD5;
            break;
        case AsymMech::RSA_SHA1_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}

			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((privateKey->getBitLength()+6)/8-2-20))
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((privateKey->getBitLength()+6)/8-2-28))
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((privateKey->getBitLength()+6)/8-2-32))
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((privateKey->getBitLength()+6)/8-2-48))
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((privateKey->getBitLength()+6)/8-2-64))
			{
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_512;
			break;
		default:
			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, osslPadding.data(), 0);
    *p = OSSL_PARAM_construct_end();

    sign_ver_ctx = EVP_MD_CTX_new();

    if (!sign_ver_ctx)
    {
        return false;
    }

    OSSLRSAPrivateKey* pk = (OSSLRSAPrivateKey*) privateKey;
    int ret = EVP_DigestSignInit_ex(sign_ver_ctx, NULL, hashAlgo.c_str(), NULL, NULL,
                                  pk->getOSSLKey(), params);

    if (!ret)
    {
        EVP_MD_CTX_free(sign_ver_ctx);
        sign_ver_ctx = NULL;
        return false;
    }

	return true;
}

bool OSSLRSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

    if (!sign_ver_ctx)
    {
        return false;
    }

    int ret = EVP_DigestSignUpdate(sign_ver_ctx, (unsigned char*) dataToSign.const_byte_str(), dataToSign.size());
    if (!ret)
    {
        EVP_MD_CTX_free(sign_ver_ctx);
        sign_ver_ctx = NULL;
        return false;
    }

	return true;
}

bool OSSLRSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLRSAPrivateKey* pk = (OSSLRSAPrivateKey*) currentPrivateKey;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	signature.resize(pk->getN().size());

	// Perform the signature operation
	size_t sigLen = signature.size();

	int ret = EVP_DigestSignFinal(sign_ver_ctx, &signature[0], &sigLen);

    EVP_MD_CTX_free(sign_ver_ctx);
    sign_ver_ctx = NULL;

    if (!ret)
    {
        return false;
    }

    return true;
}

// Verification functions
bool OSSLRSA::verify(PublicKey* publicKey, const ByteString& originalData,
		     const ByteString& signature, const AsymMech::Type mechanism,
		     const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
    // Check if the public key is the right type
    if (!publicKey->isOfType(OSSLRSAPublicKey::type))
    {
        return false;
    }

    // Perform the RSA public key operation
    OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;

    EVP_PKEY* rsa = osslKey->getOSSLKey();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa, NULL);

    if (!ctx)
    {
        return false;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Specific implementation for PKCS #1 only verification; originalData is assumed to contain
		// a digestInfo structure and verification is performed by comparing originalData to the data
		// recovered from the signature

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		const RSA_PKCS_PSS_PARAMS *pssParam = (RSA_PKCS_PSS_PARAMS*)param;

		if (pssParam == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) == 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }

		size_t allowedLen;
		const EVP_MD* hash = NULL;

		switch (pssParam->hashAlg)
		{
		case HashAlgo::SHA1:
			hash = EVP_sha1();
			allowedLen = 20;
			break;
		case HashAlgo::SHA224:
			hash = EVP_sha224();
			allowedLen = 28;
			break;
		case HashAlgo::SHA256:
			hash = EVP_sha256();
			allowedLen = 32;
			break;
		case HashAlgo::SHA384:
			hash = EVP_sha384();
			allowedLen = 48;
			break;
		case HashAlgo::SHA512:
			hash = EVP_sha512();
			allowedLen = 64;
			break;
		default:
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}

        if (hash)
        {
            if (EVP_PKEY_CTX_set_signature_md(ctx, hash) == 0)
            {
                EVP_PKEY_CTX_free(ctx);
                ctx = NULL;
                return false;
            }
        }

		if (pssParam->sLen > ((osslKey->getBitLength()+6)/8-2-allowedLen))
		{
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
		}
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Specific implementation for raw RSA verifiction; originalData is assumed to contain the
		// full input data used to compute the signature and verification is performed by comparing
		// originalData to the data recovered from the signature

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) == 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }
	}
	else
	{
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}

    int ret = EVP_PKEY_verify(ctx, (unsigned char*) signature.const_byte_str(), signature.size(), (unsigned char*) originalData.const_byte_str(), originalData.size());

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if (!ret)
    {
        return false;
    }

    return true;
}

bool OSSLRSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

    OSSL_PARAM params[2], *p = params;
    std::string osslPadding;
    std::string hashAlgo;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_MD5;
            break;
        case AsymMech::RSA_SHA1_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((publicKey->getBitLength()+6)/8-2-20))
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((publicKey->getBitLength()+6)/8-2-28))
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}

			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((publicKey->getBitLength()+6)/8-2-32))
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((publicKey->getBitLength()+6)/8-2-48))
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			if (((RSA_PKCS_PSS_PARAMS*) param)->sLen > ((publicKey->getBitLength()+6)/8-2-64))
			{
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
            osslPadding = OSSL_PKEY_RSA_PAD_MODE_PSS;
            hashAlgo = OSSL_DIGEST_NAME_SHA2_512;
			break;
		default:
			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, osslPadding.data(), 0);
    *p = OSSL_PARAM_construct_end();

    sign_ver_ctx = EVP_MD_CTX_new();

    if (!sign_ver_ctx)
    {
        return false;
    }

    OSSLRSAPublicKey* pk = (OSSLRSAPublicKey*) publicKey;
    int r = EVP_DigestVerifyInit_ex(sign_ver_ctx, NULL, hashAlgo.c_str(), NULL, NULL,
                                  pk->getOSSLKey(), params);
    if (!r)
    {
        EVP_MD_CTX_free(sign_ver_ctx);
        return false;
    }

	return true;
}

bool OSSLRSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

    if (!sign_ver_ctx)
    {
        return false;
    }

    int r = EVP_DigestVerifyUpdate(sign_ver_ctx, (unsigned char*) originalData.const_byte_str(), originalData.size());
    if (!r)
    {
        EVP_MD_CTX_free(sign_ver_ctx);
        return false;
    }

	return true;
}

bool OSSLRSA::verifyFinal(const ByteString& signature)
{
	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
	size_t sigLen = signature.size();

	int result = EVP_DigestVerifyFinal(sign_ver_ctx, (unsigned char*) signature.const_byte_str(), sigLen);
    if (!result)
    {
        EVP_MD_CTX_free(sign_ver_ctx);
        return false;
    }

    return true;
}

// Encryption functions
bool OSSLRSA::encrypt(PublicKey* publicKey, const ByteString& data,
		      ByteString& encryptedData, const AsymMech::Type padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		return false;
	}

	// Retrieve the OpenSSL key object
	EVP_PKEY* pk = ((OSSLRSAPublicKey*) publicKey)->getOSSLKey();
    if (!pk)
    {
        return false;
    }

	// Determine the OpenSSL padding algorithm
	int osslPadding = 0;

	if (padding == AsymMech::RSA_PKCS)
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 11
		if (data.size() > (size_t) (EVP_PKEY_get_size(pk) - 11))
		{
			return false;
		}

		osslPadding = RSA_PKCS1_PADDING;
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP)
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 41
		if (data.size() > (size_t) (EVP_PKEY_get_size(pk) - 41))
		{
			return false;
		}

		osslPadding = RSA_PKCS1_OAEP_PADDING;
	}
	else if (padding == AsymMech::RSA)
	{
		// The size of the input data should be exactly equal to the modulus length
		if (data.size() != (size_t) EVP_PKEY_get_size(pk))
		{
			return false;
		}

		osslPadding = RSA_NO_PADDING;
	}
	else
	{
		return false;
	}

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);

    if (!ctx)
    {
        return false;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

    // Set the RSA padding mode
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, osslPadding) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

    size_t encryptedDataLen = EVP_PKEY_get_size(pk);
    encryptedData.resize(encryptedDataLen);

    int ret = EVP_PKEY_encrypt(ctx, &encryptedData[0], &encryptedDataLen, (unsigned char*) data.const_byte_str(), data.size());

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if (ret <= 0)
	{
		return false;
	}

	return true;
}

// Decryption functions
bool OSSLRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
		      ByteString& data, const AsymMech::Type mechType, const CK_MECHANISM_TYPE hashAlgo)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
	{
		return false;
	}

	// Retrieve the OpenSSL key object
	EVP_PKEY* pk = ((OSSLRSAPrivateKey*) privateKey)->getOSSLKey();
    if (!pk)
    {
        return false;
    }

	// Check the input size
	if (encryptedData.size() != (size_t) EVP_PKEY_get_size(pk))
	{
        EVP_PKEY_free(pk);
		return false;
	}

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);

    if (!ctx)
    {
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

	// Determine the OpenSSL padding algorithm
	int osslPadding = 0;

	switch (mechType)
	{
		case AsymMech::RSA_PKCS:
			osslPadding = RSA_PKCS1_PADDING;
			break;
		case AsymMech::RSA_PKCS_OAEP:
			osslPadding = RSA_PKCS1_OAEP_PADDING;
			break;
		case AsymMech::RSA:
			osslPadding = RSA_NO_PADDING;
			break;
		default:
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
			return false;
	}

    // Set the RSA padding mode
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, osslPadding) <= 0)
    {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
        return false;
    }

    if (mechType == AsymMech::RSA_PKCS_OAEP)
    {
        const EVP_MD *md;
        switch (hashAlgo)
        {
            case CKM_SHA_1:
                md = EVP_sha1();
                break;
            case CKM_SHA256:
                md = EVP_sha256();
                break;
            case CKM_SHA384:
                md = EVP_sha384();
                break;
            default:
                EVP_PKEY_CTX_free(ctx);
                ctx = NULL;
                return false;
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            return false;
        }
    }

	size_t outLen = (size_t) EVP_PKEY_get_size(pk);
	data.resize(EVP_PKEY_get_size(pk));

    int ret = EVP_PKEY_decrypt(ctx, &data[0], &outLen, (unsigned char*) encryptedData.const_byte_str(), encryptedData.size());

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if (ret <= 0)
	{
		return false;
	}

    data.resize(outLen);

	return true;
}

// Key factory
bool OSSLRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(RSAParameters::type))
	{
		return false;
	}

	RSAParameters* params = (RSAParameters*) parameters;

	if (params->getBitLength() < getMinKeySize() || params->getBitLength() > getMaxKeySize())
	{
		return false;
	}

	if (params->getBitLength() < 1024)
	{
        return false;
	}

	// Retrieve the desired public exponent
	unsigned long e = params->getE().long_val();

	// Check the public exponent
	if ((e == 0) || (e % 2 != 1))
	{
		return false;
	}

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
    {
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, params->getBitLength()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        return false;
    }

	BIGNUM* bn_e = OSSL::byteString2bn(params->getE());
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn_e) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        BN_free(bn_e);
        ctx = NULL;
        bn_e = NULL;
        return false;
    }

    EVP_PKEY *rsa = NULL;;
    if (EVP_PKEY_generate(ctx, &rsa) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        BN_free(bn_e);
        ctx = NULL;
        bn_e = NULL;
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    BN_free(bn_e);
    ctx = NULL;
    bn_e = NULL;

    // Create an asymmetric key-pair object to return
    OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

    ((OSSLRSAPublicKey*) kp->getPublicKey())->setFromOSSL(rsa);
    ((OSSLRSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(rsa);

    *ppKeyPair = kp;

    // Release the key
    EVP_PKEY_free(rsa);

    return true;
}

unsigned long OSSLRSA::getMinKeySize()
{
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_FIPS
    // OPENSSL_RSA_FIPS_MIN_MODULUS_BITS is 1024
    return 1024;
#else
    return 512;
#endif
#endif // Unsupported by Crypto API Toolkit
    return 2048; //minimum key size per guidelines
}

unsigned long OSSLRSA::getMaxKeySize()
{
    return OPENSSL_RSA_MAX_MODULUS_BITS;
}

bool OSSLRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
    // Check input
    if ((ppKeyPair == NULL) ||
            (serialisedData.size() == 0))
    {
        return false;
    }

    ByteString dPub = ByteString::chainDeserialise(serialisedData);
    ByteString dPriv = ByteString::chainDeserialise(serialisedData);

    OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

    bool rv = true;

    if (!((RSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
    {
        rv = false;
    }

    if (!((RSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
    {
        rv = false;
    }

    if (!rv)
    {
        delete kp;
        kp = NULL;

        return false;
    }

    *ppKeyPair = kp;

    return true;
}

bool OSSLRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
    // Check input
    if ((ppPublicKey == NULL) ||
            (serialisedData.size() == 0))
    {
        return false;
    }

    OSSLRSAPublicKey* pub = new OSSLRSAPublicKey();

    if (!pub->deserialise(serialisedData))
    {
        delete pub;

        return false;
    }

    *ppPublicKey = pub;

    return true;
}

bool OSSLRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLRSAPrivateKey* priv = new OSSLRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLRSA::newPublicKey()
{
	return (PublicKey*) new OSSLRSAPublicKey();
}

PrivateKey* OSSLRSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLRSAPrivateKey();
}

AsymmetricParameters* OSSLRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

bool OSSLRSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	RSAParameters* params = new RSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
