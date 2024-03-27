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
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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

// TODO: Store context in securely allocated memory

/*****************************************************************************
 OSSLEVPMacAlgorithm.cpp

 OpenSSL MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPMacAlgorithm.h"
#include "OSSLComp.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>

// Destructor
OSSLEVPMacAlgorithm::~OSSLEVPMacAlgorithm()
{
    EVP_MAC_CTX_free(curCTX);
}

// Signing functions
bool OSSLEVPMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Initialize the context
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	curCTX = EVP_MAC_CTX_new(mac);
	if (curCTX == NULL)
	{
		// ERROR_MSG("Failed to allocate space for HMAC_CTX");

		return false;
	}
	EVP_MAC_free(mac);

	OSSL_PARAM params[2], *p = params;
    char* hashAlgo = getHashAlgo();
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, hashAlgo, strlen(hashAlgo));
    *p = OSSL_PARAM_construct_end();

	// Initialize EVP signing
	//if (!HMAC_Init_ex(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), getEVPHash(), NULL))
	if (!EVP_MAC_init(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), params))
	{
		// ERROR_MSG("HMAC_Init failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}
	return true;
}

bool OSSLEVPMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	// The GOST implementation in OpenSSL will segfault if we update with zero length.
	if (dataToSign.size() == 0) return true;

	if (!EVP_MAC_update(curCTX, dataToSign.const_byte_str(), dataToSign.size()))
	{
		// ERROR_MSG("HMAC_Update failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	size_t outLen = 0;
	if (!EVP_MAC_final(curCTX, NULL, &outLen, 0))
	{
		// ERROR_MSG("EVP_MAC_final failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	signature.resize(outLen);

	if (!EVP_MAC_final(curCTX, &signature[0], &outLen, outLen))
	{
		// ERROR_MSG("HMAC_Final failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	signature.resize(outLen);

	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;

	return true;
}

// Verification functions
bool OSSLEVPMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Initialize the context
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	curCTX = EVP_MAC_CTX_new(mac);
	if (curCTX == NULL)
	{
		// ERROR_MSG("Failed to allocate space for HMAC_CTX");

		return false;
	}
	EVP_MAC_free(mac);

	OSSL_PARAM params[2], *p = params;
    char* hashAlgo = getHashAlgo();
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, hashAlgo, strlen(hashAlgo));
    *p = OSSL_PARAM_construct_end();

	// Initialize EVP signing
	//if (!HMAC_Init_ex(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), getEVPHash(), NULL))
	if (!EVP_MAC_init(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), params))
	{
		// ERROR_MSG("HMAC_Init failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	// The GOST implementation in OpenSSL will segfault if we update with zero length.
	if (originalData.size() == 0) return true;

	if (!EVP_MAC_update(curCTX, originalData.const_byte_str(), originalData.size()))
	{
		// ERROR_MSG("HMAC_Update failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	size_t outLen;
	if (!EVP_MAC_final(curCTX, NULL, &outLen, 0))
	{
		// ERROR_MSG("HMAC_Final failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}	
	macResult.resize(outLen);

	if (!EVP_MAC_final(curCTX, &macResult[0], &outLen, outLen))
	{
		// ERROR_MSG("HMAC_Final failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;

	return macResult == signature;
}

