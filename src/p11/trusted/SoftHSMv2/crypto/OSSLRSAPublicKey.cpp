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
 OSSLRSAPublicKey.cpp

 OpenSSL RSA public key class
 *****************************************************************************/

#include "config.h"
#include "OSSLComp.h"
#include "OSSLRSAPublicKey.h"
#include "OSSLUtil.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif

// Constructors
OSSLRSAPublicKey::OSSLRSAPublicKey()
{
	rsa = NULL;
}

OSSLRSAPublicKey::OSSLRSAPublicKey(const EVP_PKEY* inPKEY)
{
	rsa = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLRSAPublicKey::~OSSLRSAPublicKey()
{
	EVP_PKEY_free(rsa);
}

// The type
/*static*/ const char* OSSLRSAPublicKey::type = "OpenSSL RSA Public Key";

// Check if the key is of the given type
bool OSSLRSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Set from OpenSSL representation
void OSSLRSAPublicKey::setFromOSSL(const EVP_PKEY* pkey)
{
	BIGNUM* bn_n = NULL;
	BIGNUM* bn_e = NULL;

    if ((EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) == 0) || !bn_n)
    {
        return;
    }

    if ((EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e) == 0) || !bn_e)
    {
        return;
    }

    ByteString inN = OSSL::bn2ByteString(bn_n);
    setN(inN);

    ByteString inE = OSSL::bn2ByteString(bn_e);
		setE(inE);
}

// Setters for the RSA public key components
void OSSLRSAPublicKey::setN(const ByteString& inN)
{
	RSAPublicKey::setN(inN);

	if (rsa)
	{
        EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPublicKey::setE(const ByteString& inE)
{
	RSAPublicKey::setE(inE);

	if (rsa)
	{
        EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLRSAPublicKey::getOSSLKey()
{
	if (rsa == NULL) createOSSLKey();

	return rsa;
}

// Create the OpenSSL representation of the key
void OSSLRSAPublicKey::createOSSLKey()
{
	if (rsa != NULL) return;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
    {
        //EVP_PKEY_CTX_free(ctx);
        return;
    }

	BIGNUM* bn_n = OSSL::byteString2bn(n);
	BIGNUM* bn_e = OSSL::byteString2bn(e);

    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;

    if ((tmpl = OSSL_PARAM_BLD_new()) == NULL
        || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_n)
        || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_e)
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
    {
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &rsa, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        rsa = NULL;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
}
