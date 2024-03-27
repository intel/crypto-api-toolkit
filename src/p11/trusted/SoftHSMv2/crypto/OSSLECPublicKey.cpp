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
 OSSLECPublicKey.cpp

 OpenSSL Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "DerUtil.h"
#include "OSSLECPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/decoder.h>
#include <string.h>
#include <mbusafecrt.h>

// Constructors
OSSLECPublicKey::OSSLECPublicKey()
{
    nid = NID_undef;
    pkey = NULL;
}

OSSLECPublicKey::OSSLECPublicKey(const EVP_PKEY* inPKEY)
{
    nid = NID_undef;
    pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLECPublicKey::~OSSLECPublicKey()
{
	EVP_PKEY_free(pkey);
    pkey = NULL;
}

// The type
/*static*/ const char* OSSLECPublicKey::type = "OpenSSL EC Public Key";

// Get the maximum possible signature length for the key
unsigned long OSSLECPublicKey::getOrderLength() const
{
    // getOutPutLength() multiplies the result by 2, so we are halving it here
    // Adding + 1 gives enough buffer if the returned signature length is odd
    return (getSignatureLength() + 1) / 2;
}

// Set from OpenSSL representation
void OSSLECPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
    char grpName[30];
    size_t groupNameLen = 0;
    if (EVP_PKEY_get_group_name(inPKEY, grpName, sizeof(grpName), &groupNameLen) != 0)
    {
        EC_GROUP *grp = EC_GROUP_new_by_curve_name(OBJ_sn2nid(grpName));
        if (grp != NULL)
        {
            ByteString inEC = OSSL::grp2ByteString(grp);
            setEC(inEC);
        }
    }

    // i2d_PUBKEY incorrectly does not const the key argument?!
    EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
    int len = i2d_PUBKEY(key, NULL);
    if (len <= 0)
    {
        // ERROR_MSG("Could not encode ECDSA public key");
        return;
    }
    ByteString der;
    der.resize(len);
    unsigned char *p = &der[0];
    i2d_PUBKEY(key, &p);
    ByteString raw;
    raw.resize(len);
    memcpy_s(&raw[0], len, &der[0], len);
    setQ(DERUTIL::raw2Octet(raw));
}

// Check if the key is of the given type
bool OSSLECPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC public key components
void OSSLECPublicKey::setEC(const ByteString& inEC)
{
    nid = OSSL::byteString2oid(inEC);
	ECPublicKey::setEC(inEC);

    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
}

void OSSLECPublicKey::setQ(const ByteString& inQ)
{
	ECPublicKey::setQ(inQ);

    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLECPublicKey::getOSSLKey()
{
    if (pkey == NULL) createOSSLKey();
    return pkey;
}

void OSSLECPublicKey::createOSSLKey()
{
    if (pkey != NULL) return;

	ByteString der = DERUTIL::octet2Raw(q);
	size_t len = der.size();
	if (len == 0) return;
    const unsigned char *p = &der[0];
    size_t dataLen = der.size();
    OSSL_DECODER_CTX* ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "EC",
                                        EVP_PKEY_PUBLIC_KEY, NULL, NULL);

    if (!ctx)
    {
        return;
    }
    (void)OSSL_DECODER_from_data(ctx, &p, &dataLen);
    OSSL_DECODER_CTX_free(ctx);
}

unsigned long OSSLECPublicKey::getSignatureLength() const
{
    if (pkey == NULL)
    {
        ByteString der = DERUTIL::octet2Raw(q);
        size_t len = der.size();
        if (len == 0) return 0;
        const unsigned char *p = &der[0];
        size_t dataLen = len;
        EVP_PKEY *tmpPKEY = NULL;
        OSSL_DECODER_CTX* ctx = OSSL_DECODER_CTX_new_for_pkey(&tmpPKEY, "DER", NULL, "EC",
                                                              EVP_PKEY_PUBLIC_KEY, NULL, NULL);
        if (!ctx)
        {
            return 0;
        }
        (void)OSSL_DECODER_from_data(ctx, &p, &dataLen);
        OSSL_DECODER_CTX_free(ctx);
        unsigned long sigLen = (unsigned long)EVP_PKEY_size(tmpPKEY);
        EVP_PKEY_free(tmpPKEY);
        return sigLen;
    }

    return (unsigned long)EVP_PKEY_size(pkey);
}
#endif
