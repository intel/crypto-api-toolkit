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
 OSSLECPrivateKey.h

 OpenSSL Elliptic Curve private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLECPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLECPRIVATEKEY_H

#include "config.h"
#include "ECPrivateKey.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

class OSSLECPrivateKey : public ECPrivateKey
{
public:
	// Constructors
	OSSLECPrivateKey();

	OSSLECPrivateKey(const EVP_PKEY* inPKEY);

	// Destructor
	virtual ~OSSLECPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the EC private key components
	virtual void setD(const ByteString& inD);

	// Setters for the EC public key components
	virtual void setEC(const ByteString& inEC);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Set from OpenSSL representation
	virtual void setFromOSSL(const EVP_PKEY* inPKEY);

	// Retrieve the OpenSSL representation of the key
	EVP_PKEY* getOSSLKey();

private:
	// The internal OpenSSL representation
    int nid;
    EVP_PKEY* pkey;

    // Create the OpenSSL representation of the key
	void createOSSLKey();

    unsigned long getSignatureLength() const;
};

#endif // !_SOFTHSM_V2_OSSLECPRIVATEKEY_H

