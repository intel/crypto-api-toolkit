/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

/*****************************************************************************
 p11Defines.h

 Set the PKCS#11 macros.
 *****************************************************************************/

#ifndef P11DEFINES_H
#define P11DEFINES_H

// 1. CK_PTR: The indirection string for making a pointer to an
// object.

#define CK_PTR *

// 2. CK_DECLARE_FUNCTION(returnType, name): A macro which makes
// an importable Cryptoki library function declaration out of a
// return type and a function name.

#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name

// 3. CK_DECLARE_FUNCTION_POINTER(returnType, name): A macro
// which makes a Cryptoki API function pointer declaration or
// function pointer type declaration out of a return type and a
// function name.

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)

// 4. CK_CALLBACK_FUNCTION(returnType, name): A macro which makes
// a function pointer type for an application callback out of
// a return type for the callback and a name for the callback.

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

// 5. NULL_PTR: This macro is the value of a NULL pointer.

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#define CKA_VALUE_KEY_BUFFER   0x00000167UL

#define CKM_VENDOR_DEFINED_INVALID 0xFFFFFFFFUL
#define CKK_INVALID                0xFFFFFFFFUL
#define CKO_INVALID                0xFFFFFFFFUL
#define CKU_USER_INVALID           0xFFFFFFFFUL
#define INVALID_SLOT_ID            0xFFFFFFFFUL
#define CKS_INVALID                0xFFFFFFFFUL

// Crypto API Toolkit custom CKMs
#define CKM_AES_PBIND                         0x0000210BUL
#define CKM_RSA_PBIND_EXPORT                  0x0000210CUL
#define CKM_EXPORT_RSA_PUBLIC_KEY             0x0000210DUL
#define CKM_IMPORT_RSA_PUBLIC_KEY             0x0000210EUL
#define CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY  0x0000210FUL
#define CKM_RSA_PBIND_IMPORT                  0x00002110UL
#define CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY 0x00002111UL

// Crypto API Toolkit custom CKMs for HMAC
#define CKM_SHA256_HMAC_AES_KEYID      0x000002A2UL
#define CKM_SHA512_HMAC_AES_KEYID      0x000002A3UL

// Crypto API Toolkit custom error codes
#define CKR_DEVICE_TABLE_FULL            0x80000001UL
#define CKR_CIPHER_OPERATION_FAILED      0x80000002UL
#define CKR_PLATFORM_SEAL_UNSEAL_FAILED  0x80000003UL
#define CKR_POWER_STATE_INVALID          0x80000004UL
#define CKR_USER_PIN_ALREADY_INITIALIZED 0x80000005UL
#define CKR_OPERATION_NOT_PERMITTED      0x80000006UL
#define CKR_IMPORT_RAW_KEY_UNSUPPORTED   0x80000007UL

enum QuoteSignatureType
{
    INVALID_SIGNATURE    = 0,
    UNLINKABLE_SIGNATURE = 1,
    LINKABLE_SIGNATURE   = 2
};

typedef struct CK_HMAC_AES_KEYID_PARAMS {
    CK_ULONG ulKeyID;
} CK_HMAC_AES_KEYID_PARAMS;

typedef CK_HMAC_AES_KEYID_PARAMS CK_PTR CK_HMAC_AES_KEYID_PARAMS_PTR;

typedef struct CK_RSA_PUBLIC_KEY_PARAMS {
    CK_ULONG ulExponentLen;
    CK_ULONG ulModulusLen;
} CK_RSA_PUBLIC_KEY_PARAMS;

typedef CK_RSA_PUBLIC_KEY_PARAMS CK_PTR CK_RSA_PUBLIC_KEY_PARAMS_PTR;

typedef struct CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS {
    CK_BYTE_PTR       pSpid;
    CK_ULONG          ulSpidLen;
    CK_BYTE_PTR       pSigRL;
    CK_ULONG          ulSigRLLen;
    CK_ULONG          ulQuoteSignatureType;
} CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS;

typedef CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS CK_PTR CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR;

typedef struct CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS {
    CK_LONG qlPolicy;
} CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS;

typedef CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS CK_PTR CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR;

typedef struct CK_RSA_PBIND_IMPORT_PARAMS {
    CK_BYTE_PTR   pPlatformBoundKey;
    CK_ULONG      ulPlatformBoundKeyLen;
} CK_RSA_PBIND_IMPORT_PARAMS;

typedef CK_RSA_PBIND_IMPORT_PARAMS CK_PTR CK_RSA_PBIND_IMPORT_PARAMS_PTR;



#endif // P11DEFINES_H

