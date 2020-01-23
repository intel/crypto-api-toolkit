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

#ifndef KEYMANAGEMENT_H
#define KEYMANAGEMENT_H

#include "cryptoki.h"

//---------------------------------------------------------------------------------------------
/**
* Generates a symmetric key.
* @param  hSession   The session handle.
* @param  pMechanism The mechanism to be used for key generation.
* @param  pTemplate  The template containing attributes to be set for the key generated.
* @param  ulCount    Size of template passed.
* @param  phKey      The pointer that holds the key handle associated with the generated key.
* @return CK_RV      CKR_OK if the key is successfully generated, error code otherwise.
*/
CK_RV generateKey(CK_SESSION_HANDLE    hSession,
                  CK_MECHANISM_PTR     pMechanism,
                  CK_ATTRIBUTE_PTR     pTemplate,
                  CK_ULONG             ulCount,
                  CK_OBJECT_HANDLE_PTR phKey);

//---------------------------------------------------------------------------------------------
/**
* Generates an asymmetric key pair.
* @param  hSession                   The session handle.
* @param  pMechanism                 The mechanism to be used for key generation.
* @param  pPublicKeyTemplate         The template containing attributes to be set for the public key generated.
* @param  ulPublicKeyAttributeCount  Size of public key template passed.
* @param  pPrivateKeyTemplate        The template containing attributes to be set for the private key generated.
* @param  ulPrivateKeyAttributeCount Size of private key template passed.
* @param  phPublicKey                The pointer that holds the public key handle associated with the generated public key.
* @param  phPrivateKey               The pointer that holds the private key handle associated with the generated private key.
* @return CK_RV                      CKR_OK if the key is successfully generated, error code otherwise.
*/
CK_RV generateKeyPair(CK_SESSION_HANDLE    hSession,
                      CK_MECHANISM_PTR     pMechanism,
                      CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
                      CK_ULONG             ulPublicKeyAttributeCount,
                      CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
                      CK_ULONG             ulPrivateKeyAttributeCount,
                      CK_OBJECT_HANDLE_PTR phPublicKey,
                      CK_OBJECT_HANDLE_PTR phPrivateKey);

//---------------------------------------------------------------------------------------------
/**
* Wraps a key with another key.
* @param  hSession          The session handle.
* @param  pMechanism        The mechanism to be used for key wrapping.
* @param  hWrappingKey      The wrapping key handle.
* @param  hKey              The key handle for the key to be wrapped.
* @param  pWrappedKey       Pointer that holds the wrapped key buffer.
* @param  pulWrappedKeyLen  Pointer that holds the size of wrapped key buffer.
* @return CK_RV             CKR_OK if the key is successfully wrapped, error code otherwise.
*/
CK_RV wrapKey(CK_SESSION_HANDLE hSession,
              CK_MECHANISM_PTR  pMechanism,
              CK_OBJECT_HANDLE  hWrappingKey,
              CK_OBJECT_HANDLE  hKey,
              CK_BYTE_PTR       pWrappedKey,
              CK_ULONG_PTR      pulWrappedKeyLen);

//---------------------------------------------------------------------------------------------
/**
* Unwraps a key.
* @param  hSession         The session handle.
* @param  pMechanism       The mechanism to be used for key unwrapping.
* @param  hUnwrappingKey   The key handle to be used for unwrapping.
* @param  pWrappedKey      Pointer that holds the wrapped key buffer.
* @param  ulWrappedKeyLen  The size of wrapped key buffer.
* @param  pTemplate        The template containing attributes to be set for the unwrapped key.
* @param  ulCount          Size of template passed.
* @param  hKey             The key handle of unwrapped key.
* @return CK_RV            CKR_OK if the key is successfully unwrapped, error code otherwise.
*/
CK_RV unwrapKey(CK_SESSION_HANDLE    hSession,
                CK_MECHANISM_PTR     pMechanism,
                CK_OBJECT_HANDLE     hUnwrappingKey,
                CK_BYTE_PTR          pWrappedKey,
                CK_ULONG             ulWrappedKeyLen,
                CK_ATTRIBUTE_PTR     pTemplate,
                CK_ULONG             ulCount,
                CK_OBJECT_HANDLE_PTR hKey);


CK_RV deriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

#endif //KEYMANAGEMENT_H

