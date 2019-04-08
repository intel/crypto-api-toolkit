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

#ifndef ASYMMETRIC_PROVIDER_H
#define ASYMMETRIC_PROVIDER_H

#include <memory>
#include <mutex>

#include "CryptoEnclaveDefs.h"
#include "Constants.h"
#include "SessionHandleCache.h"
#include "AsymmetricKeyHandleCache.h"
#include "p11Defines.h"
#include "AttributeHelpers.h"

namespace P11Crypto
{
    class AsymmetricProvider
    {
    public:

        static std::shared_ptr<AsymmetricProvider> getAsymmetricProvider();

        AsymmetricProvider() = default;

        /**
        * Generates an asymmetric key pair
        * @param    hSession                    The session handle
        * @param    pPublicKeyTemplate          Template for the public key
        * @param    ulPublicKeyAttributeCount   The size of public key template
        * @param    pPrivateKeyTemplate         Template for the private key
        * @param    ulPrivateKeyAttributeCount  The size of private key template
        * @param    phPublicKey                 The key handle for public key
        * @param    phPrivateKey                The key handle for private key
        * @param    publicKeyAttributes         Attribute structure holding all attributes set for public key
        * @param    privateKeyAttributes        Attribute structure holding all attributes set for private key
        * @return   CK_RV                       CKR_OK if operation is successful, error code otherwise
        */
        CK_RV generateKeyPair(const CK_SESSION_HANDLE& hSession,
                              const CK_ATTRIBUTE_PTR   pPublicKeyTemplate,
                              const CK_ULONG&          ulPublicKeyAttributeCount,
                              const CK_ATTRIBUTE_PTR   pPrivateKeyTemplate,
                              const CK_ULONG&          ulPrivateKeyAttributeCount,
                              CK_OBJECT_HANDLE_PTR     phPublicKey,
                              CK_OBJECT_HANDLE_PTR     phPrivateKey,
                              Attributes&              publicKeyAttributes,
                              Attributes&              privateKeyAttributes);

        /**
        * Encrypts a buffer using the public key
        * @param    keyHandle                  The public key handle
        * @param    sourceBuffer               The input buffer to be encrypted
        * @param    sourceBufferLen            The length of the input buffer
        * @param    destBuffer                 The destination buffer where the encrypted output goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferRequiredLength   The length of destination buffer that will be required to hold encrypted output
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV encrypt(const uint32_t&   keyHandle,
                      const uint8_t*    sourceBuffer,
                      const uint32_t&   sourceBufferLen,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t&         destBufferRequiredLength);

        /**
        * Decrypts a buffer using the private key
        * @param    keyHandle                  The private key Id from provider
        * @param    encryptedBuffer            The input buffer to be decrypted
        * @param    encryptedBufferLen         The length of the input buffer
        * @param    destBuffer                 The destination buffer where the decrypted output goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferRequiredLength   The length of destination buffer that will be required to hold decrypted output
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV decrypt(const uint32_t&   keyHandle,
                      const uint8_t*    encryptedBuffer,
                      const uint32_t&   encryptedBufferLen,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t&         destBufferRequiredLength);

        /**
        * Signs a buffer using the private key
        * @param    keyHandle                  The private key handle
        * @param    sourceBuffer               The input buffer to be signed
        * @param    sourceBufferLen            The length of the input buffer
        * @param    destBuffer                 The destination buffer where the signature goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferRequiredLength   The length of destination buffer that will be required to hold the signature
        * @param    rsaPadding                 The RSA padding scheme to be used
        * @param    hashMode                   The hash mode to be used for hashing, HashMode::invalid if no hashing is required
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV sign(const uint32_t&   keyHandle,
                   const uint8_t*    sourceBuffer,
                   const uint32_t&   sourceBufferLen,
                   uint8_t*          destBuffer,
                   const uint32_t&   destBufferLen,
                   uint32_t&         destBufferRequiredLength,
                   const RsaPadding& rsaPadding,
                   const HashMode&   hashMode);

        /**
        * Verifies a signature using the public key
        * @param    keyHandle           The public key handle
        * @param    sourceBuffer        The input buffer which was used for signing
        * @param    sourceBufferLen     The length of the input buffer
        * @param    destBuffer          The signature buffer
        * @param    destBufferLen       The length of signature
        * @param    rsaPadding          The RSA padding scheme to be used
        * @param    hashMode            The hash mode to be used for hashing, HashMode::invalid if no hashing is required
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise
        */
        CK_RV verify(const uint32_t&    keyHandle,
                     const uint8_t*     sourceBuffer,
                     const uint32_t&    sourceBufferLen,
                     uint8_t*           destBuffer,
                     uint32_t           destBufferLen,
                     const RsaPadding&  rsaPadding,
                     const HashMode&    hashMode);

        /**
        * Wraps a key with another key
        * @param    wrappingKeyHandle          The key handle of key that wraps another key
        * @param    keyHandleData              The key handle of key to be wrapped
        * @param    destBuffer                 The destination buffer where the wrapped key buffer goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the wrapped key
        * @param    rsaPadding                 The RSA padding scheme to be used
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV wrapKey(const uint32_t&   wrappingKeyHandle,
                      const uint32_t&   keyHandleData,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t&         destBufferLenRequired,
                      const RsaPadding& rsaPadding);

        /**
        * Platform binds an asymmetric key
        * @param    keyHandle                  The key handle of key that is to be platform bound
        * @param    destBuffer                 The destination buffer where the platform bound key buffer goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the platform bound key
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV platformbindKey(const uint32_t&   keyHandle,
                              uint8_t*          destBuffer,
                              const uint32_t&   destBufferLen,
                              uint32_t&         destBufferLenRequired);

        /**
        * Unwraps a key with another key
        * @param    unwrappingKeyHandle     The key handle of key that unwraps another key
        * @param    keyHandle               The key handle that points to the unwrapped key
        * @param    sourceBuffer            The input buffer that contains the wrapped key
        * @param    sourceBufferLen         The length of the input buffer
        * @param    rsaPadding              The RSA padding scheme to be used
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise
        */
        CK_RV unwrapKey(const uint32_t&   unwrappingKeyHandle,
                        uint32_t*         keyHandle,
                        const uint8_t*    sourceBuffer,
                        const uint32_t&   sourceBufferLen,
                        const RsaPadding& rsaPadding);

        /**
        * Imports a platform bound asymmetric key
        * @param    pPublicKeyTemplate          Template for the public key
        * @param    ulPublicKeyAttributeCount   The size of public key template
        * @param    pPrivateKeyTemplate         Template for the private key
        * @param    ulPrivateKeyAttributeCount  The size of private key template
        * @param    phPublicKey                 The key handle for public key
        * @param    phPrivateKey                The key handle for private key
        * @param    platformBoundKey            The platform bound asymmetric key buffer
        * @param    publicKeyAttributes         Attribute structure holding all attributes set for public key
        * @param    privateKeyAttributes        Attribute structure holding all attributes set for private key
        * @return   CK_RV                       CKR_OK if operation is successful, error code otherwise
        */
        CK_RV importPlatformBoundKey(const CK_ATTRIBUTE_PTR         pPublicKeyTemplate,
                                     const CK_ULONG&                ulPublicKeyAttributeCount,
                                     const CK_ATTRIBUTE_PTR         pPrivateKeyTemplate,
                                     const CK_ULONG&                ulPrivateKeyAttributeCount,
                                     CK_OBJECT_HANDLE_PTR           phPublicKey,
                                     CK_OBJECT_HANDLE_PTR           phPrivateKey,
                                     const std::vector<uint8_t>&    platformBoundKey,
                                     Attributes&                    publicKeyAttributes,
                                     Attributes&                    privateKeyAttributes);

        /**
        * Exports the public key of an asymmetric key
        * @param    keyHandle                  The key handle of key that is to be exported
        * @param    destBuffer                 The destination buffer where the public key buffer goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the public key
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV exportKey(const uint32_t& keyHandle,
                        uint8_t*        destBuffer,
                        const uint32_t& destBufferLen,
                        uint32_t&       destBufferLenRequired);

        /**
        * Imports a public key into the cache
        * @param    keyHandle           The key handle that points to the imported public key
        * @param    sourceBuffer        The input buffer that contains the public key
        * @param    sourceBufferLen     The length of the input buffer
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise
        */
        CK_RV importKey(uint32_t*       keyHandle,
                        const uint8_t*  sourceBuffer,
                        const uint32_t& sourceBufferLen);

         /**
        * Removes a key from the asymmetric key cache
        * @param    keyHandle           The asymmetric key handle (can be private/public)
        * @param    keyHandleCache      The asymmetric key handle cache
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise
        */
        CK_RV destroyKey(const uint32_t&                           keyHandle,
                         std::shared_ptr<AsymmetricKeyHandleCache> keyHandleCache);

        /**
        * Exports a buffer containing quote and asymmetric public key associated with key handle passed
        * @param    keyHandle                  The key handle of an asymmetric key(public)
        * @param    spid                       The service provider Id
        * @param    spidLen                    The length of spid in bytes
        * @param    sigRL                      The signature revocation list
        * @param    sigRLLen                   The length of sigRL in bytes
        * @param    signatureType              The type of signature(linkable/unlinkable)
        * @param    destBuffer                 The destination buffer where the custom quote + public key buffer goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the quote + public key
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV exportQuotePublicKey(const uint32_t&  keyHandle,
                                   const uint8_t*   spid,
                                   const uint32_t&  spidLen,
                                   const uint8_t*   sigRL,
                                   const uint32_t&  sigRLLen,
                                   const uint32_t&  signatureType,
                                   uint8_t*         destBuffer,
                                   const uint32_t&  destBufferLen,
                                   uint32_t&        destBufferLenRequired);

        static std::recursive_mutex mProviderMutex;
    };
}
#endif //ASYMMETRIC_PROVIDER_H