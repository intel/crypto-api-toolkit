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

#include <mutex>
#include <functional>

#include "config.h"
#include "CryptoEnclaveDefs.h"
#include "EnclaveUtils.h"
#include "p11Enclave_u.h"

namespace P11Crypto
{
    namespace AsymmetricProvider
    {
        //---------------------------------------------------------------------------------------------
        /**
        * Generates an asymmetric key pair.
        * @param    asymKeyParams    The AsymKeyParams structure.
        * @param    phPublicKey      The key handle for public key.
        * @param    phPrivateKey     The key handle for private key.
        * @return   CK_RV            CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV generateRsaKeyPair(const AsymmetricKeyParams&   asymKeyParams,
                                 const std::vector<CK_ULONG>& packedAttributesPublic,
                                 const std::vector<CK_ULONG>& packedAttributesPrivate,
                                 CK_OBJECT_HANDLE_PTR         phPublicKey,
                                 CK_OBJECT_HANDLE_PTR         phPrivateKey);

        //---------------------------------------------------------------------------------------------
        /**
        * Encrypts a buffer using the public key.
        * @param    keyHandle                  The public key handle.
        * @param    sourceBuffer               The input buffer to be encrypted.
        * @param    sourceBufferLen            The length of the input buffer.
        * @param    destBuffer                 The destination buffer where the encrypted output goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    destBufferRequiredLength   The length of destination buffer that will be required to hold encrypted output.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV encrypt(const uint32_t&   keyHandle,
                      const uint8_t*    sourceBuffer,
                      const uint32_t&   sourceBufferLen,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t*         destBufferRequiredLength,
                      const RsaPadding& rsaPadding);

        //---------------------------------------------------------------------------------------------
        // /**
        // * Decrypts a buffer using the private key.
        // * @param    keyHandle                  The private key Id from provider.
        // * @param    encryptedBuffer            The input buffer to be decrypted.
        // * @param    encryptedBufferLen         The length of the input buffer.
        // * @param    destBuffer                 The destination buffer where the decrypted output goes into.
        // * @param    destBufferLen              The length of destination buffer.
        // * @param    destBufferRequiredLength   The length of destination buffer that will be required to hold decrypted output.
        // * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        // */
        CK_RV decrypt(const uint32_t&   keyHandle,
                      const uint8_t*    encryptedBuffer,
                      const uint32_t&   encryptedBufferLen,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t*         destBufferRequiredLength,
                      const RsaPadding& rsaPadding);

        //---------------------------------------------------------------------------------------------
        /**
        * Wraps a key with another key.
        * @param    wrappingKeyHandle          The key handle of key that wraps another key.
        * @param    keyHandleData              The key handle of key to be wrapped.
        * @param    rsaCryptParams             The RsaCryptParams structure.
        * @param    destBuffer                 The destination buffer where the wrapped key buffer goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the wrapped key.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV wrapKey(const uint32_t&       wrappingKeyHandle,
                      const uint32_t&       keyHandleData,
                      const RsaCryptParams& rsaCryptParams,
                      uint8_t*              destBuffer,
                      const uint32_t&       destBufferLen,
                      uint32_t*             destBufferLenRequired);

        //---------------------------------------------------------------------------------------------
        /**
        * Exports the public key of an asymmetric key.
        * @param    keyHandle                  The key handle of key that is to be exported.
        * @param    destBuffer                 The destination buffer where the public key buffer goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the public key.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV exportPublicKey(const uint32_t& keyHandle,
                              uint8_t*        destBuffer,
                              const uint32_t& destBufferLen,
                              uint32_t*       destBufferLenRequired);

        //---------------------------------------------------------------------------------------------
        /**
        * Exports a buffer containing EPID quote and asymmetric (RSA) public key associated with key handle passed.
        * @param    keyHandle                  The key handle of an asymmetric key(public).
        * @param    rsaQuoteWrapParams         The RsaEpidQuoteWrapParams structure.
        * @param    destBuffer                 The destination buffer where the custom quote + public key buffer goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the quote + public key.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV exportQuoteWithRsaPublicKey(const uint32_t&       	keyHandle,
                                          const RsaEpidQuoteParams& rsaQuoteWrapParams,
                                          uint8_t*              	destBuffer,
                                          const uint32_t&       	destBufferLen,
                                          uint32_t*             	destBufferLenRequired);

#ifdef DCAP_SUPPORT
        //---------------------------------------------------------------------------------------------
        /**
        * Exports a buffer containing ECDSA quote and asymmetric (RSA) public key associated with key handle passed.
        * @param    keyHandle                  The key handle of an asymmetric key(public).
        * @param    rsaQuoteWrapParams         The RsaEcdsaQuoteWrapParams structure.
        * @param    destBuffer                 The destination buffer where the custom quote + public key buffer goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the quote + public key.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV exportQuoteWithRsaPublicKey(const uint32_t&       	 keyHandle,
                                          const RsaEcdsaQuoteParams& rsaQuoteWrapParams,
                                          uint8_t*              	 destBuffer,
                                          const uint32_t&       	 destBufferLen,
                                          uint32_t*            		 destBufferLenRequired);
#endif

        /**
        * Unwraps a key with another key.
        * @param    unwrappingKeyHandle     The key handle of key that unwraps another key.
        * @param    sourceBuffer            The input buffer that contains the wrapped key.
        * @param    sourceBufferLen         The length of the input buffer.
        * @param    rsaCryptParams          The RsaCryptParams structure.
        * @param    keyHandle               The key handle that points to the unwrapped key.
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise.
        */

        CK_RV unwrapKey(const uint32_t&              unwrappingKeyHandle,
                        const uint8_t*               sourceBuffer,
                        const uint32_t&              sourceBufferLen,
                        const RsaCryptParams&        rsaCryptParams,
                        const std::vector<CK_ULONG>& packedAttributes,
                        uint32_t*                    keyHandle);

        //---------------------------------------------------------------------------------------------
        /**
        * Imports a public key into the cache.
        * @param    sourceBuffer        The input buffer that contains the public key.
        * @param    sourceBufferLen     The length of the input buffer.
        * @param    keyHandle           The key handle that points to the imported public key.
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV importKey(const uint8_t*               sourceBuffer,
                        const uint32_t&              sourceBufferLen,
                        const std::vector<CK_ULONG>& packedAttributes,
                        uint32_t*                    keyHandle);

        //---------------------------------------------------------------------------------------------
        /**
        * Signs a buffer using the private key
        * @param    keyHandle                  The private key handle.
        * @param    sourceBuffer               The input buffer to be signed.
        * @param    sourceBufferLen            The length of the input buffer.
        * @param    destBuffer                 The destination buffer where the signature goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    rsaPadding                 The RSA padding scheme to be used.
        * @param    hashMode                   The hash mode to be used for hashing, HashMode::invalid if no hashing is required.
        * @param    destBufferRequiredLength   Pointer to length of destination buffer that will be required to hold the signature.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV sign(const uint32_t&   keyHandle,
                   const uint8_t*    sourceBuffer,
                   const uint32_t&   sourceBufferLen,
                   uint8_t*          destBuffer,
                   const uint32_t&   destBufferLen,
                   const RsaPadding& rsaPadding,
                   const HashMode&   hashMode,
                   uint32_t*         destBufferRequiredLength);

        //---------------------------------------------------------------------------------------------
        /**
        * Verifies a signature using the public key.
        * @param    keyHandle           The public key handle.
        * @param    sourceBuffer        The input buffer which was used for signing.
        * @param    sourceBufferLen     The length of the input buffer.
        * @param    destBuffer          The signature buffer.
        * @param    destBufferLen       The length of signature.
        * @param    rsaPadding          The RSA padding scheme to be used.
        * @param    hashMode            The hash mode to be used for hashing, HashMode::invalid if no hashing is required.
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV verify(const uint32_t&   keyHandle,
                     const uint8_t*    sourceBuffer,
                     const uint32_t&   sourceBufferLen,
                     uint8_t*          destBuffer,
                     uint32_t          destBufferLen,
                     const RsaPadding& rsaPadding,
                     const HashMode&   hashMode);

        //---------------------------------------------------------------------------------------------
        CK_RV generateEcc(const AsymmetricKeyParams&   asymKeyParams,
                          const std::vector<CK_ULONG>& packedAttributesPublic,
                          const std::vector<CK_ULONG>& packedAttributesPrivate,
                          CK_OBJECT_HANDLE_PTR         phPublicKey,
                          CK_OBJECT_HANDLE_PTR         phPrivateKey);
    };
}
#endif //ASYMMETRIC_PROVIDER_H

