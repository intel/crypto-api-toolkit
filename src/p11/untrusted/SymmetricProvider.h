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

#ifndef SYMMETRIC_CRYPTO_H
#define SYMMETRIC_CRYPTO_H

#include <sgx_error.h>

#include "CryptoEnclaveDefs.h"
#include "EnclaveUtils.h"
#include "p11Enclave_u.h"

namespace P11Crypto
{
    namespace SymmetricProvider
    {
        //---------------------------------------------------------------------------------------------
        /**
         * Generates an AES key.
         * @param   symKeyParams The SymmetricKeyParams structure.
         * @param   importKey    Bool value indicating key generation or key import.
         * @param   phKey        The symmetric key handle that points to the key generated.
         * @return  CK_RV        CKR_OK if operation is successful, error code otherwise.
         */
        CK_RV generateAesKey(const SymmetricKeyParams& symKeyParams,
                             const bool&               importKey,
                             CK_OBJECT_HANDLE_PTR      phKey);

        //---------------------------------------------------------------------------------------------
        /**
         * Initializes the encryption process.
         * @param   keyHandle      The key handle.
         * @param   aesCryptParams The AesCryptParams structure.
         * @return  CK_RV          CKR_OK if operation is successful, error code otherwise.
         */
        CK_RV encryptInit(const uint32_t& keyHandle, const AesCryptParams& aesCryptParams);

        //---------------------------------------------------------------------------------------------
        /**
         * Initializes the decryption process.
         * @param   keyHandle      The key handle.
         * @param   aesCryptParams The AesCryptParams structure.
         * @return  CK_RV          CKR_OK if operation is successful, error code otherwise.
         */
        CK_RV decryptInit(const uint32_t& keyHandle, const AesCryptParams& aesCryptParams);

        //---------------------------------------------------------------------------------------------
        /**
        * Continues an encryption operation.
        * @param    keyHandle                  The key handle.
        * @param    sourceBuffer               The input buffer to be encrypted.
        * @param    sourceBufferLen            The length of the input buffer.
        * @param    encryptedData              The destination buffer where the encrypted output goes into.
        * @param    encryptedDataLen           The length of destination buffer.
        * @param    destBufferRequiredLen      The number of bytes required to hold the encrypted data.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV encryptUpdate(const uint32_t& keyHandle,
                            const uint8_t*  sourceBuffer,
                            const uint32_t& sourceBufferLen,
                            uint8_t*        encryptedData,
                            const uint32_t& encryptedDataLen,
                            uint32_t*       destBufferRequiredLen);

        //---------------------------------------------------------------------------------------------
        /**
        * Continues an decryption operation.
        * @param    keyHandle               The key handle.
        * @param    encryptedData           The input buffer to be decrypted.
        * @param    encryptedDataLen        The length of the input buffer.
        * @param    destBuffer              The destination buffer where the decrypted output goes into.
        * @param    destBufferLen           The length of destination buffer.
        * @param    destBufferRequiredLen   The number of bytes required to decrypt the input buffer.
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV decryptUpdate(const uint32_t& keyHandle,
                            const uint8_t*  encryptedData,
                            const uint32_t& encryptedDataLen,
                            uint8_t*        destBuffer,
                            const uint32_t& destBufferLen,
                            uint32_t*       destBufferRequiredLen);

        //---------------------------------------------------------------------------------------------
        /**
         * Finalizes a multi-part encryption process.
         * @param   keyHandle                 The key handle.
         * @param   encryptedData             A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param   destBufferRequiredLen     The number of bytes required to hold the encrypted data.
         * @return  CK_RV                     CKR_OK if operation is successful, error code otherwise.
         */
        CK_RV encryptFinal(const uint32_t& keyHandle,
                           uint8_t*        encryptedData,
                           uint32_t*       destBufferRequiredLen);

        //---------------------------------------------------------------------------------------------
        /**
         * Finalizes a multi-part decryption process.
         * @param   keyHandle               The key handle.
         * @param   decryptedData           A pointer to a buffer (previously allocated) where the decrypted data will be stored.
         * @param   destBufferRequiredLen   The number of bytes to allocate decryptedData.
         * @return  CK_RV                   CKR_OK if operation is successful, error code otherwise.
         */
        CK_RV decryptFinal(const uint32_t& keyHandle,
                           uint8_t*        decryptedData,
                           uint32_t*       destBufferRequiredLen);

        //---------------------------------------------------------------------------------------------
        /**
        * Wraps a key with another key.
        * @param    wrappingKeyHandle       The key handle of key that wraps another key.
        * @param    keyHandleData           The key handle of key to be wrapped.
        * @param    aesCryptParams          The AesCryptParams structure.
        * @param    destBuffer              The destination buffer where the wrapped key buffer goes into.
        * @param    destBufferLen           The length of destination buffer.
        * @param    destBufferLenRequired   The length of destination buffer that will be required to hold the wrapped key.
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV wrapKey(const uint32_t&       wrappingKeyHandle,
                      const uint32_t&       keyHandleData,
                      const AesCryptParams& aesCryptParams,
                      uint8_t*              destBuffer,
                      const uint32_t&       destBufferLen,
                      uint32_t*             destBufferLenRequired);

        //---------------------------------------------------------------------------------------------
        /**
        * Platform binds a symmetric key.
        * @param    keyHandle                  The key handle of key that is to be platform bound.
        * @param    destBuffer                 The destination buffer where the platform bound key buffer goes into.
        * @param    destBufferLen              The length of destination buffer.
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the platform bound key.
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV platformbindKey(const uint32_t& keyHandle,
                              uint8_t*        destBuffer,
                              const uint32_t& destBufferLen,
                              uint32_t*       destBufferLenRequired);

        //---------------------------------------------------------------------------------------------
        /**
        * Unwraps a key with another key.
        * @param    unwrappingKeyHandle     The key handle of key that unwraps another key.
        * @param    sourceBuffer            The input buffer that contains the wrapped key.
        * @param    sourceBufferLen         The length of the input buffer.
        * @param    aesCryptParams          The AesCryptParams structure.
        * @param    wrappedKeyType          KeyType that indicates if the wrapped key is Rsa or Aes.
        * @param    keyHandle               The key handle that points to the unwrapped key.
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV unwrapKey(const uint32_t&       unwrappingKeyHandle,
                        const uint8_t*        sourceBuffer,
                        const uint32_t&       sourceBufferLen,
                        const AesCryptParams& aesCryptParams,
                        const KeyType&        wrappedKeyType,
                        uint32_t*             keyHandle);

        //---------------------------------------------------------------------------------------------
        /**
        * Imports a platform bound symmetric key.
        * @param    sourceBuffer        The platform bound key.
        * @param    sourceBufferLen     The length of platform bound key.
        * @param    keyHandle           The key handle of key that will be associated with the imported platform bound key.
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV importPlatformBoundKey(const uint8_t*  sourceBuffer,
                                     const uint32_t& sourceBufferLen,
                                     uint32_t*       keyHandle);
    };
}
#endif //SYMMETRIC_CRYPTO_H