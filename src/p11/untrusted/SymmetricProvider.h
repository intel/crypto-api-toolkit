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

#include <memory>
#include <mutex>

#include "SessionHandleCache.h"
#include "SymmetricKeyHandleCache.h"
#include "p11Defines.h"
#include "AttributeHelpers.h"

namespace P11Crypto
{
    class SymmetricProvider
    {
    public:

        static std::shared_ptr<SymmetricProvider> getSymmetricProvider();

        SymmetricProvider() = default;

        /**
         * Generates a symmetric key
         * @param   hSession        The session handle
         * @param   pTemplate       Template for the symmetric key to be generated
         * @param   ulCount         The size of template passed
         * @param   phKey           The symmetric key handle that points to the key generated
         * @param   keyAttributes   Attribute structure holding all attributes set for the symmetric key
         * @return  CK_RV           CKR_OK if operation is successful, error code otherwise
         */
        CK_RV generateKey(const CK_SESSION_HANDLE& hSession,
                          const CK_ATTRIBUTE_PTR   pTemplate,
                          const CK_ULONG&          ulCount,
                          CK_OBJECT_HANDLE_PTR     phKey,
                          Attributes&              keyAttributes);

        /**
         * Clears/removes a symmetric key
         * @param   keyHandle       The symmetric key handle that points to the key generated
         * @param   keyHandleCache  The symmetric key handle cache
         * @return  CK_RV           CKR_OK if operation is successful, error code otherwise
         */
        CK_RV destroyKey(const uint32_t&                          keyHandle,
                         std::shared_ptr<SymmetricKeyHandleCache> keyHandleCache);

        /**
         * Initializes the encryption process
         * @param   keyHandle     The key handle
         * @param   iv            The initialization vector to be used
         * @param   ivSize        The size of iv in bytes
         * @param   aad           The additional authentication data, to be used for GCM operations
         * @param   aadSize       The size of aad in bytes
         * @param   cipherMode    The cipher mode to be used for encryption
         * @param   padding       Parameter to indicate the use of padding, used for CBC operations
         * @param   tagBits       The size of tag in bits
         * @param   counterBits   The size of counter in bits
         * @return  CK_RV         CKR_OK if operation is successful, error code otherwise
         */
        CK_RV encryptInit(const uint32_t&   keyHandle,
                          const uint8_t*    iv,
                          const uint32_t&   ivSize,
                          const uint8_t*    aad,
                          const uint32_t&   aadSize,
                          const uint8_t&    cipherMode,
                          const int&        padding,
                          const uint32_t&   tagBits,
                          const int&        counterBits);

        /**
        * Continues an encryption operation
        * @param    keyHandle                  The key handle
        * @param    sourceBuffer               The input buffer to be encrypted
        * @param    sourceBufferLen            The length of the input buffer
        * @param    encryptedData              The destination buffer where the encrypted output goes into
        * @param    encryptedDataLen           The length of destination buffer
        * @param    destBufferRequiredLen      The number of bytes required to hold the encrypted data
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV encryptUpdate(const uint32_t&   keyHandle,
                            const uint8_t*    sourceBuffer,
                            const uint32_t&   sourceBufferLen,
                            uint8_t*          encryptedData,
                            const uint32_t&   encryptedDataLen,
                            uint32_t&         destBufferRequiredLen);

        /**
         * Finalizes a multi-part encryption process
         * @param   keyHandle                 The key handle
         * @param   encryptedData             A pointer to a buffer (previously allocated) where the encrypted data will be stored
         * @param   destBufferRequiredLen     The number of bytes required to hold the encrypted data
         * @return  CK_RV                     CKR_OK if operation is successful, error code otherwise
         */
        CK_RV encryptFinal(const uint32_t&   keyHandle,
                           uint8_t*          encryptedData,
                           uint32_t&         destBufferRequiredLen);

        /**
         * Initializes the decryption process.
         * @param   keyHandle     The key handle
         * @param   iv            The initialization vector to be used
         * @param   ivSize        The size of iv in bytes
         * @param   aad           The additional authentication data, to be used for GCM operations
         * @param   aadSize       The size of aad in bytes
         * @param   cipherMode    The cipher mode to be used for decryption
         * @param   padding       Parameter to indicate the use of padding, used for CBC operations
         * @param   tagBits       The size of tag in bits
         * @param   counterBits   The size of counter in bits
         * @return  CK_RV         CKR_OK if operation is successful, error code otherwise
         */
        CK_RV decryptInit(const uint32_t&   keyHandle,
                          const uint8_t*    iv,
                          const uint32_t&   ivSize,
                          const uint8_t*    aad,
                          const uint32_t&   aadSize,
                          const uint8_t&    cipherMode,
                          const int&        padding,
                          const uint32_t&   tagBits,
                          const int&        counterBits);

        /**
        * Continues an decryption operation
        * @param    keyHandle               The key handle
        * @param    encryptedData           The input buffer to be decrypted
        * @param    encryptedDataLen        The length of the input buffer
        * @param    destBuffer              The destination buffer where the decrypted output goes into
        * @param    destBufferLen           The length of destination buffer
        * @param    destBufferRequiredLen   The number of bytes required to decrypt the input buffer
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise
        */
        CK_RV decryptUpdate(const uint32_t&   keyHandle,
                            const uint8_t*    encryptedData,
                            const uint32_t&   encryptedDataLen,
                            uint8_t*          destBuffer,
                            const uint32_t&   destBufferLen,
                            uint32_t&         destBufferRequiredLen);

        /**
         * Finalizes a multi-part decryption process
         * @param   keyHandle               The key handle
         * @param   decryptedData           A pointer to a buffer (previously allocated) where the decrypted data will be stored
         * @param   destBufferRequiredLen   The number of bytes to allocate decryptedData
         * @return  CK_RV                   CKR_OK if operation is successful, error code otherwise
         */
        CK_RV decryptFinal(const uint32_t&   keyHandle,
                           uint8_t*          decryptedData,
                           uint32_t&         destBufferRequiredLen);

        /**
        * Wraps a key with another key
        * @param    wrappingKeyHandle       The key handle of key that wraps another key
        * @param    keyHandleData           The key handle of key to be wrapped
        * @param    iv                      The initialization vector to be used
        * @param    ivSize                  The size of iv in bytes
        * @param    aad                     The additional authentication data, to be used for GCM operations
        * @param    aadSize                 The size of aad in bytes
        * @param    cipherMode              The cipher mode to be used
        * @param    padding                 Parameter to indicate the use of padding, used for CBC operations
        * @param    tagBits                 The size of tag in bits
        * @param    counterBits             The size of counter in bits
        * @param    destBuffer              The destination buffer where the wrapped key buffer goes into
        * @param    destBufferLen           The length of destination buffer
        * @param    destBufferLenRequired   The length of destination buffer that will be required to hold the wrapped key
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise
        */
        CK_RV wrapKey(const uint32_t&    wrappingKeyHandle,
                      const uint32_t&    keyHandleData,
                      const uint8_t*     iv,
                      const uint32_t&    ivSize,
                      const uint8_t*     aad,
                      const uint32_t&    aadSize,
                      const uint8_t&     cipherMode,
                      const int&         padding,
                      const uint32_t&    tagBits,
                      const int&         counterBits,
                      uint8_t*           destBuffer,
                      const uint32_t&    destBufferLen,
                      uint32_t&          destBufferLenRequired);

        /**
        * Unwraps a key with another key
        * @param    unwrappingKeyHandle     The key handle of key that unwraps another key
        * @param    keyHandle               The key handle that points to the unwrapped key
        * @param    sourceBuffer            The input buffer that contains the wrapped key
        * @param    sourceBufferLen         The length of the input buffer
        * @param    iv                      The initialization vector to be used
        * @param    ivSize                  The size of iv in bytes
        * @param    aad                     The additional authentication data, to be used for GCM operations
        * @param    aadSize                 The size of aad in bytes
        * @param    cipherMode              The cipher mode to be used
        * @param    padding                 Parameter to indicate the use of padding, used for CBC operations
        * @param    tagBits                 The size of tag in bits
        * @param    counterBits             The size of counter in bits
        * @return   CK_RV                   CKR_OK if operation is successful, error code otherwise
        */
        CK_RV unwrapKey(const uint32_t&  unwrappingKeyHandle,
                        uint32_t*        keyHandle,
                        const uint8_t*   sourceBuffer,
                        const uint32_t&  sourceBufferLen,
                        const uint8_t*   iv,
                        const uint32_t&  ivSize,
                        const uint8_t*   aad,
                        const uint32_t&  aadSize,
                        const uint8_t&   cipherMode,
                        const int&       padding,
                        const uint32_t&  tagBits,
                        const int&       counterBits);

        /**
        * Platform binds a symmetric key
        * @param    keyHandle                  The key handle of key that is to be platform bound
        * @param    destBuffer                 The destination buffer where the platform bound key buffer goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    destBufferLenRequired      The length of destination buffer that will be required to hold the platform bound key
        * @return   CK_RV                      CKR_OK if operation is successful, error code otherwise
        */
        CK_RV platformbindKey(const uint32_t&    keyHandle,
                              uint8_t*           destBuffer,
                              const uint32_t&    destBufferLen,
                              uint32_t&          destBufferLenRequired);

        /**
        * Imports a platform bound symmetric key
        * @param    keyHandle           The key handle of key that will be associated with the imported platform bound key
        * @param    sourceBuffer        The platform bound key
        * @param    sourceBufferLen     The length of platform bound key
        * @return   CK_RV               CKR_OK if operation is successful, error code otherwise
        */
        CK_RV importPlatformBoundKey(uint32_t*       keyHandle,
                                     const uint8_t*  sourceBuffer,
                                     const uint32_t& sourceBufferLen);

    private:
        static std::recursive_mutex mProviderMutex;
    };
}
#endif //SYMMETRIC_CRYPTO_H

