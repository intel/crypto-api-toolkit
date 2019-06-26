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

#ifndef ENCLAVE_EVP_DECRYPT_H
#define ENCLAVE_EVP_DECRYPT_H

#include "EVPContextHandle.h"
#include "ByteBuffer.h"
#include "CryptParams.h"
#include "EVPCtxStateCache.h"

namespace CryptoSgx
{
    /**
     * Class used to decrypt using OpenSSL EVP Crypto functions.
     */
    class EVPDecrypt
    {
    public:
        /**
         * Constructor.
         */
        EVPDecrypt();

        EVPDecrypt(const EVPDecrypt& other) = delete;

        EVPDecrypt& operator=(const EVPDecrypt& other) = delete;

        /**
         * Initializes the decryption process.
         * @param   cipherMode    The cipher mode to be used for decryption.
         * @param   cryptParams   A pointer to CryptParams structure containing necessary parameters.
         * @return                True if the operation was successful, false otherwise.
         */
        bool init(const EVP_CIPHER*  cipherMode,
                  const CryptParams& cryptParams);

        /**
         * Decrypts a buffer.
         * @param   cryptParams               A pointer to CryptParams structure containing necessary params.
         * @param   destBuffer                A pointer to a buffer (previously allocated) where the decrypted data will be stored.
         * @param   decryptedBytes            On exit, the length in bytes of the decrypted bytes.
         * @param   sourceBuffer              The buffer to be decrypted.
         * @param   sourceBufferLen           The length of the input buffer.
         * @param   removeBlockCipherPadding  Flag to indicate cleanup of padded bytes.
         * @return                            True if the operation was successful, false otherwise.
         */
        bool decrypt(CryptParams* cryptParams,
                     Byte*        destBuffer,
                     int*         decryptedBytes,
                     const Byte*  sourceBuffer,
                     const int    sourceBufferLen,
                     bool         removeBlockCipherPadding = false);

        /**
         * Finalizes the decryption process.
         * @param destBuffer      A pointer to a buffer (previously allocated) where the decrypted data will be stored.
         * @param decryptedBytes  On exit, the length in bytes of the decrypted  bytes.
         * @return                True if the operation was successful, false otherwise.
         */
        bool final(Byte* destBuffer, int* decryptedBytes);

        /**
        * Continues a multi-part decryption process.
        * @param evpCtxState        The evp state.
        * @param destBuffer         The destination buffer where the decrypted output goes into.
        * @param decryptedBytes     The number of bytes decrypted.
        * @param sourceBuffer       The input buffer to be decrypted.
        * @param sourceBufferLen    The length of the input buffer.
        * @return                   True if decryption is successful, false otherwise.
        */
        bool decryptUpdate(EVPCtxState*   evpCtxState,
                           uint8_t*       destBuffer,
                           int*           decryptedBytes,
                           const uint8_t* sourceBuffer,
                           const int      sourceBufferLen);

        /**
         * Finalizes a multi-part decryption process.
         * @param evpCtxState       The evp state.
         * @param destBuffer        A pointer to a buffer (previously allocated) where the decrypted data will be stored.
         * @param decryptedBytes    On exit, the length in bytes of the decrypted  bytes.
         * @return                  True if the operation was successful, false otherwise.
         */
        bool decryptFinal(EVPCtxState* evpCtxState,
                          uint8_t*     destBuffer,
                          int*         bytesDecrypted);

        /**
         * Gets the evp context handle.
         * @return      The Evp Context Handle.
        */
        EVPContextHandle& getContext();

    private:

        EVPContextHandle mContext;

        bool initGCM(const EVP_CIPHER*  cipherMode,
                     const CryptParams& cryptParams);

        bool initCTR(const EVP_CIPHER*  cipherMode,
                     const CryptParams& cryptParams);

        bool initCBC(const EVP_CIPHER*  cipherMode,
                     const CryptParams& cryptParams);

        bool decryptWithPaddingCustomizations(CryptParams& cryptParams,
                                              Byte*        destBuffer,
                                              int*         decryptedBytes,
                                              const Byte*  sourceBuffer,
                                              const int    sourceBufferLen);
    };

} //CryptoSgx

#endif //EVP_DECRYPT_H

