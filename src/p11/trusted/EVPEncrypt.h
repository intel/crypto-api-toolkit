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

#ifndef ENCLAVE_EVP_ENCRYPT_H
#define ENCLAVE_EVP_ENCRYPT_H

#include "ByteBuffer.h"
#include "EVPContextHandle.h"
#include "CryptParams.h"
#include "EVPCtxStateCache.h"

namespace CryptoSgx
{
    /**
     * Class used to encrypt using OpenSSL EVP Crypto functions.
     */
    class EVPEncrypt
    {
    public:
        /**
         * Constructor.
         */
        EVPEncrypt();

        EVPEncrypt(const EVPEncrypt& other) = delete;

        EVPEncrypt& operator=(const EVPEncrypt& other) = delete;

        /**
         * Initializes the encryption process.
         * @param cipherMode    The cipher mode to be used for encryption.
         * @param cryptParams   A pointer to CryptParams structure containing necessary parameters.
         * @return              True if the operation was successful, false otherwise.
         */
        bool init(const EVP_CIPHER*  cipherMode,
                  const CryptParams& cryptParams);

        /**
         * Encrypts a buffer.
         * @param destBuffer            A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param encryptedBytes        On exit, the length in bytes of the encrypted bytes.
         * @param sourceBuffer          The buffer to be encrypted.
         * @param sourceBufferLen       The length of the input buffer.
         * @param useBlockCipherPadding Flag to indicate whether to pad the plain text.
         * @return                      True if the operation was successful, false otherwise.
         */
        bool encrypt(uint8_t*       destBuffer,
                     int*           encryptedBytes,
                     const uint8_t* sourceBuffer,
                     const int      sourceBufferLen,
                     bool           useBlockCipherPadding = false);

        /**
        * Continues a multi-part encryption process.
        * @param evpCtxState        The evp state.
        * @param destBuffer         The destination buffer where the encrypted output goes into.
        * @param encryptedBytes     The number of bytes encrypted.
        * @param sourceBuffer       The input buffer to be encrypted.
        * @param sourceBufferLen    The length of the input buffer.
        * @return                   True if encryption is successful, false otherwise.
        */
        bool encryptUpdate(EVPCtxState*     evpCtxState,
                           uint8_t*         destBuffer,
                           int*             encryptedBytes,
                           const uint8_t*   sourceBuffer,
                           const int        sourceBufferLen);

        /**
         * Finalizes a multi-part encryption process.
         * @param evpCtxState       The evp state.
         * @param destBuffer        A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param encryptedBytes    On exit, the length in bytes of the encrypted bytes.
         * @return                  True if the operation was successful, false otherwise.
         */
        bool encryptFinal(EVPCtxState*  evpCtxState,
                          uint8_t*      destBuffer,
                          int*          encryptedBytes);

        /**
         * Finalizes the encryption process.
         * @param destBuffer      A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param encryptedBytes  On exit, the length in bytes of the encrypted bytes.
         * @return                True if the operation was successful, false otherwise.
         */
        bool final(CryptParams* cryptParams, Byte* destBuffer, int* encryptedBytes);

        /**
         * Gets the evp context handle.
         * @return      The Evp Context Handle.
        */
        EVPContextHandle& getContext();

    private:
        // Member variables
        EVPContextHandle mContext;

        EVPCtxStateCache  mEVPCtxStateCache;

        bool initGCM(const EVP_CIPHER* cipher,
                     const CryptParams& cryptParams);

        bool initCTR(const EVP_CIPHER* cipher,
                     const CryptParams& cryptParams);

        bool initCBC(const EVP_CIPHER* cipher,
                     const CryptParams& cryptParams);

        bool encryptWithPaddingCustomizations(uint8_t*          destBuffer,
                                              int*              encryptedBytes,
                                              const uint8_t*    sourceBuffer,
                                              const int         sourceBufferLen);
    };

} //CryptoSgx

#endif //EVP_ENCRYPT_H

