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

#ifndef ENCLAVE_CRYPTO_HASH_H
#define ENCLAVE_CRYPTO_HASH_H

#include <ipp/ippcp.h>
#include <map>

#include "CryptoEnclaveDefs.h"
#include "HashStateCache.h"

namespace CryptoSgx
{
    /**
     * Cryptographic hash implementation.
     */
    class CryptoHash
    {
    public:
        /**
         * Constructor.
         */
        CryptoHash() = default;

        CryptoHash(const CryptoHash& other) = delete;

        CryptoHash& operator=(const CryptoHash& other) = delete;

        /**
         * Creates a hash state
         * @param hashId            The hash handle from provider
         * @param hashMode          The hash algorithm
         * @param hmac              Whether this is HMAC operation
         * @param secret            The buffer containing key for hmac operation
         * @param secretLen         The length of the secret buffer
         * @return                  SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus createHashState(const uint32_t& hashId,
                                  const HashMode& hashMode,
                                  const bool&     hmac,
                                  const uint8_t*  secret,
                                  const uint32_t& secretLen);

        /**
        * Hashes the data
        * @param hashId            The hash handle from provider
        * @param sourceBuffer      The input buffer to be hashed
        * @param sourceBufferLen   The length of the input buffer
        * @return                  SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus hashData(const uint32_t&  hashId,
                           const uint8_t*   sourceBuffer,
                           const uint32_t&  sourceBufferLen);

        /**
        * Returns the hash
        * @param hashId            The hash handle from provider
        * @param destBuffer        The output buffer to to hold the hash
        * @param destBufferLen     The length of the output buffer
        * @return                  SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus getHashDigest(const uint32_t& hashId,
                                uint8_t*        destBuffer,
                                const uint32_t& destBufferLen);

        /**
        * Destroys the hash state
        * @param hashId            The hash handle from provider
        * @return                  SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus destroyHash(const uint32_t& hashId);

        /**
        * Computes hash of a buffer
        * @param hashMode        The hashMode to be used
        * @param srcBuffer       The source buffer to be hashed
        * @param srcBufferLen    The length of the source buffer
        * @param destBuffer      The destination buffer to hold the hash digest
        * @param destBufferLen   The length of the destination buffer
        */
        bool computeHash(const HashMode& hashMode,
                         const Byte*     srcBuffer,
                         const uint32_t& srcBufferLen,
                         Byte*           destBuffer,
                         const uint32_t& destBufferLen);

        /**
        * Clears the hash state cache
        */
        void clearStates();

    private:
        bool getHashState(const uint32_t& hashId,
                          HashState*      hashState);

        void addHashState(const uint32_t&   hashId,
                          const HashMode&   hashMode,
                          const bool&       hmac,
                          ByteBuffer        hashContext);

        HashStateCache  mHashStateCache;
    };

} //CryptoSgx

#endif //CRYPTO_HASH_H

