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

#ifndef ENCLAVE_IPP_HASH_H
#define ENCLAVE_IPP_HASH_H

#include <map>
#include <ipp/ippcp.h>

#include "ByteBuffer.h"
#include "CryptoEnclaveDefs.h"

namespace CryptoSgx
{
    /**
     * Class used to encrypt using IPP Crypto functions.
     */
    class IppHash
    {
    public:
        /**
         * Constructor.
         */
        IppHash(const HashMode& hashMode, const bool& hmac);

        /**
        * Gets the IPP hash/hmac state size.
        * @return   The size of the ipp hash/hmac state.
        */
        int getSize();

        /**
         * Initializes the hashing process.
         * @param destBuffer        The buffer that holds the ipp context.
         * @param destBufferLen     The length of the destination buffer.
         * @param secret            The secret passed for HMAC, relevant only for hmac.
         * @param secretLen         The length of the secret, relevant only for hmac.
         * @return                  True if the operation was successful, false otherwise.
         */
        bool init (void*            destBuffer,
                   const uint32_t&  destBufferLen,
                   const uint8_t*   secret      = nullptr,
                   const uint32_t&  secretLen   = 0);

        /**
         * Does a hash update to the buffer passed.
         * @param ippCtx           IPP hash context.
         * @param sourceBuffer     The source buffer to be hashed.
         * @param sourceBufferLen  The length of the source buffer.
         * @return                 True if the operation was successful, false otherwise.
         */
        bool update(void*           ippCtx,
                    Byte*           sourceBuffer,
                    const uint32_t& sourceBufferLen);

        /**
         * Finalizes the hash.
         * @param ippCtx          IPP hash context
         * @param destBuffer      The destination buffer to hold the hash digest
         * @param destBufferLen   The length of the destination buffer
         * @return                True if the operation was successful, false otherwise.
         */
        bool final(void*           ippCtx,
                   Byte*           destBuffer,
                   const uint32_t& destBufferLen);

    private:
        IppHash(const IppHash& other);
        IppHash& operator=(const IppHash& other);

        HashMode    mHashMode;
        bool        mHmac;
    };

} //CryptoSgx

#endif // IPP_HASH_H
