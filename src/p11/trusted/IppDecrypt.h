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

#ifndef ENCLAVE_IPP_DECRYPT_H
#define ENCLAVE_IPP_DECRYPT_H

#include "ByteBuffer.h"
#include "IppContextHandle.h"
#include "CryptParams.h"
#include "IppStateCache.h"

namespace CryptoSgx
{
    /**
     * Class used to decrypt using Ipp Crypto functions.
     */
    class IppDecrypt
    {
    public:
        /**
         * Constructor.
         */
        IppDecrypt();

        /**
         * Initializes a multi-part decryption process.
         * @param   cryptParams   A pointer to CryptParams structure containing necessary parameters.
         * @return                True if the operation was successful, false otherwise.
         */
        bool decryptInit(const CryptParams& cryptParams);

        /**
        * Continues a multi-part decryption process.
        * @param ippCtxState        The ipp state.
        * @param destBuffer         The destination buffer where the decrypted output goes into.
        * @param decryptedBytes     The number of bytes decrypted.
        * @param sourceBuffer       The input buffer to be decrypted.
        * @param sourceBufferLen    The length of the input buffer.
        * @return                   True if decryption is successful, false otherwise.
        */
        bool decryptUpdate(IppCtxState&    ippCtxState,
                           uint8_t*        destBuffer,
                           int&            decryptedBytes,
                           const uint8_t*  sourceBuffer,
                           const int       sourceBufferLen);

        /**
         * Finalizes a multi-part decryption process.
         * @param ippCtxState   The evp state.
         */
        void decryptFinal(IppCtxState& ippCtxState);

        /**
         * Gets the ipp context handle.
         * @return  IppContextHandle    The Ipp Context Handle.
        */
        IppContextHandle& getIppContext();

    private:
        // Member variables
        IppContextHandle mContext;

        IppStateCache mIppCtxStateCache;
    };

} //CryptoSgx

#endif //ENCLAVE_IPP_DECRYPT_H

