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

#ifndef HASH_PROVIDER_H
#define HASH_PROVIDER_H


#include <sgx_error.h>

#include "EnclaveUtils.h"

namespace P11Crypto
{
    static std::map<HashMode, HashDigestLength> hashDigestLengthMap = {
                                                                        { HashMode::sha256, HashDigestLength::sha256 },
                                                                        { HashMode::sha512, HashDigestLength::sha512 }
                                                                      };
    namespace HashProvider
    {
        //---------------------------------------------------------------------------------------------
        /**
        * Initializes a hash operation.
        * @param    hashHandle          The hash handle.
        * @param    keyHandleForHmac    The symmetric key handle to be used as key for HMAC.
        * @param    hashMode            The HashMode to be used.
        * @param    hmac                True if hmac, false otherwise.
        * @return	CK_RV		        CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV hashInit(uint32_t*       hashHandle,
                       const uint32_t& keyHandleForHmac,
                       const HashMode& hashMode,
                       const bool&     hmac);

        //---------------------------------------------------------------------------------------------
        /**
        * Continues a hash operation.
        * @param    hashHandle          The hash handle.
        * @param    sourceBuffer        The data to be hashed.
        * @param    sourceBufferLen     The length in bytes of data to be hashed.
        * @return	CK_RV		        CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV hashUpdate(const uint32_t& hashHandle,
                         const uint8_t*  sourceBuffer,
                         const uint32_t& sourceBufferLen);

        //---------------------------------------------------------------------------------------------
        /**
        * Finalizes a hash operation.
        * @param    hashHandle        The hash handle.
        * @param    destBuffer        The buffer to hold the hash.
        * @param    destBufferLen     The length in bytes of destBuffer.
        * @return	CK_RV		      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV hashFinal(const uint32_t& hashHandle,
                        uint8_t*        destBuffer,
                        const uint32_t& destBufferLen);

        //---------------------------------------------------------------------------------------------
        /**
        * Clears the removes a hash handle from the hashHandle cache.
        * @param    hashHandle        The hash handle.
        * @return	CK_RV		      CKR_OK if operation is successful, error code otherwise.
        */
        CK_RV destroyHash(const uint32_t& hashHandle);
    };
}
#endif //HASH_PROVIDER_H

