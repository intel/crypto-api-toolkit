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

#ifndef TOKEN_OBJECT_PARSER_H
#define TOKEN_OBJECT_PARSER_H

#include <string>
#include <mbusafecrt.h>
#include <sgx_trts.h>
#include <sgx_tprotected_fs.h>
#include "CryptoEnclaveDefs.h"
#include "SymmetricKeyCache.h"
#include "SgxFileUtils.h"
#include "ByteBuffer.h"

namespace Utils
{
    namespace TokenObjectParser
    {
        uint64_t getSlotId(const uint64_t* attributeBuffer, const uint32_t& attributeBufferLen);

        bool writeTokenObject(const std::string&           fileName,
                              const CryptoSgx::ByteBuffer& pinMaterial,
                              const uint64_t*              attributeBuffer,
                              const uint64_t&              attributeBufferLen,
                              const uint8_t*               keyBuffer,
                              const uint64_t&              keyBufferLen,
                              const bool&                  usedForWrapping,
                              const uint64_t&              pairKeyId,
                              std::string*                 filePath);

        bool readTokenObject(const std::string&           filePath,
                             const CryptoSgx::ByteBuffer& pinMaterial,
                             uint64_t*                    attributeBuffer,
                             uint64_t                     attributeBufferLen,
                             uint64_t*                    attributeBufferLenRequired,
                             uint8_t*                     keyBuffer,
                             uint64_t                     keyBufferLen,
                             uint64_t*                    keyBufferLenRequired,
                             bool*                        usedForWrapping,
                             uint64_t*                    pairKeyId,
                             bool                         bufferLenRequest = false);

        bool updatePinMaterial(const std::string&           filePath,
                               const CryptoSgx::ByteBuffer& pinMaterial);

        bool setWrappingStatus(const std::string& filePath,
                               const uint64_t&    pairKeyId);
    }
}

#endif // TOKEN_OBJECT_PARSER_H