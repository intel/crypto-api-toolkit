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

#ifndef ENCLAVE_UTILS_H
#define ENCLAVE_UTILS_H

#include "Constants.h"
#include "EnclaveHelpers.h"
#include <string>

namespace Utils
{
    namespace EnclaveUtils
    {
        uint32_t generateRandom();

        std::string sealDataBlob(const std::string& input, const bool& pin = false);

        bool loadEnclave();

        void unloadEnclave();

        void cleanUpState(const uint32_t& keyId);

        CK_RV destroyKey(const CK_OBJECT_HANDLE& objectHandle, const KeyType& keyType);

        CK_RV getPkcsStatus(const sgx_status_t& sgxStatus, const SgxCryptStatus& enclaveStatus);

        CK_RV getRsaModulusExponent(const CK_OBJECT_HANDLE&  keyHandle,
                                    const CK_ATTRIBUTE_TYPE& attributeType,
                                    const bool&              attributeValueNull,
                                    std::string*             attributeValue,
                                    uint32_t*                attributeSize);
    }
}

#endif //ENCLAVE_UTILS_H