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

#include "HashProvider.h"

namespace P11Crypto
{
    namespace HashProvider
    {
        //---------------------------------------------------------------------------------------------
        CK_RV hashInit(uint32_t*       hashHandle,
                       const uint32_t& keyHandleForHmac,
                       const HashMode& hashMode,
                       const bool&     hmac)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = generateId(enclaveHelpers.getSgxEnclaveId(),
                                       reinterpret_cast<int32_t*>(&enclaveStatus),
                                       hashHandle);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    break;
                }

                sgxStatus = digestInit(enclaveHelpers.getSgxEnclaveId(),
                                       reinterpret_cast<int32_t*>(&enclaveStatus),
                                       *hashHandle,
                                       keyHandleForHmac,
                                       static_cast<uint8_t>(hashMode),
                                       static_cast<uint8_t>(hmac));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    // Clean up the hash handle in enclave cache
                    sgxStatus = destroyHashState(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                 *hashHandle);
                }

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV hashUpdate(const uint32_t& hashHandle,
                         const uint8_t*  sourceBuffer,
                         const uint32_t& sourceBufferLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = digestUpdate(enclaveHelpers.getSgxEnclaveId(),
                                         reinterpret_cast<int32_t*>(&enclaveStatus),
                                         hashHandle,
                                         sourceBuffer, sourceBufferLen);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV hashFinal(const uint32_t& hashHandle,
                        uint8_t*        destBuffer,
                        const uint32_t& destBufferLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = digestFinal(enclaveHelpers.getSgxEnclaveId(),
                                        reinterpret_cast<int32_t*>(&enclaveStatus),
                                        hashHandle,
                                        destBuffer, destBufferLen);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV destroyHash(const uint32_t& hashHandle)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = destroyHashState(enclaveHelpers.getSgxEnclaveId(),
                                             reinterpret_cast<int32_t*>(&enclaveStatus),
                                             hashHandle);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    break;
                }

                rv = CKR_OK;
            } while (false);

            return rv;
        }
    }
}