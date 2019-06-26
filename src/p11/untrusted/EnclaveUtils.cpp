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

#include "EnclaveUtils.h"

namespace Utils
{
    namespace EnclaveUtils
    {
        //---------------------------------------------------------------------------------------------
        bool loadEnclave()
        {
            P11Crypto::EnclaveHelpers enclaveHelpers;

            if (!enclaveHelpers.isSgxEnclaveLoaded())
            {
                if (sgx_status_t::SGX_SUCCESS != enclaveHelpers.loadSgxEnclave())
                {
                    return false;
                }
            }

            return true;
        }

        //---------------------------------------------------------------------------------------------
        void unloadEnclave()
        {
            P11Crypto::EnclaveHelpers enclaveHelpers;

            if (enclaveHelpers.isSgxEnclaveLoaded())
            {
                enclaveHelpers.unloadSgxEnclave();
            }
        }

        //---------------------------------------------------------------------------------------------
        std::string sealDataBlob(const std::string& input, const bool& pin)
        {
            CK_RV                     rv              = CKR_FUNCTION_FAILED;
            sgx_status_t              sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus            enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
            uint32_t                  bytesNeeded     = 0;
            P11Crypto::EnclaveHelpers enclaveHelpers;
            std::vector<uint8_t>      destBuffer;
            std::string               sealedOutput;

            do
            {
                if (!pin)
                {
                    sgxStatus = sealData(enclaveHelpers.getSgxEnclaveId(),
                                         reinterpret_cast<int32_t*>(&enclaveStatus),
                                         const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&input.at(0))),
                                         input.size(),
                                         nullptr,
                                         destBuffer.size(),
                                         &bytesNeeded);
                }
                else
                {
                    sgxStatus = sealPin(enclaveHelpers.getSgxEnclaveId(),
                                        reinterpret_cast<int32_t*>(&enclaveStatus),
                                        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&input.at(0))),
                                        input.size(),
                                        nullptr,
                                        destBuffer.size(),
                                        &bytesNeeded);
                }


                rv = getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    break;
                }

                destBuffer.resize(bytesNeeded);

                if (!pin)
                {
                    sgxStatus = sealData(enclaveHelpers.getSgxEnclaveId(),
                                         reinterpret_cast<int32_t*>(&enclaveStatus),
                                        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&input.at(0))),
                                         input.size(),
                                         destBuffer.data(),
                                         destBuffer.size(),
                                         &bytesNeeded);
                }
                else
                {
                    sgxStatus = sealPin(enclaveHelpers.getSgxEnclaveId(),
                                        reinterpret_cast<int32_t*>(&enclaveStatus),
                                        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&input.at(0))),
                                        input.size(),
                                        destBuffer.data(),
                                        destBuffer.size(),
                                        &bytesNeeded);
                }

                rv = getPkcsStatus(sgxStatus, enclaveStatus);

                sealedOutput.assign(destBuffer.begin(), destBuffer.end());
            } while(false);

            return sealedOutput;
        }

        //---------------------------------------------------------------------------------------------
        uint32_t generateRandom()
        {
            sgx_status_t              sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus            enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t                  id            = 0;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            sgxStatus = generateId(enclaveHelpers.getSgxEnclaveId(),
                                   reinterpret_cast<int32_t*>(&enclaveStatus),
                                   &id);

            CK_RV rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);
            if (CKR_OK != rv)
            {
                id = 0;
            }

            return id;
        }

        //---------------------------------------------------------------------------------------------
        void cleanUpState(const uint32_t& keyId)
        {
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            sgxStatus = clearCacheState(enclaveHelpers.getSgxEnclaveId(),
                                        reinterpret_cast<int32_t*>(&enclaveStatus),
                                        keyId);
        }

        //---------------------------------------------------------------------------------------------
        CK_RV destroyKey(const CK_OBJECT_HANDLE& objectHandle, const KeyType& keyType)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            sgxStatus = ::destroyKey(enclaveHelpers.getSgxEnclaveId(),
                                     reinterpret_cast<int32_t*>(&enclaveStatus),
                                     objectHandle,
                                     static_cast<uint8_t>(keyType));

            rv = getPkcsStatus(sgxStatus, enclaveStatus);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getPkcsStatus(const sgx_status_t& sgxStatus, const SgxCryptStatus& enclaveStatus)
        {
            P11Crypto::EnclaveHelpers enclaveHelpers;

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                return CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                return CKR_GENERAL_ERROR;
            }
            else
            {
                return enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getRsaModulusExponent(const CK_OBJECT_HANDLE&  keyHandle,
                                    const CK_ATTRIBUTE_TYPE& attributeType,
                                    const bool&              attributeValueNull,
                                    std::string*             attributeValue,
                                    uint32_t*                attributeSize)
        {
            if (!attributeValue || !attributeSize)
            {
                return CKR_GENERAL_ERROR;
            }

            if ((CKA_MODULUS         != attributeType) &&
                (CKA_PUBLIC_EXPONENT != attributeType))
            {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }

            CK_RV          rv                    = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus             = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus         = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
            uint32_t       destBufferLenRequired = 0;
            uint32_t       modulusSize           = 0;
            uint32_t       exponentSize          = 0;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            sgxStatus = asymmetricExportKey(enclaveHelpers.getSgxEnclaveId(),
                                            reinterpret_cast<int32_t*>(&enclaveStatus),
                                            keyHandle,
                                            nullptr,
                                            0,
                                            &destBufferLenRequired,
                                            &modulusSize,
                                            &exponentSize);

            rv = getPkcsStatus(sgxStatus, enclaveStatus);
            if (CKR_OK != rv)
            {
                return rv;
            }

            *attributeSize = (CKA_MODULUS == attributeType) ? modulusSize : exponentSize;

            if (attributeValueNull)
            {
                return rv;
            }

            std::vector<uint8_t> destBuffer(destBufferLenRequired, 0);
            destBufferLenRequired = 0;

            sgxStatus = asymmetricExportKey(enclaveHelpers.getSgxEnclaveId(),
                                            reinterpret_cast<int32_t*>(&enclaveStatus),
                                            keyHandle,
                                            destBuffer.data(),
                                            destBuffer.size(),
                                            &destBufferLenRequired,
                                            &modulusSize,
                                            &exponentSize);

            rv = getPkcsStatus(sgxStatus, enclaveStatus);

            if (CKR_OK != rv)
            {
                *attributeSize = 0;
            }
            else
            {
                if (CKA_MODULUS == attributeType)
                {
                    (*attributeValue).assign(reinterpret_cast<const char*>(destBuffer.data() + exponentSize), modulusSize);
                }
                else if (CKA_PUBLIC_EXPONENT == attributeType)
                {
                    (*attributeValue).assign(reinterpret_cast<const char*>(destBuffer.data()), exponentSize);
                }
            }

            return rv;
        }
    }
}