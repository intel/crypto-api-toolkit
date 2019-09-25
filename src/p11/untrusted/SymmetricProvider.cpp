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

#include "SymmetricProvider.h"

namespace P11Crypto
{
    namespace SymmetricProvider
    {
        //---------------------------------------------------------------------------------------------
        CK_RV generateAesKey(const SymmetricKeyParams&    symKeyParams,
                             const bool&                  importKey,
                             const std::vector<CK_ULONG>& packedAttributes,
                             CK_OBJECT_HANDLE_PTR         phKey)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t       keyHandle     = 0;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            if (!phKey)
            {
                return CKR_ARGUMENTS_BAD;
            }

            if (importKey)
            {
#ifndef IMPORT_RAW_KEY
                return CKR_IMPORT_RAW_KEY_UNSUPPORTED;
#else
                sgxStatus = importSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                               reinterpret_cast<int32_t*>(&enclaveStatus),
                                               &keyHandle,
                                               symKeyParams.rawKeyBuffer.data(),
                                               symKeyParams.rawKeyBuffer.size(),
                                               packedAttributes.data(),
                                               packedAttributes.size() * sizeof(CK_ULONG));
#endif
            }
            else
            {
                sgxStatus = generateSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                 &keyHandle,
                                                 symKeyParams.keyLength,
                                                 packedAttributes.data(),
                                                 packedAttributes.size() * sizeof(CK_ULONG));
            }


            rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            if (CKR_OK == rv)
            {
                *phKey = keyHandle;
            }
            else
            {
                *phKey = CK_INVALID_HANDLE;
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV encryptInit(const uint32_t& keyHandle, const AesCryptParams& aesCryptParams)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = symmetricEncryptInit(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                 keyHandle,
                                                 aesCryptParams.iv.data(),  aesCryptParams.iv.size(),
                                                 aesCryptParams.aad.data(), aesCryptParams.aad.size(),
                                                 static_cast<int>(aesCryptParams.cipherMode),
                                                 aesCryptParams.padding,
                                                 aesCryptParams.tagBits,
                                                 aesCryptParams.counterBits);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV decryptInit(const uint32_t& keyHandle, const AesCryptParams& aesCryptParams)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = symmetricDecryptInit(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                 keyHandle,
                                                 aesCryptParams.iv.data(),  aesCryptParams.iv.size(),
                                                 aesCryptParams.aad.data(), aesCryptParams.aad.size(),
                                                 static_cast<int>(aesCryptParams.cipherMode),
                                                 aesCryptParams.padding,
                                                 aesCryptParams.tagBits,
                                                 aesCryptParams.counterBits);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV encryptUpdate(const uint32_t& keyHandle,
                            const uint8_t*  sourceBuffer,
                            const uint32_t& sourceBufferLen,
                            uint8_t*        encryptedData,
                            const uint32_t& encryptedDataLen,
                            uint32_t*       destBufferRequiredLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                if (!sourceBuffer)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                sgxStatus = symmetricEncryptUpdate(enclaveHelpers.getSgxEnclaveId(),
                                                   reinterpret_cast<int32_t*>(&enclaveStatus),
                                                   keyHandle,
                                                   sourceBuffer,  sourceBufferLen,
                                                   encryptedData, encryptedDataLen,
                                                   destBufferRequiredLen);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV decryptUpdate(const uint32_t& keyHandle,
                            const uint8_t*  encryptedData,
                            const uint32_t& encryptedDataLen,
                            uint8_t*        destBuffer,
                            const uint32_t& destBufferLen,
                            uint32_t*       destBufferRequiredLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            do
            {
                if (!encryptedData)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                sgxStatus = symmetricDecryptUpdate(enclaveHelpers.getSgxEnclaveId(),
                                                   reinterpret_cast<int32_t*>(&enclaveStatus),
                                                   keyHandle,
                                                   encryptedData, encryptedDataLen,
                                                   destBuffer,    destBufferLen,
                                                   destBufferRequiredLen);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV encryptFinal(const uint32_t& keyHandle,
                           uint8_t*        encryptedData,
                           uint32_t*       destBufferRequiredLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = symmetricEncryptFinal(enclaveHelpers.getSgxEnclaveId(),
                                                reinterpret_cast<int32_t*>(&enclaveStatus),
                                                keyHandle,
                                                encryptedData,
                                                destBufferRequiredLen);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV decryptFinal(const uint32_t& keyHandle,
                           uint8_t*        decryptedData,
                           uint32_t*       destBufferRequiredLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                if (!destBufferRequiredLen)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                sgxStatus = symmetricDecryptFinal(enclaveHelpers.getSgxEnclaveId(),
                                                reinterpret_cast<int32_t*>(&enclaveStatus),
                                                keyHandle,
                                                decryptedData,
                                                destBufferRequiredLen);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    *destBufferRequiredLen = 0;
                }

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV wrapKey(const uint32_t&       wrappingKeyHandle,
                      const uint32_t&       keyHandleData,
                      const AesCryptParams& aesCryptParams,
                      uint8_t*              destBuffer,
                      const uint32_t&       destBufferLen,
                      uint32_t*             destBufferLenRequired)
        {
            CK_RV               rv              = CKR_FUNCTION_FAILED;
            sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers      enclaveHelpers;

            do
            {
                sgxStatus = wrapSymmetricKeyWithSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                             reinterpret_cast<int32_t*>(&enclaveStatus),
                                                             wrappingKeyHandle,
                                                             keyHandleData,
                                                             aesCryptParams.iv.data(),  aesCryptParams.iv.size(),
                                                             aesCryptParams.aad.data(), aesCryptParams.aad.size(),
                                                             static_cast<uint8_t>(aesCryptParams.cipherMode),
                                                             static_cast<int>(aesCryptParams.padding),
                                                             aesCryptParams.tagBits,
                                                             aesCryptParams.counterBits,
                                                             destBuffer, destBufferLen,
                                                             destBufferLenRequired);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV unwrapKey(const uint32_t&              unwrappingKeyHandle,
                        const uint8_t*               sourceBuffer,
                        const uint32_t&              sourceBufferLen,
                        const AesCryptParams&        aesCryptParams,
                        const KeyType&               wrappedKeyType,
                        const std::vector<CK_ULONG>& packedAttributes,
                        uint32_t*                    keyHandle)
        {
            CK_RV          rv                 = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus          = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus      = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t       unwrappedKeyHandle = 0;
            EnclaveHelpers enclaveHelpers;

            do
            {
                if (!keyHandle || !sourceBuffer)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                sgxStatus = unwrapWithSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                   reinterpret_cast<int32_t*>(&enclaveStatus),
                                                   unwrappingKeyHandle,
                                                   &unwrappedKeyHandle,
                                                   sourceBuffer, sourceBufferLen,
                                                   aesCryptParams.iv.data(),  aesCryptParams.iv.size(),
                                                   aesCryptParams.aad.data(), aesCryptParams.aad.size(),
                                                   static_cast<uint8_t>(aesCryptParams.cipherMode),
                                                   static_cast<int>(aesCryptParams.padding),
                                                   aesCryptParams.tagBits,
                                                   aesCryptParams.counterBits,
                                                   static_cast<uint8_t>(wrappedKeyType),
                                                   packedAttributes.data(),
                                                   packedAttributes.size() * sizeof(CK_ULONG));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);
                if (CKR_OK != rv)
                {
                    break;
                }

                *keyHandle = unwrappedKeyHandle;

            } while (false);

            return rv;
        }
    }
}
