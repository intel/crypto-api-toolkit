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

#include <sgx_error.h>
#include <vector>

#include "SymmetricProvider.h"
#include "EnclaveHelpers.h"
#include "Constants.h"
#include "p11Enclave_u.h"

namespace P11Crypto
{
    std::recursive_mutex SymmetricProvider::mProviderMutex;

    //---------------------------------------------------------------------------------------------
    std::shared_ptr<SymmetricProvider> SymmetricProvider::getSymmetricProvider()
    {
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        std::shared_ptr<SymmetricProvider> symmetricProvider = std::make_shared<SymmetricProvider>();

        ulock.unlock();
        return symmetricProvider;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::generateKey(const CK_SESSION_HANDLE& hSession,
                                         const CK_ATTRIBUTE_PTR   pTemplate,
                                         const CK_ULONG&          ulCount,
                                         CK_OBJECT_HANDLE_PTR     phKey,
                                         Attributes&              keyAttributes)
    {
        CK_RV                   rv            = CKR_FUNCTION_FAILED;
        uint32_t                keyLength     = 0;
        uint32_t                keyHandle     = 0;
        bool                    importRawKey  = false;
        bool                    generateKey   = false;
        sgx_status_t            sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus          enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        std::string             label, id;
        CK_KEY_TYPE             keyType;
        CK_OBJECT_CLASS         keyClass;
        std::vector<uint8_t>    rawKeyBuffer;
        EnclaveHelpers          enclaveHelpers;
        KeyGenerationMechanism  keyGenMechanism;
        uint32_t                attributeBitmask;
        AttributeHelpers        attributeHelpers;

        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!pTemplate  ||
                !phKey)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            rv = attributeHelpers.getSymmetricKeyParameters(pTemplate,
                                                            ulCount,
                                                            importRawKey,
                                                            generateKey,
                                                            rawKeyBuffer,
                                                            keyLength);
            if (CKR_OK != rv)
            {
                break;
            }

            if (importRawKey && generateKey)
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }

            if (importRawKey)
            {
                keyGenMechanism = KeyGenerationMechanism::aesImportRawKey;
                rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                    pTemplate,
                                                                    ulCount,
                                                                    attributeBitmask,
                                                                    label,
                                                                    id,
                                                                    keyClass,
                                                                    keyType);
                if (CKR_OK != rv)
                {
                    break;
                }

                attributeHelpers.populateAttributes(attributeBitmask,
                                                    label,
                                                    id,
                                                    keyGenMechanism,
                                                    keyClass,
                                                    keyType,
                                                    keyAttributes);
#ifndef IMPORT_RAW_KEY
                rv = CKR_GENERAL_ERROR;
                break;
#else
                sgxStatus = importSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                               reinterpret_cast<int32_t*>(&enclaveStatus),
                                               &keyHandle,
                                               rawKeyBuffer.data(),
                                               rawKeyBuffer.size());
#endif
            }
            else if (generateKey)
            {
                keyGenMechanism = KeyGenerationMechanism::aesGenerateKey;
                rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                    pTemplate,
                                                                    ulCount,
                                                                    attributeBitmask,
                                                                    label,
                                                                    id,
                                                                    keyClass,
                                                                    keyType);
                if (CKR_OK != rv)
                {
                    break;
                }

                attributeHelpers.populateAttributes(attributeBitmask,
                                                    label,
                                                    id,
                                                    keyGenMechanism,
                                                    keyClass,
                                                    keyType,
                                                    keyAttributes);

                if (!(static_cast<uint16_t>(SymmetricKeySize::keyLength128) == keyLength ||
                      static_cast<uint16_t>(SymmetricKeySize::keyLength192) == keyLength ||
                      static_cast<uint16_t>(SymmetricKeySize::keyLength256) == keyLength))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                sgxStatus = generateSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                 &keyHandle,
                                                 keyLength);
            }
            else
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                break;
            }

            *phKey = keyHandle;
        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::destroyKey(const uint32_t&                          keyHandle,
                                        std::shared_ptr<SymmetricKeyHandleCache> keyHandleCache)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            // Clean up keyHandle in enclave cache
            sgxStatus = destroySymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                            reinterpret_cast<int32_t*>(&enclaveStatus),
                                            keyHandle);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                break;
            }

            // Clean up keyhandle in provider cache
            keyHandleCache->remove(keyHandle);

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::encryptInit(const uint32_t&   keyHandle,
                                         const uint8_t*    iv,
                                         const uint32_t&   ivSize,
                                         const uint8_t*    aad,
                                         const uint32_t&   aadSize,
                                         const uint8_t&    cipherMode,
                                         const int&        padding,
                                         const uint32_t&   tagBits,
                                         const int&        counterBits)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = symmetricEncryptInit(enclaveHelpers.getSgxEnclaveId(),
                                             reinterpret_cast<int32_t*>(&enclaveStatus),
                                             keyHandle,
                                             iv,
                                             ivSize,
                                             aad,
                                             aadSize,
                                             cipherMode,
                                             padding,
                                             tagBits,
                                             counterBits);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::encryptUpdate(const uint32_t&   keyHandle,
                                           const uint8_t*    sourceBuffer,
                                           const uint32_t&   sourceBufferLen,
                                           uint8_t*          encryptedData,
                                           const uint32_t&   encryptedDataLen,
                                           uint32_t&         destBufferRequiredLen)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

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
                                               sourceBuffer,
                                               sourceBufferLen,
                                               encryptedData,
                                               encryptedDataLen,
                                               &destBufferRequiredLen);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::encryptFinal(const uint32_t&   keyHandle,
                                          uint8_t*          encryptedData,
                                          uint32_t&         destBufferRequiredLen)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = symmetricEncryptFinal(enclaveHelpers.getSgxEnclaveId(),
                                              reinterpret_cast<int32_t*>(&enclaveStatus),
                                              keyHandle,
                                              encryptedData,
                                              &destBufferRequiredLen);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::decryptInit(const uint32_t&   keyHandle,
                                         const uint8_t*    iv,
                                         const uint32_t&   ivSize,
                                         const uint8_t*    aad,
                                         const uint32_t&   aadSize,
                                         const uint8_t&    cipherMode,
                                         const int&        padding,
                                         const uint32_t&   tagBits,
                                         const int&        counterBits)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = symmetricDecryptInit(enclaveHelpers.getSgxEnclaveId(),
                                             reinterpret_cast<int32_t*>(&enclaveStatus),
                                             keyHandle,
                                             iv,
                                             ivSize,
                                             aad,
                                             aadSize,
                                             cipherMode,
                                             padding,
                                             tagBits,
                                             counterBits);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::decryptUpdate(const uint32_t&   keyHandle,
                                           const uint8_t*    encryptedData,
                                           const uint32_t&   encryptedDataLen,
                                           uint8_t*          destBuffer,
                                           const uint32_t&   destBufferLen,
                                           uint32_t&         destBufferRequiredLen)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

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
                                               encryptedData,
                                               encryptedDataLen,
                                               destBuffer,
                                               destBufferLen,
                                               &destBufferRequiredLen);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::decryptFinal(const uint32_t&   keyHandle,
                                          uint8_t*          decryptedData,
                                          uint32_t&         destBufferRequiredLen)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = symmetricDecryptFinal(enclaveHelpers.getSgxEnclaveId(),
                                              reinterpret_cast<int32_t*>(&enclaveStatus),
                                              keyHandle,
                                              decryptedData,
                                              &destBufferRequiredLen);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                destBufferRequiredLen = 0;
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::wrapKey(const uint32_t&    wrappingKeyHandle,
                                     const uint32_t&    keyHandleData,
                                     const uint8_t*     iv,
                                     const uint32_t&    ivSize,
                                     const uint8_t*     aad,
                                     const uint32_t&    aadSize,
                                     const uint8_t&     cipherMode,
                                     const int&         padding,
                                     const uint32_t&    tagBits,
                                     const int&         counterBits,
                                     uint8_t*           destBuffer,
                                     const uint32_t&    destBufferLen,
                                     uint32_t&          destBufferLenRequired)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = wrapSymmetricKeyWithSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                         reinterpret_cast<int32_t*>(&enclaveStatus),
                                                         wrappingKeyHandle,
                                                         keyHandleData,
                                                         iv,
                                                         ivSize,
                                                         aad,
                                                         aadSize,
                                                         cipherMode,
                                                         padding,
                                                         tagBits,
                                                         counterBits,
                                                         destBuffer,
                                                         destBufferLen,
                                                         &destBufferLenRequired);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::platformbindKey(const uint32_t&    keyHandle,
                                             uint8_t*           destBuffer,
                                             const uint32_t&    destBufferLen,
                                             uint32_t&          destBufferLenRequired)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = platformBindSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                 keyHandle,
                                                 destBuffer,
                                                 destBufferLen,
                                                 &destBufferLenRequired);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::unwrapKey(const uint32_t&  unwrappingKeyHandle,
                                       uint32_t*        keyHandle,
                                       const uint8_t*   sourceBuffer,
                                       const uint32_t&  sourceBufferLen,
                                       const uint8_t*   iv,
                                       const uint32_t&  ivSize,
                                       const uint8_t*   aad,
                                       const uint32_t&  aadSize,
                                       const uint8_t&   cipherMode,
                                       const int&       padding,
                                       const uint32_t&  tagBits,
                                       const int&       counterBits)
    {
        CK_RV               rv                 = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus          = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus      = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        uint32_t            unwrappedKeyHandle = 0;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!keyHandle ||
                !sourceBuffer)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }
            sgxStatus = unwrapSymmetricKeyWithSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                           reinterpret_cast<int32_t*>(&enclaveStatus),
                                                           unwrappingKeyHandle,
                                                           &unwrappedKeyHandle,
                                                           sourceBuffer,
                                                           sourceBufferLen,
                                                           iv,
                                                           ivSize,
                                                           aad,
                                                           aadSize,
                                                           static_cast<uint8_t>(cipherMode),
                                                           padding,
                                                           tagBits,
                                                           counterBits);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                break;
            }

            *keyHandle = unwrappedKeyHandle;

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SymmetricProvider::importPlatformBoundKey(uint32_t*       keyHandle,
                                                    const uint8_t*  sourceBuffer,
                                                    const uint32_t& sourceBufferLen)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!keyHandle ||
                !sourceBuffer)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            sgxStatus = unwrapAndImportPlatformBoundSymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                                 reinterpret_cast<int32_t*>(&enclaveStatus),
                                                                 keyHandle,
                                                                 sourceBuffer,
                                                                 sourceBufferLen);
            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

        } while (false);

        ulock.unlock();
        return rv;
    }
}
