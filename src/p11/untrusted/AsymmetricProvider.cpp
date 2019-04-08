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
#include <sgx_uae_service.h>
#include <vector>
#include <functional>

#include "AsymmetricProvider.h"
#include "EnclaveHelpers.h"
#include "p11Enclave_u.h"

namespace P11Crypto
{
    std::recursive_mutex AsymmetricProvider::mProviderMutex;

    //---------------------------------------------------------------------------------------------
    std::shared_ptr<AsymmetricProvider> AsymmetricProvider::getAsymmetricProvider()
    {
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        std::shared_ptr<AsymmetricProvider> asymmetricProvider = std::make_shared<AsymmetricProvider>();

        ulock.unlock();
        return asymmetricProvider;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AsymmetricProvider::generateKeyPair(const CK_SESSION_HANDLE& hSession,
                                              const CK_ATTRIBUTE_PTR   pPublicKeyTemplate,
                                              const CK_ULONG&          ulPublicKeyAttributeCount,
                                              const CK_ATTRIBUTE_PTR   pPrivateKeyTemplate,
                                              const CK_ULONG&          ulPrivateKeyAttributeCount,
                                              CK_OBJECT_HANDLE_PTR     phPublicKey,
                                              CK_OBJECT_HANDLE_PTR     phPrivateKey,
                                              Attributes&              publicKeyAttributes,
                                              Attributes&              privateKeyAttributes)
    {
        CK_RV                  rv                         = CKR_FUNCTION_FAILED;
        sgx_status_t           sgxStatus                  = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus         enclaveStatus              = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool                   hasModulusLength           = false;
        uint32_t               modulusLength              = 0;
        uint32_t               privateKeyAttributeBitmask = 0;
        uint32_t               publicKeyAttributeBitmask  = 0;
        uint32_t               publicKeyHandle            = 0;
        uint32_t               privateKeyHandle           = 0;
        KeyGenerationMechanism keyGenMechanism;
        std::string            publicKeyLabel, privateKeyLabel, publicKeyId, privateKeyId;
        CK_OBJECT_CLASS        publicKeyClass, privateKeyClass;
        CK_KEY_TYPE            publicKeyType,  privateKeyType;
        EnclaveHelpers         enclaveHelpers;
        AttributeHelpers       attributeHelpers;

        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!pPublicKeyTemplate  ||
                !pPrivateKeyTemplate ||
                !phPublicKey         ||
                !phPrivateKey)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            keyGenMechanism = KeyGenerationMechanism::rsaGeneratePublicKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pPublicKeyTemplate,
                                                                ulPublicKeyAttributeCount,
                                                                publicKeyAttributeBitmask,
                                                                publicKeyLabel,
                                                                publicKeyId,
                                                                publicKeyClass,
                                                                publicKeyType);
            if (CKR_OK != rv)
            {
                break;
            }

            attributeHelpers.populateAttributes(publicKeyAttributeBitmask,
                                                publicKeyLabel,
                                                publicKeyId,
                                                keyGenMechanism,
                                                publicKeyClass,
                                                publicKeyType,
                                                publicKeyAttributes);

            keyGenMechanism = KeyGenerationMechanism::rsaGeneratePrivateKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pPrivateKeyTemplate,
                                                                ulPrivateKeyAttributeCount,
                                                                privateKeyAttributeBitmask,
                                                                privateKeyLabel,
                                                                privateKeyId,
                                                                privateKeyClass,
                                                                privateKeyType);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = attributeHelpers.getModulusLength(pPublicKeyTemplate,
                                                   ulPublicKeyAttributeCount,
                                                   hasModulusLength,
                                                   modulusLength);
            if (CKR_OK != rv)
            {
                break;
            }

            if (!hasModulusLength)
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            if (publicKeyId != privateKeyId)
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }

            attributeHelpers.populateAttributes(privateKeyAttributeBitmask,
                                                privateKeyLabel,
                                                privateKeyId,
                                                keyGenMechanism,
                                                privateKeyClass,
                                                privateKeyType,
                                                privateKeyAttributes);

            sgxStatus = generateAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                              reinterpret_cast<int32_t*>(&enclaveStatus),
                                              &publicKeyHandle,
                                              &privateKeyHandle,
                                              modulusLength);
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

            *phPublicKey  = publicKeyHandle;
            *phPrivateKey = privateKeyHandle;

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AsymmetricProvider::encrypt(const uint32_t&   keyHandle,
                                      const uint8_t*    sourceBuffer,
                                      const uint32_t&   sourceBufferLen,
                                      uint8_t*          destBuffer,
                                      const uint32_t&   destBufferLen,
                                      uint32_t&         destBufferRequiredLength)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        RsaPadding          paddingScheme   = RsaPadding::rsaPkcs1Oaep; // This is the only padding scheme supported.
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

            sgxStatus = asymmetricEncrypt(enclaveHelpers.getSgxEnclaveId(),
                                          reinterpret_cast<int32_t*>(&enclaveStatus),
                                          keyHandle,
                                          sourceBuffer,
                                          sourceBufferLen,
                                          destBuffer,
                                          destBufferLen,
                                          &destBufferRequiredLength,
                                          static_cast<uint8_t>(paddingScheme));
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
    CK_RV AsymmetricProvider::decrypt(const uint32_t&   keyHandle,
                                      const uint8_t*    encryptedBuffer,
                                      const uint32_t&   encryptedBufferLen,
                                      uint8_t*          destBuffer,
                                      const uint32_t&   destBufferLen,
                                      uint32_t&         destBufferRequiredLength)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        RsaPadding          paddingScheme   = RsaPadding::rsaPkcs1Oaep; // This is the only padding scheme supported.
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!encryptedBuffer)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            sgxStatus = asymmetricDecrypt(enclaveHelpers.getSgxEnclaveId(),
                                          reinterpret_cast<int32_t*>(&enclaveStatus),
                                          keyHandle,
                                          encryptedBuffer,
                                          encryptedBufferLen,
                                          destBuffer,
                                          destBufferLen,
                                          &destBufferRequiredLength,
                                          static_cast<uint8_t>(paddingScheme));
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
    CK_RV AsymmetricProvider::sign(const uint32_t&   keyHandle,
                                   const uint8_t*    sourceBuffer,
                                   const uint32_t&   sourceBufferLen,
                                   uint8_t*          destBuffer,
                                   const uint32_t&   destBufferLen,
                                   uint32_t&         destBufferRequiredLength,
                                   const RsaPadding& rsaPadding,
                                   const HashMode&   hashMode)
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

            sgxStatus = asymmetricSign(enclaveHelpers.getSgxEnclaveId(),
                                       reinterpret_cast<int32_t*>(&enclaveStatus),
                                       keyHandle,
                                       sourceBuffer,
                                       sourceBufferLen,
                                       destBuffer,
                                       destBufferLen,
                                       &destBufferRequiredLength,
                                       hashAlgorithmIdSha256,
                                       static_cast<uint8_t>(rsaPadding),
                                       static_cast<uint8_t>(hashMode),
                                       saltSizeBytes);
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
    CK_RV AsymmetricProvider::verify(const uint32_t&    keyHandle,
                                     const uint8_t*     sourceBuffer,
                                     const uint32_t&    sourceBufferLen,
                                     uint8_t*           destBuffer,
                                     uint32_t           destBufferLen,
                                     const RsaPadding&  rsaPadding,
                                     const HashMode&    hashMode)
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

            sgxStatus = asymmetricVerify(enclaveHelpers.getSgxEnclaveId(),
                                         reinterpret_cast<int32_t*>(&enclaveStatus),
                                         keyHandle,
                                         sourceBuffer,
                                         sourceBufferLen,
                                         destBuffer,
                                         destBufferLen,
                                         hashAlgorithmIdSha256,
                                         static_cast<uint8_t>(rsaPadding),
                                         static_cast<uint8_t>(hashMode),
                                         saltSizeBytes);
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
    CK_RV AsymmetricProvider::destroyKey(const uint32_t&                           keyHandle,
                                         std::shared_ptr<AsymmetricKeyHandleCache> keyHandleCache)
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
            sgxStatus = destroyAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
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

            // Clean up keyHandle in provider cache
            keyHandleCache->remove(keyHandle);

        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AsymmetricProvider::wrapKey(const uint32_t&   wrappingKeyHandle,
                                      const uint32_t&   keyHandleData,
                                      uint8_t*          destBuffer,
                                      const uint32_t&   destBufferLen,
                                      uint32_t&         destBufferLenRequired,
                                      const RsaPadding& rsaPadding)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = wrapWithAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                              reinterpret_cast<int32_t*>(&enclaveStatus),
                                              wrappingKeyHandle,
                                              keyHandleData,
                                              destBuffer,
                                              destBufferLen,
                                              &destBufferLenRequired,
                                              static_cast<uint8_t>(rsaPadding));
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
    CK_RV AsymmetricProvider::platformbindKey(const uint32_t&   keyHandle,
                                              uint8_t*          destBuffer,
                                              const uint32_t&   destBufferLen,
                                              uint32_t&         destBufferLenRequired)
    {
        CK_RV               rv              = CKR_FUNCTION_FAILED;
        sgx_status_t        sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus      enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers      enclaveHelpers;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            sgxStatus = platformBindAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
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
    CK_RV AsymmetricProvider::unwrapKey(const uint32_t&   unwrappingKeyHandle,
                                        uint32_t*         keyHandle,
                                        const uint8_t*    sourceBuffer,
                                        const uint32_t&   sourceBufferLen,
                                        const RsaPadding& rsaPadding)
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

            sgxStatus = unwrapWithAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                reinterpret_cast<int32_t*>(&enclaveStatus),
                                                unwrappingKeyHandle,
                                                &unwrappedKeyHandle,
                                                sourceBuffer,
                                                sourceBufferLen,
                                                static_cast<uint8_t>(rsaPadding));
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
    CK_RV AsymmetricProvider::importPlatformBoundKey(const CK_ATTRIBUTE_PTR         pPublicKeyTemplate,
                                                     const CK_ULONG&                ulPublicKeyAttributeCount,
                                                     const CK_ATTRIBUTE_PTR         pPrivateKeyTemplate,
                                                     const CK_ULONG&                ulPrivateKeyAttributeCount,
                                                     CK_OBJECT_HANDLE_PTR           phPublicKey,
                                                     CK_OBJECT_HANDLE_PTR           phPrivateKey,
                                                     const std::vector<uint8_t>&    platformBoundKey,
                                                     Attributes&                    publicKeyAttributes,
                                                     Attributes&                    privateKeyAttributes)
    {
        CK_RV                  rv            = CKR_FUNCTION_FAILED;
        sgx_status_t           sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus         enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        EnclaveHelpers         enclaveHelpers;
        AttributeHelpers       attributeHelpers;
        KeyGenerationMechanism keyGenMechanism;
        std::string            publicKeyLabel, privateKeyLabel, publicKeyId, privateKeyId;
        CK_OBJECT_CLASS        publicKeyClass, privateKeyClass;
        CK_KEY_TYPE            publicKeyType,  privateKeyType;
        uint32_t               publicKeyAttributeBitmask, privateKeyAttributeBitmask;
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!pPublicKeyTemplate  ||
                !pPrivateKeyTemplate ||
                !phPublicKey         ||
                !phPrivateKey)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            keyGenMechanism = KeyGenerationMechanism::rsaImportPbindPublicKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pPublicKeyTemplate,
                                                                ulPublicKeyAttributeCount,
                                                                publicKeyAttributeBitmask,
                                                                publicKeyLabel,
                                                                publicKeyId,
                                                                publicKeyClass,
                                                                publicKeyType);
            if (CKR_OK != rv)
            {
                break;
            }

            attributeHelpers.populateAttributes(publicKeyAttributeBitmask,
                                                publicKeyLabel,
                                                publicKeyId,
                                                keyGenMechanism,
                                                publicKeyClass,
                                                publicKeyType,
                                                publicKeyAttributes);

            keyGenMechanism = KeyGenerationMechanism::rsaImportPbindPrivateKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pPrivateKeyTemplate,
                                                                ulPrivateKeyAttributeCount,
                                                                privateKeyAttributeBitmask,
                                                                privateKeyLabel,
                                                                privateKeyId,
                                                                privateKeyClass,
                                                                privateKeyType);
            if (CKR_OK != rv)
            {
                break;
            }

            if (publicKeyId != privateKeyId)
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }

            attributeHelpers.populateAttributes(privateKeyAttributeBitmask,
                                                privateKeyLabel,
                                                privateKeyId,
                                                keyGenMechanism,
                                                privateKeyClass,
                                                privateKeyType,
                                                privateKeyAttributes);

            sgxStatus = unwrapAndImportPlatformBoundAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                                  reinterpret_cast<int32_t*>(&enclaveStatus),
                                                                  reinterpret_cast<uint32_t*>(phPublicKey),
                                                                  reinterpret_cast<uint32_t*>(phPrivateKey),
                                                                  platformBoundKey.data(),
                                                                  platformBoundKey.size());

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
    CK_RV AsymmetricProvider::exportKey(const uint32_t& keyHandle,
                                        uint8_t*        destBuffer,
                                        const uint32_t& destBufferLen,
                                        uint32_t&       destBufferLenRequired)
    {
        CK_RV                       rv              = CKR_FUNCTION_FAILED;
        sgx_status_t                sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus              enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        uint32_t                    modulusSize     = 0;
        uint32_t                    exponentSize    = 0;
        uint32_t                    offset          = 0;
        EnclaveHelpers              enclaveHelpers;
        CK_RSA_PUBLIC_KEY_PARAMS    rsaPublicKeyParams{};
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
            sgxStatus = asymmetricExportKey(enclaveHelpers.getSgxEnclaveId(),
                                            reinterpret_cast<int32_t*>(&enclaveStatus),
                                            keyHandle,
                                            (!destBuffer) ? nullptr : destBuffer + offset,
                                            (!destBuffer) ? destBufferLen : destBufferLen - offset,
                                            &destBufferLenRequired,
                                            &modulusSize,
                                            &exponentSize);
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
                destBufferLenRequired = 0;
                break;
            }

            destBufferLenRequired += sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
            if (destBuffer)
            {
                rsaPublicKeyParams.ulExponentLen    = exponentSize;
                rsaPublicKeyParams.ulModulusLen     = modulusSize;
                memcpy(destBuffer, &rsaPublicKeyParams, sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
            }

            rv = CKR_OK;
        } while (false);

        ulock.unlock();
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AsymmetricProvider::importKey(uint32_t*       keyHandle,
                                        const uint8_t*  sourceBuffer,
                                        const uint32_t& sourceBufferLen)
    {
        CK_RV                       rv              = CKR_FUNCTION_FAILED;
        sgx_status_t                sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus              enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        uint32_t                    offset          = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
        EnclaveHelpers              enclaveHelpers;
        std::vector<uint8_t>        modulus;
        std::vector<uint8_t>        exponent;
        CK_RSA_PUBLIC_KEY_PARAMS    rsaPublicKeyParams{};
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

            memcpy(&rsaPublicKeyParams, sourceBuffer, sizeof(CK_RSA_PUBLIC_KEY_PARAMS));

            modulus.resize(rsaPublicKeyParams.ulModulusLen);
            memcpy(modulus.data(), sourceBuffer + offset, rsaPublicKeyParams.ulModulusLen);
            offset += rsaPublicKeyParams.ulModulusLen;

            exponent.resize(rsaPublicKeyParams.ulExponentLen);
            memcpy(exponent.data(), sourceBuffer + offset, rsaPublicKeyParams.ulExponentLen);

            sgxStatus = asymmetricImportKey(enclaveHelpers.getSgxEnclaveId(),
                                            reinterpret_cast<int32_t*>(&enclaveStatus),
                                            keyHandle,
                                            modulus.data(),
                                            modulus.size(),
                                            exponent.data(),
                                            exponent.size());
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
    CK_RV appendQuote(const uint32_t&   keyHandle,
                      const uint8_t*    spid,
                      const uint32_t&   spidLen,
                      const uint8_t*    sigRL,
                      const uint32_t    sigRLLen,
                      const uint32_t&   signatureType,
                      uint8_t*          quoteBuffer,
                      const uint32_t&   quoteBufferLen)
    {
        CK_RV                       rv              = CKR_FUNCTION_FAILED;
        sgx_status_t                sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus              enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        sgx_target_info_t           targetInfo      = { 0 };
        sgx_epid_group_id_t         gid             = { 0 };
        sgx_quote_t*                sgxQuote        = reinterpret_cast<sgx_quote_t*>(quoteBuffer);
        sgx_quote_sign_type_t       quoteSignType;
        sgx_report_t                enclaveReport   = { 0 };
        EnclaveHelpers              enclaveHelpers;

        do
        {
            if (!spid  ||
                !quoteBuffer)
            {
                rv = CKR_DATA_INVALID;
                break;
            }

            sgxStatus = sgx_init_quote(&targetInfo, &gid);
            if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            if (LINKABLE_SIGNATURE == signatureType)
            {
                quoteSignType = SGX_LINKABLE_SIGNATURE;
            }
            else if (UNLINKABLE_SIGNATURE == signatureType)
            {
                quoteSignType = SGX_UNLINKABLE_SIGNATURE;
            }
            else
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            sgxStatus = createReportForKeyHandle(enclaveHelpers.getSgxEnclaveId(),
                                                 reinterpret_cast<int*>(&enclaveStatus),
                                                 keyHandle,
                                                 &targetInfo,
                                                 &enclaveReport);
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

            sgxStatus = sgx_get_quote(&enclaveReport,
                                      quoteSignType,
                                      reinterpret_cast<const sgx_spid_t*>(spid),
                                      nullptr,
                                      sigRL,
                                      sigRLLen,
                                      nullptr,
                                      sgxQuote,
                                      quoteBufferLen);

            if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            rv = CKR_OK;
        } while (false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AsymmetricProvider::exportQuotePublicKey(const uint32_t&  keyHandle,
                                                   const uint8_t*   spid,
                                                   const uint32_t&  spidLen,
                                                   const uint8_t*   sigRL,
                                                   const uint32_t&  sigRLLen,
                                                   const uint32_t&  signatureType,
                                                   uint8_t*         destBuffer,
                                                   const uint32_t&  destBufferLen,
                                                   uint32_t&        destBufferLenRequired)
    {
        CK_RV                       rv              = CKR_FUNCTION_FAILED;
        sgx_status_t                sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus              enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        uint32_t                    modulusSize     = 0;
        uint32_t                    exponentSize    = 0;
        uint32_t                    offset          = 0;
        uint32_t                    quoteLength     = 0;
        uint32_t                    publicKeyLength = 0;
        EnclaveHelpers              enclaveHelpers;
        CK_RSA_PUBLIC_KEY_PARAMS    rsaPublicKeyParams{};
        std::unique_lock<decltype(mProviderMutex)> ulock(mProviderMutex, std::defer_lock);
        ulock.lock();

        do
        {
            if (!spid)
            {
                rv = CKR_DATA_INVALID;
                break;
            }

            offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
            sgxStatus = asymmetricExportKey(enclaveHelpers.getSgxEnclaveId(),
                                            reinterpret_cast<int32_t*>(&enclaveStatus),
                                            keyHandle,
                                            (!destBuffer) ? nullptr : destBuffer + offset,
                                            (!destBuffer) ? destBufferLen : destBufferLen - offset,
                                            &destBufferLenRequired,
                                            &modulusSize,
                                            &exponentSize);
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
                destBufferLenRequired = 0;
                break;
            }

            destBufferLenRequired += sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
            publicKeyLength = destBufferLenRequired;
            if (destBuffer)
            {
                rsaPublicKeyParams.ulExponentLen    = exponentSize;
                rsaPublicKeyParams.ulModulusLen     = modulusSize;
                memcpy(destBuffer, &rsaPublicKeyParams, sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
            }

            uint32_t quoteLengthTemp = 0;
            sgx_status_t calcQuoteSizeStatus = sgx_calc_quote_size(sigRL,
                                                                   sigRLLen,
                                                                   &quoteLengthTemp);
            if (sgx_status_t::SGX_SUCCESS == calcQuoteSizeStatus)
            {
                quoteLength = quoteLengthTemp;
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            destBufferLenRequired += quoteLength;
            if (!destBuffer)
            {
                rv = CKR_OK;
                break;
            }

            if (destBufferLen < destBufferLenRequired)
            {
                rv = CKR_BUFFER_TOO_SMALL;
                memset(destBuffer, 0, destBufferLen);
                break;
            }

            rv = appendQuote(keyHandle,
                             spid,
                             spidLen,
                             sigRL,
                             sigRLLen,
                             signatureType,
                             destBuffer + publicKeyLength,
                             quoteLength);
            if (CKR_OK != rv)
            {
                memset(destBuffer, 0, destBufferLenRequired);
                destBufferLenRequired = 0;
                break;
            }
        } while (false);

        ulock.unlock();
        return rv;
    }
}
