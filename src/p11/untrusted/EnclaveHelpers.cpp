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

#include <sgx_urts.h>
#include <sgx_error.h>
#include <sgx_uae_service.h>
#include <map>

#include "EnclaveHelpers.h"
#include "CryptoEnclaveDefs.h"
#include "p11Enclave_u.h"

// Globals with file scope.
namespace P11Crypto
{
    sgx_enclave_id_t    EnclaveHelpers::mEnclaveInvalidId       = 0;
    volatile long       EnclaveHelpers::mSgxEnclaveLoadedCount  = 0;
    sgx_enclave_id_t    EnclaveHelpers::mSgxEnclaveId           = 0;
    std::string         enclaveFileName                         = (("NONE" == installationPath)? defaultLibraryPath : libraryDirectory) + "libp11SgxEnclave.signed.so";

    std::map<const SgxCryptStatus, const uint64_t> enclaveToPkcs11ErrorMap({{ SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS,                   CKR_OK },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE,       CKR_DATA_LEN_RANGE },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY,             CKR_DEVICE_MEMORY },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER,         CKR_ARGUMENTS_BAD },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT,          CKR_BUFFER_TOO_SMALL },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE,        CKR_KEY_HANDLE_INVALID },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BLOCK_CIPHER_MODE, CKR_MECHANISM_INVALID },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE_LENGTH,  CKR_SIGNATURE_LEN_RANGE },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE,         CKR_SIGNATURE_INVALID },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_WRAPPED_KEY,       CKR_WRAPPED_KEY_INVALID },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_TAG_SIZE,          CKR_MECHANISM_PARAM_INVALID },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL,            CKR_DEVICE_TABLE_FULL },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_HASH_STATE_TABLE_FULL,     CKR_DEVICE_TABLE_FULL },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED,   CKR_CIPHER_OPERATION_FAILED },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_SEALED_DATA_FAILED,        CKR_PLATFORM_SEAL_UNSEAL_FAILED },
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_SESSION_EXISTS,            CKR_SESSION_EXISTS},
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_LOGGED_IN,                 CKR_LOGGED_IN},
                                                                            { SgxCryptStatus::SGX_CRYPT_STATUS_NOT_LOGGED,                CKR_NOT_LOGGED} });

    //---------------------------------------------------------------------------------------------
    EnclaveHelpers::EnclaveHelpers()
    {

    }

    //---------------------------------------------------------------------------------------------
    sgx_status_t EnclaveHelpers::loadSgxEnclave(ProviderType providerType)
    {
        sgx_launch_token_t token;
        sgx_status_t       sgxStatus        = sgx_status_t::SGX_ERROR_UNEXPECTED;
        int                tokenUpdated     = 0;
        sgx_enclave_id_t   sgxEnclaveId     = mEnclaveInvalidId;
        sgx_status_t       enclaveStatus    = sgx_status_t::SGX_ERROR_UNEXPECTED;
        unsigned long      sgxNumRetries    = 0;

        if (isSgxEnclaveLoaded())
        {
            // The Intel SGX enclave is already loaded so return success.
        #ifdef _WIN32
            InterlockedIncrement(&mSgxEnclaveLoadedCount);
        #else
            __sync_add_and_fetch(&mSgxEnclaveLoadedCount, 1);
        #endif
            return SGX_SUCCESS;
        }

        memset(&token, 0, sizeof(token));

        // There is no need to handle SGX_ERROR_ENCLAVE_LOST here because
        // for sure this is the first new instance of enclave creation.
        sgxStatus = sgx_create_enclave(enclaveFileName.data(),
                                       SGX_DEBUG_FLAG,
                                       &token,
                                       &tokenUpdated,
                                       &sgxEnclaveId,
                                       NULL);

#if RELEASE_WHITELISTED_ENCLAVE
        if (sgx_status_t::SGX_ERROR_SERVICE_INVALID_PRIVILEGE == sgxStatus)
        {
            // If error indicates that enclave verification fails due to cert not being
            // in white list, register the embedded white list cert binary and retry
            // loading the enclave. Registration is a one-time operation.
            // Please refer to sgx_register_wl_cert_chain
            // https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-register-wl-cert-chain
            // After registration call sgx_create_enclave
        }
#endif
        // Initialize the SGX enclave.
        if (sgx_status_t::SGX_SUCCESS == sgxStatus)
        {
            while (sgxNumRetries <= mEnclaveInvalidId)
            {
                sgxStatus = initCryptoEnclave(sgxEnclaveId,
                                              reinterpret_cast<int32_t*>(&enclaveStatus),
                                              static_cast<uint8_t>(providerType));

                if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
                {
                    ++sgxNumRetries;
                    continue;
                }
                else
                {
                    break;
                }
            }

            // Save the SGX enclave ID for later.
            if (sgx_status_t::SGX_SUCCESS == sgxStatus)
            {
                setSgxEnclaveId(sgxEnclaveId);
            #ifdef _WIN32
                InterlockedIncrement(&mSgxEnclaveLoadedCount);
            #else
                __sync_add_and_fetch(&mSgxEnclaveLoadedCount, 1);
            #endif
            }
            else
            {
                sgx_destroy_enclave(sgxEnclaveId);
                setSgxEnclaveId(mEnclaveInvalidId);
            }
        }
        else
        {
            setSgxEnclaveId(mEnclaveInvalidId);
        }

        return sgxStatus;
    } // end loadSgxEnclave()

    //---------------------------------------------------------------------------------------------
    sgx_status_t EnclaveHelpers::unloadSgxEnclave(ProviderType providerType)
    {
        sgx_status_t enclaveStatus  = SGX_ERROR_UNEXPECTED;
        sgx_status_t sgxStatus      = SGX_ERROR_UNEXPECTED;

        do
        {
            if (false == isSgxEnclaveLoaded())
            {
                sgxStatus = sgx_status_t::SGX_SUCCESS;
                break;
            }
            #ifdef _WIN32
                InterlockedDecrement(&mSgxEnclaveLoadedCount);
            #else
                __sync_sub_and_fetch(&mSgxEnclaveLoadedCount, 1);
            #endif

            (void)deinitCryptoEnclave(getSgxEnclaveId(),
                                      reinterpret_cast<int32_t*>(&enclaveStatus),
                                      static_cast<uint8_t>(providerType));

            // The Intel SGX enclave is already
            // in use so return success.
            if (mSgxEnclaveLoadedCount > 0)
            {
                sgxStatus = SGX_SUCCESS;
                break;
            }

            sgxStatus = sgx_destroy_enclave(getSgxEnclaveId());

            if (sgx_status_t::SGX_SUCCESS == sgxStatus)
            {
                setSgxEnclaveId(mEnclaveInvalidId);
            #ifdef _WIN32
                InterlockedExchange(&mSgxEnclaveLoadedCount, 0);
            #else
                __sync_lock_test_and_set(&mSgxEnclaveLoadedCount, 0);
            #endif
            }

        } while (false);

        return sgxStatus;
    } // unloadSgxEnclave()

    //---------------------------------------------------------------------------------------------
    CK_RV EnclaveHelpers::enclaveStatusToPkcsStatus(const SgxCryptStatus& enclaveStatus)
    {
        CK_RV mappedStatus = CKR_FUNCTION_FAILED;

        std::map<const SgxCryptStatus, const uint64_t>::iterator it;

        it = enclaveToPkcs11ErrorMap.find(enclaveStatus);
        if (enclaveToPkcs11ErrorMap.end() == it)
        {
            mappedStatus = CKR_FUNCTION_FAILED;
        }
        else
        {
            mappedStatus = it->second;
        }

        return mappedStatus;
    }
}