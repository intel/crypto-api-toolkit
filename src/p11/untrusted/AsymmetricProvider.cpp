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

#include "AsymmetricProvider.h"
#include <sgx_error.h>
#include <sgx_uae_service.h>

#ifdef DCAP_SUPPORT
#include "sgx_pce.h"
#include "sgx_dcap_ql_wrapper.h"
#endif

namespace P11Crypto
{
    namespace AsymmetricProvider
    {
        //---------------------------------------------------------------------------------------------
        CK_RV generateRsaKeyPair(const AsymmetricKeyParams&   asymKeyParams,
                                 const std::vector<CK_ULONG>& packedAttributesPublic,
                                 const std::vector<CK_ULONG>& packedAttributesPrivate,
                                 CK_OBJECT_HANDLE_PTR         phPublicKey,
                                 CK_OBJECT_HANDLE_PTR         phPrivateKey)
        {
            CK_RV          rv               = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus        = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus    = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t       publicKeyHandle  = 0;
            uint32_t       privateKeyHandle = 0;
            EnclaveHelpers enclaveHelpers;

            do
            {
                if (!phPublicKey || !phPrivateKey)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                sgxStatus = generateAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                  reinterpret_cast<int32_t*>(&enclaveStatus),
                                                  &publicKeyHandle,
                                                  &privateKeyHandle,
                                                  static_cast<uint16_t>(asymKeyParams.modulusLength),
                                                  packedAttributesPublic.data(),
                                                  packedAttributesPublic.size() * sizeof(CK_ULONG),
                                                  packedAttributesPrivate.data(),
                                                  packedAttributesPrivate.size() * sizeof(CK_ULONG));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK == rv)
                {
                    *phPublicKey  = publicKeyHandle;
                    *phPrivateKey = privateKeyHandle;
                }
                else
                {
                    *phPublicKey  = CK_INVALID_HANDLE;
                    *phPrivateKey = CK_INVALID_HANDLE;
                }
            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV generateEcc(const AsymmetricKeyParams&   asymKeyParams,
                          const std::vector<CK_ULONG>& packedAttributesPublic,
                          const std::vector<CK_ULONG>& packedAttributesPrivate,
                          CK_OBJECT_HANDLE_PTR         phPublicKey,
                          CK_OBJECT_HANDLE_PTR         phPrivateKey)
        {
            CK_RV          rv               = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus        = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus    = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t       publicKeyHandle  = 0;
            uint32_t       privateKeyHandle = 0;
            EnclaveHelpers enclaveHelpers;

            do
            {
                if (!phPublicKey || !phPrivateKey)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                sgxStatus = generateEccKeyPair(enclaveHelpers.getSgxEnclaveId(),
                                               reinterpret_cast<int32_t*>(&enclaveStatus),
                                               &publicKeyHandle,
                                               &privateKeyHandle,
                                               reinterpret_cast<const unsigned char*>(asymKeyParams.curveOid.c_str()),
                                               asymKeyParams.curveOid.size(),
                                               packedAttributesPublic.data(),
                                               packedAttributesPublic.size() * sizeof(CK_ULONG),
                                               packedAttributesPrivate.data(),
                                               packedAttributesPrivate.size() * sizeof(CK_ULONG));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK == rv)
                {
                    *phPublicKey  = publicKeyHandle;
                    *phPrivateKey = privateKeyHandle;
                }
                else
                {
                    *phPublicKey  = CK_INVALID_HANDLE;
                    *phPrivateKey = CK_INVALID_HANDLE;
                }
            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV encrypt(const uint32_t&   keyHandle,
                      const uint8_t*    sourceBuffer,
                      const uint32_t&   sourceBufferLen,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t*         destBufferRequiredLength,
                      const RsaPadding& rsaPadding)
        {
            CK_RV          rv              = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

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
                                            sourceBuffer, sourceBufferLen,
                                            destBuffer,   destBufferLen,
                                            destBufferRequiredLength,
                                            static_cast<uint8_t>(rsaPadding));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV decrypt(const uint32_t&   keyHandle,
                      const uint8_t*    encryptedBuffer,
                      const uint32_t&   encryptedBufferLen,
                      uint8_t*          destBuffer,
                      const uint32_t&   destBufferLen,
                      uint32_t*         destBufferRequiredLength,
                      const RsaPadding& rsaPadding)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

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
                                              encryptedBuffer, encryptedBufferLen,
                                              destBuffer, destBufferLen,
                                              destBufferRequiredLength,
                                              static_cast<uint8_t>(rsaPadding));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV wrapKey(const uint32_t&       wrappingKeyHandle,
                      const uint32_t&       keyHandleData,
                      const RsaCryptParams& rsaCryptParams,
                      uint8_t*              destBuffer,
                      const uint32_t&       destBufferLen,
                      uint32_t*             destBufferLenRequired)
        {
            CK_RV          rv              = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                sgxStatus = wrapWithAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                  reinterpret_cast<int32_t*>(&enclaveStatus),
                                                  wrappingKeyHandle,
                                                  keyHandleData,
                                                  destBuffer, destBufferLen,
                                                  destBufferLenRequired,
                                                  static_cast<uint8_t>(rsaCryptParams.rsaPadding));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV exportPublicKey(const uint32_t& keyHandle,
                              uint8_t*        destBuffer,
                              const uint32_t& destBufferLen,
                              uint32_t*       destBufferLenRequired)
        {
            CK_RV                       rv              = CKR_FUNCTION_FAILED;
            sgx_status_t                sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus              enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t                    modulusSize     = 0;
            uint32_t                    exponentSize    = 0;
            uint32_t                    offset          = 0;
            EnclaveHelpers              enclaveHelpers;
            CK_RSA_PUBLIC_KEY_PARAMS    rsaPublicKeyParams{};

            do
            {
                if (!destBufferLenRequired)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
                sgxStatus = asymmetricExportKey(enclaveHelpers.getSgxEnclaveId(),
                                                reinterpret_cast<int32_t*>(&enclaveStatus),
                                                keyHandle,
                                                (!destBuffer) ? nullptr : destBuffer + offset,
                                                (!destBuffer) ? destBufferLen : destBufferLen - offset,
                                                destBufferLenRequired,
                                                &modulusSize,
                                                &exponentSize);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    *destBufferLenRequired = 0;
                    break;
                }

                *destBufferLenRequired += sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
                if (destBuffer)
                {
                    rsaPublicKeyParams.ulExponentLen = exponentSize;
                    rsaPublicKeyParams.ulModulusLen  = modulusSize;
                    memcpy(destBuffer, &rsaPublicKeyParams, sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
                }

                rv = CKR_OK;
            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        static CK_RV appendQuote(const uint32_t& keyHandle,
                                 const uint8_t*  spid,
                                 const uint32_t& spidLen,
                                 const uint8_t*  sigRL,
                                 const uint32_t  sigRLLen,
                                 const uint32_t& signatureType,
                                 uint8_t*        quoteBuffer,
                                 const uint32_t& quoteBufferLen)
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

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    break;
                }

                sgxStatus = sgx_get_quote(&enclaveReport,
                                          quoteSignType,
                                          reinterpret_cast<const sgx_spid_t*>(spid),
                                          nullptr,
                                          sigRL, sigRLLen,
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

#ifdef DCAP_SUPPORT
        //---------------------------------------------------------------------------------------------
        static CK_RV appendQuote(const uint32_t&    keyHandle,
                                 sgx_target_info_t* targetInfo,
                                 uint8_t*           quoteBuffer,
                                 const uint32_t&    quoteBufferLen)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            quote3_error_t qrv           = SGX_QL_SUCCESS;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            sgx_report_t   enclaveReport = { 0 };
            EnclaveHelpers enclaveHelpers;
            sgx_status_t   sgxStatus{SGX_SUCCESS};

            do
            {
                if (!quoteBuffer)
                {
                    rv = CKR_DATA_INVALID;
                    break;
                }

                sgxStatus = createReportForKeyHandle(enclaveHelpers.getSgxEnclaveId(),
                                                     reinterpret_cast<int*>(&enclaveStatus),
                                                     keyHandle,
                                                     targetInfo,
                                                     &enclaveReport);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    break;
                }

                qrv = sgx_qe_get_quote(&enclaveReport, quoteBufferLen, quoteBuffer);

                if (SGX_QL_SUCCESS != qrv)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                rv = CKR_OK;
            } while (false);

            return rv;
        }
#endif

        //---------------------------------------------------------------------------------------------
        CK_RV exportQuoteWithRsaPublicKey(const uint32_t&           keyHandle,
                                          const RsaEpidQuoteParams& rsaQuoteWrapParams,
                                          uint8_t*                  destBuffer,
                                          const uint32_t&           destBufferLen,
                                          uint32_t*                 destBufferLenRequired)
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

            do
            {
                if (!destBufferLenRequired)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                *destBufferLenRequired = 0;

                if (!rsaQuoteWrapParams.spid.data() || !rsaQuoteWrapParams.spid.size())
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
                                                destBufferLenRequired,
                                                &modulusSize,
                                                &exponentSize);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    *destBufferLenRequired = 0;
                    break;
                }

                *destBufferLenRequired += sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
                publicKeyLength = *destBufferLenRequired;
                if (destBuffer && destBufferLen >= sizeof(CK_RSA_PUBLIC_KEY_PARAMS))
                {
                    rsaPublicKeyParams.ulExponentLen    = exponentSize;
                    rsaPublicKeyParams.ulModulusLen     = modulusSize;
                    memcpy(destBuffer, &rsaPublicKeyParams, sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
                }

                uint32_t quoteLengthTemp = 0;
                sgx_status_t calcQuoteSizeStatus = sgx_calc_quote_size(rsaQuoteWrapParams.sigRL.data(),
                                                                       rsaQuoteWrapParams.sigRL.size(),
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

                *destBufferLenRequired += quoteLength;
                if (!destBuffer)
                {
                    rv = CKR_OK;
                    break;
                }

                if (destBufferLen < *destBufferLenRequired)
                {
                    rv = CKR_BUFFER_TOO_SMALL;
                    memset(destBuffer, 0, destBufferLen);
                    break;
                }

                rv = appendQuote(keyHandle,
                                 rsaQuoteWrapParams.spid.data(),  rsaQuoteWrapParams.spid.size(),
                                 rsaQuoteWrapParams.sigRL.data(), rsaQuoteWrapParams.sigRL.size(),
                                 rsaQuoteWrapParams.signatureType,
                                 destBuffer + publicKeyLength,
                                 quoteLength);
                if (CKR_OK != rv)
                {
                    memset(destBuffer, 0, *destBufferLenRequired);
                    *destBufferLenRequired = 0;
                    break;
                }
            } while (false);

            return rv;
        }

#ifdef DCAP_SUPPORT
        //---------------------------------------------------------------------------------------------
        CK_RV exportQuoteWithRsaPublicKey(const uint32_t&               keyHandle,
                                          const RsaEcdsaQuoteParams&    rsaQuoteParams,
                                          uint8_t*                      destBuffer,
                                          const uint32_t&               destBufferLen,
                                          uint32_t*                     destBufferLenRequired)
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

            do
            {
                if (!destBufferLenRequired)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                *destBufferLenRequired = 0;

                if (!(SGX_QL_PERSISTENT == rsaQuoteParams.qlPolicy ||
                      SGX_QL_EPHEMERAL  == rsaQuoteParams.qlPolicy ||
                      SGX_QL_DEFAULT    == rsaQuoteParams.qlPolicy))
                {
                    rv = CKR_ARGUMENTS_BAD;
                }

                offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
                sgxStatus = asymmetricExportKey(enclaveHelpers.getSgxEnclaveId(),
                                                reinterpret_cast<int32_t*>(&enclaveStatus),
                                                keyHandle,
                                                (!destBuffer) ? nullptr : destBuffer + offset,
                                                (!destBuffer) ? destBufferLen : destBufferLen - offset,
                                                destBufferLenRequired,
                                                &modulusSize,
                                                &exponentSize);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

                if (CKR_OK != rv)
                {
                    *destBufferLenRequired = 0;
                    break;
                }

                *destBufferLenRequired += sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
                publicKeyLength = *destBufferLenRequired;
                if (destBuffer && destBufferLen >= sizeof(CK_RSA_PUBLIC_KEY_PARAMS))
                {
                    rsaPublicKeyParams.ulExponentLen    = exponentSize;
                    rsaPublicKeyParams.ulModulusLen     = modulusSize;
                    memcpy(destBuffer, &rsaPublicKeyParams, sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
                }

                quote3_error_t qrv = SGX_QL_SUCCESS;

                qrv = sgx_qe_set_enclave_load_policy(static_cast<sgx_ql_request_policy_t>(rsaQuoteParams.qlPolicy));
                if(SGX_QL_SUCCESS != qrv)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                sgx_target_info_t targetInfo{0};
                qrv = sgx_qe_get_target_info(&targetInfo);
                if (SGX_QL_SUCCESS != qrv)
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                uint32_t quoteLengthTemp = 0;
                qrv = sgx_qe_get_quote_size(&quoteLengthTemp);

                if (SGX_QL_SUCCESS == qrv)
                {
                    quoteLength = quoteLengthTemp;
                }
                else
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                *destBufferLenRequired += quoteLength;
                if (!destBuffer)
                {
                    rv = CKR_OK;
                    break;
                }

                if (destBufferLen < *destBufferLenRequired)
                {
                    rv = CKR_BUFFER_TOO_SMALL;
                    memset(destBuffer, 0, destBufferLen);
                    break;
                }

                rv = appendQuote(keyHandle,
                                 &targetInfo,
                                 destBuffer + publicKeyLength,
                                 quoteLength);

                qrv = sgx_qe_cleanup_by_policy();

                //TODO: If the cleanup call fails, should we fail the Wrap call?

                if (CKR_OK != rv)
                {
                    memset(destBuffer, 0, *destBufferLenRequired);
                    *destBufferLenRequired = 0;
                    break;
                }
            } while (false);

            return rv;
        }
#endif

        //---------------------------------------------------------------------------------------------
        CK_RV unwrapKey(const uint32_t&              unwrappingKeyHandle,
                        const uint8_t*               sourceBuffer,
                        const uint32_t&              sourceBufferLen,
                        const RsaCryptParams&        rsaCryptParams,
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

                sgxStatus = unwrapWithAsymmetricKey(enclaveHelpers.getSgxEnclaveId(),
                                                    reinterpret_cast<int32_t*>(&enclaveStatus),
                                                    unwrappingKeyHandle,
                                                    &unwrappedKeyHandle,
                                                    sourceBuffer, sourceBufferLen,
                                                    static_cast<uint8_t>(rsaCryptParams.rsaPadding),
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

        //---------------------------------------------------------------------------------------------
        CK_RV importKey(const uint8_t*               sourceBuffer,
                        const uint32_t&              sourceBufferLen,
                        const std::vector<CK_ULONG>& packedAttributes,
                        uint32_t*                    keyHandle)
        {
            CK_RV                    rv            = CKR_FUNCTION_FAILED;
            sgx_status_t             sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus           enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            uint32_t                 offset        = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
            EnclaveHelpers           enclaveHelpers;
            std::vector<uint8_t>     modulus;
            std::vector<uint8_t>     exponent;
            CK_RSA_PUBLIC_KEY_PARAMS rsaPublicKeyParams{};

            do
            {
                if (!keyHandle || !sourceBuffer)
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
                                                modulus.data(),  modulus.size(),
                                                exponent.data(), exponent.size(),
                                                packedAttributes.data(),
                                                packedAttributes.size() * sizeof(CK_ULONG));

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV sign(const uint32_t&   keyHandle,
                   const uint8_t*    sourceBuffer,
                   const uint32_t&   sourceBufferLen,
                   uint8_t*          destBuffer,
                   const uint32_t&   destBufferLen,
                   const RsaPadding& rsaPadding,
                   const HashMode&   hashMode,
                   uint32_t*         destBufferRequiredLength)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            EnclaveHelpers enclaveHelpers;

            do
            {
                if (!sourceBuffer || !destBufferRequiredLength)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                sgxStatus = asymmetricSign(enclaveHelpers.getSgxEnclaveId(),
                                           reinterpret_cast<int32_t*>(&enclaveStatus),
                                           keyHandle,
                                           sourceBuffer, sourceBufferLen,
                                           destBuffer,   destBufferLen,
                                           destBufferRequiredLength,
                                           hashAlgorithmIdSha256,
                                           static_cast<uint8_t>(rsaPadding),
                                           static_cast<uint8_t>(hashMode),
                                           saltSizeBytes);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV verify(const uint32_t&   keyHandle,
                     const uint8_t*    sourceBuffer,
                     const uint32_t&   sourceBufferLen,
                     uint8_t*          destBuffer,
                     uint32_t          destBufferLen,
                     const RsaPadding& rsaPadding,
                     const HashMode&   hashMode)
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

                sgxStatus = asymmetricVerify(enclaveHelpers.getSgxEnclaveId(),
                                             reinterpret_cast<int32_t*>(&enclaveStatus),
                                             keyHandle,
                                             sourceBuffer, sourceBufferLen,
                                             destBuffer,   destBufferLen,
                                             hashAlgorithmIdSha256,
                                             static_cast<uint8_t>(rsaPadding),
                                             static_cast<uint8_t>(hashMode),
                                             saltSizeBytes);

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);

            } while (false);

            return rv;
        }
    }
}
