/*
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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

#include "KeyManagement.h"
#include "EnclaveInterface.h"
#include "p11Sgx.h"
#include "config.h"
#ifdef DCAP_SUPPORT
#include "QuoteGeneration.h"
#endif

//---------------------------------------------------------------------------------------------
CK_RV generateKey(CK_SESSION_HANDLE    hSession,
                  CK_MECHANISM_PTR     pMechanism,
                  CK_ATTRIBUTE_PTR     pTemplate,
                  CK_ULONG             ulCount,
                  CK_OBJECT_HANDLE_PTR phKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::generateKey(hSession,
                                      pMechanism,
                                      pTemplate,
                                      ulCount,
                                      phKey);
}

//---------------------------------------------------------------------------------------------
CK_RV generateKeyPair(CK_SESSION_HANDLE    hSession,
                      CK_MECHANISM_PTR     pMechanism,
                      CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
                      CK_ULONG             ulPublicKeyAttributeCount,
                      CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
                      CK_ULONG             ulPrivateKeyAttributeCount,
                      CK_OBJECT_HANDLE_PTR phPublicKey,
                      CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::generateKeyPair(hSession,
                                          pMechanism,
                                          pPublicKeyTemplate,
                                          ulPublicKeyAttributeCount,
                                          pPrivateKeyTemplate,
                                          ulPrivateKeyAttributeCount,
                                          phPublicKey,
                                          phPrivateKey);
}

//---------------------------------------------------------------------------------------------
CK_RV wrapKey(CK_SESSION_HANDLE hSession,
              CK_MECHANISM_PTR  pMechanism,
              CK_OBJECT_HANDLE  hWrappingKey,
              CK_OBJECT_HANDLE  hKey,
              CK_BYTE_PTR       pWrappedKey,
              CK_ULONG_PTR      pulWrappedKeyLen)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

#ifdef DCAP_SUPPORT
    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_MECHANISM quoteMechanism{};
    CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL quoteParamsInternal{};

    //load the extra parameter for CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY mechanism
    if(pMechanism->mechanism == CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY)
    {
        if (!pMechanism->pParameter || (sizeof(CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS) != pMechanism->ulParameterLen))
        {
            return CKR_ARGUMENTS_BAD;
        }

        quote3_error_t qrv = SGX_QL_SUCCESS;

        qrv = sgx_qe_set_enclave_load_policy(static_cast<sgx_ql_request_policy_t>(CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->qlPolicy));
        if(SGX_QL_SUCCESS != qrv)
        {
            return CKR_GENERAL_ERROR;
        }

        sgx_target_info_t targetInfo{0};

        qrv = sgx_qe_get_target_info(&targetInfo);
        if (SGX_QL_SUCCESS != qrv)
        {
            return CKR_GENERAL_ERROR;
        }

        uint32_t quoteLength = 0;
        qrv = sgx_qe_get_quote_size(&quoteLength);

        if (SGX_QL_SUCCESS != qrv)
        {
            return CKR_GENERAL_ERROR;
        }

        quoteParamsInternal = { targetInfo, quoteLength };

        quoteMechanism.mechanism = CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY_INTERNAL;
        quoteMechanism.pParameter = &quoteParamsInternal;
        quoteMechanism.ulParameterLen = sizeof(quoteParamsInternal);
    }
#endif

    rv = EnclaveInterface::wrapKey(hSession,
#ifdef DCAP_SUPPORT
                                  (pMechanism->mechanism == CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY) ? &quoteMechanism : pMechanism,
#else
                                   pMechanism,
#endif
                                   hWrappingKey,
                                   hKey,
                                   pWrappedKey,
                                   pulWrappedKeyLen);
#ifdef DCAP_SUPPORT
    if(pMechanism->mechanism == CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY)
    {
        sgx_qe_cleanup_by_policy();
    }
#endif
    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV unwrapKey(CK_SESSION_HANDLE    hSession,
                CK_MECHANISM_PTR     pMechanism,
                CK_OBJECT_HANDLE     hUnwrappingKey,
                CK_BYTE_PTR          pWrappedKey,
                CK_ULONG             ulWrappedKeyLen,
                CK_ATTRIBUTE_PTR     pTemplate,
                CK_ULONG             ulCount,
                CK_OBJECT_HANDLE_PTR hKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::unwrapKey(hSession,
                                    pMechanism,
                                    hUnwrappingKey,
                                    pWrappedKey,
                                    ulWrappedKeyLen,
                                    pTemplate,
                                    ulCount,
                                    hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV deriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::deriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}