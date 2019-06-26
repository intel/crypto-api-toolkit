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

#include "SignVerify.h"

//---------------------------------------------------------------------------------------------
static bool isSupportedSignVerifyMechanism(const CK_MECHANISM_PTR pMechanism)
{
    bool result = false;

    if (!pMechanism)
    {
        return false;
    }

    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        result = true;
        break;
    default:
        result = false;
        break;
    }
    return result;
}

//---------------------------------------------------------------------------------------------
CK_RV signInit(CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR  pMechanism,
               CK_OBJECT_HANDLE  hKey)
{
    CK_RV      rv         = CKR_FUNCTION_FAILED;
    RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
    HashMode   hashMode   = HashMode::invalid;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!gSessionCache->attributeSet(hKey, BoolAttribute::SIGN))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        if (isSupportedSignVerifyMechanism(pMechanism))
        {
            SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
            if (!sessionParameters.activeOperation.test(ActiveOp::Sign_None))
            {
                rv = CKR_OPERATION_ACTIVE;
                break;
            }

            switch(pMechanism->mechanism)
            {
                case CKM_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    break;
                case CKM_SHA256_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha256;
                    break;
                case CKM_SHA512_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha512;
                    break;
                case CKM_RSA_PKCS_PSS:
                case CKM_SHA256_RSA_PKCS_PSS:
                case CKM_SHA512_RSA_PKCS_PSS:
                    if (!pMechanism->pParameter                                                                                                     ||
                        sizeof(CK_RSA_PKCS_PSS_PARAMS)                               != pMechanism->ulParameterLen                                  ||
                        CKM_SHA256                                                   != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg ||
                        static_cast<CK_ULONG>(hashDigestLengthMap[HashMode::sha256]) != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen)
                        {
                            rv = CKR_ARGUMENTS_BAD;
                            break;
                        }
                        rsaPadding = RsaPadding::rsaPkcs1Pss;
                        if (CKM_SHA256_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha256;
                        }
                        else if (CKM_SHA512_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha512;
                        }
                    break;
                default:
                    rv = CKR_MECHANISM_INVALID;
                    break;
            }

            if (CKR_OK != rv)
            {
                break;
            }

            sessionParameters.activeOperation.reset(ActiveOp::Sign_None);
            sessionParameters.activeOperation.set(ActiveOp::Sign_Init);
            sessionParameters.data.signParams.keyHandle  = hKey;
            sessionParameters.data.signParams.hashMode   = hashMode;
            sessionParameters.data.signParams.rsaPadding = rsaPadding;

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV sign(CK_SESSION_HANDLE hSession,
           CK_BYTE_PTR       pData,
           CK_ULONG          ulDataLen,
           CK_BYTE_PTR       pSignature,
           CK_ULONG_PTR      pulSignatureLen)
{
    CK_RV             rv        = CKR_FUNCTION_FAILED;
    uint32_t          sessionId = hSession & std::numeric_limits<uint32_t>::max();
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(sessionId))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(sessionId);

        if (!pData || !pulSignatureLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!sessionParameters.activeOperation.test(ActiveOp::Sign_Init))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        RsaPadding rsaPadding = sessionParameters.data.signParams.rsaPadding;
        uint32_t   keyHandle  = sessionParameters.data.signParams.keyHandle;
        HashMode   hashMode   = sessionParameters.data.signParams.hashMode;
        uint32_t   destBufferRequiredLength  = 0;

        uint32_t destBufferLen = *pulSignatureLen;
        rv = P11Crypto::AsymmetricProvider::sign(keyHandle,
                                                 pData, ulDataLen,
                                                 pSignature, destBufferLen,
                                                 rsaPadding,
                                                 hashMode,
                                                 &destBufferRequiredLength);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulSignatureLen = destBufferRequiredLength;
        if (!pSignature)
        {
            rv = CKR_OK;
            break;
        }

        P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Sign);

        gSessionCache->add(sessionId, sessionParameters);
    } while (false);

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache)
        {
            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Sign);

            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV verifyInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR  pMechanism,
                 CK_OBJECT_HANDLE  hKey)
{
    CK_RV      rv         = CKR_FUNCTION_FAILED;
    RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
    HashMode   hashMode   = HashMode::invalid;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!gSessionCache->attributeSet(hKey, BoolAttribute::VERIFY))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        if (isSupportedSignVerifyMechanism(pMechanism))
        {
            SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
            if (!sessionParameters.activeOperation.test(ActiveOp::Verify_None))
            {
                rv = CKR_OPERATION_ACTIVE;
                break;
            }

            switch(pMechanism->mechanism)
            {
                case CKM_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    break;
                case CKM_SHA256_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha256;
                    break;
                case CKM_SHA512_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha512;
                    break;
                case CKM_RSA_PKCS_PSS:
                case CKM_SHA256_RSA_PKCS_PSS:
                case CKM_SHA512_RSA_PKCS_PSS:
                    if (!pMechanism->pParameter                                                                                                     ||
                        sizeof(CK_RSA_PKCS_PSS_PARAMS)                               != pMechanism->ulParameterLen                                  ||
                        CKM_SHA256                                                   != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg ||
                        static_cast<CK_ULONG>(hashDigestLengthMap[HashMode::sha256]) != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen)
                        {
                            rv = CKR_ARGUMENTS_BAD;
                            break;
                        }
                        rsaPadding = RsaPadding::rsaPkcs1Pss;
                        if (CKM_SHA256_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha256;
                        }
                        else if (CKM_SHA512_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha512;
                        }
                    break;
                default:
                    rv = CKR_MECHANISM_INVALID;
                    break;
            }

            if (CKR_OK != rv)
            {
                break;
            }

            sessionParameters.activeOperation.reset(ActiveOp::Verify_None);
            sessionParameters.activeOperation.set(ActiveOp::Verify_Init);
            sessionParameters.data.verifyParams.keyHandle  = hKey;
            sessionParameters.data.verifyParams.hashMode   = hashMode;
            sessionParameters.data.verifyParams.rsaPadding = rsaPadding;

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV verify(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR       pData,
             CK_ULONG          ulDataLen,
             CK_BYTE_PTR       pSignature,
             CK_ULONG          ulSignatureLen)
{
    CK_RV             rv        = CKR_FUNCTION_FAILED;
    uint32_t          sessionId = hSession & std::numeric_limits<uint32_t>::max();
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(sessionId))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(sessionId);

        if (!pData || !pSignature)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!sessionParameters.activeOperation.test(ActiveOp::Verify_Init))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        RsaPadding rsaPadding = sessionParameters.data.verifyParams.rsaPadding;
        uint32_t   keyHandle  = sessionParameters.data.verifyParams.keyHandle;
        HashMode   hashMode   = sessionParameters.data.verifyParams.hashMode;


        rv = P11Crypto::AsymmetricProvider::verify(keyHandle,
                                                   pData,      ulDataLen,
                                                   pSignature, ulSignatureLen,
                                                   rsaPadding,
                                                   hashMode);
        if (CKR_OK != rv)
        {
            break;
        }

        P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Verify);

        gSessionCache->add(sessionId, sessionParameters);
    } while (false);

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache)
        {
            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Verify);

            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}
