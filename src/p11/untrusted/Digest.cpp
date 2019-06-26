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

#include "Digest.h"

//---------------------------------------------------------------------------------------------
static CK_RV populateHashMechanismParameters(const CK_MECHANISM_PTR pMechanism,
                                             HashMode*              hashMode,
                                             bool*                  hmac,
                                             uint32_t*              keyHandleForHmac)
{
    CK_RV rv = CKR_OK;

    if (!pMechanism || !hashMode || !hmac || !keyHandleForHmac)
    {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_SHA256:
            *hashMode = HashMode::sha256;
            break;
        case CKM_SHA512:
            *hashMode = HashMode::sha512;
            break;
        case CKM_SHA256_HMAC_AES_KEYID:
            *hashMode    = HashMode::sha256;
            *hmac        = true;
            if (!pMechanism->pParameter || (sizeof(CK_HMAC_AES_KEYID_PARAMS) != pMechanism->ulParameterLen))
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
            }
            else
            {
                *keyHandleForHmac = CK_HMAC_AES_KEYID_PARAMS_PTR(pMechanism->pParameter)->ulKeyID;
            }
            break;
        case CKM_SHA512_HMAC_AES_KEYID:
            *hashMode    = HashMode::sha512;
            *hmac        = true;
            if (!pMechanism->pParameter || (sizeof(CK_HMAC_AES_KEYID_PARAMS) != pMechanism->ulParameterLen))
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
            }
            else
            {
                *keyHandleForHmac = CK_HMAC_AES_KEYID_PARAMS_PTR(pMechanism->pParameter)->ulKeyID;
            }
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV digestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    CK_RV    rv               = CKR_FUNCTION_FAILED;
    HashMode hashMode         = HashMode::invalid;
    bool     hmac             = false;
    uint32_t keyHandleForHmac = 0;
    uint32_t hashHandle       = 0;

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

        SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
        if (!sessionParameters.activeOperation.test(ActiveOp::Hash_None))
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        rv = populateHashMechanismParameters(pMechanism,
                                             &hashMode,
                                             &hmac,
                                             &keyHandleForHmac);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = P11Crypto::HashProvider::hashInit(&hashHandle,
                                               keyHandleForHmac,
                                               hashMode,
                                               hmac);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.activeOperation.reset(ActiveOp::Hash_None);
        sessionParameters.activeOperation.set(ActiveOp::Hash_Init);
        sessionParameters.data.hashParams.hashHandle = hashHandle;
        sessionParameters.data.hashParams.hashMode   = hashMode;

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        gSessionCache->add(sessionId, sessionParameters);

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV digestUpdate(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pPart,
                   CK_ULONG          ulPartLen)
{
    CK_RV             rv         = CKR_FUNCTION_FAILED;
    uint32_t          hashHandle = 0;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(hSession);

        if (!pPart)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!(sessionParameters.activeOperation.test(ActiveOp::Hash_Init) ||
              sessionParameters.activeOperation.test(ActiveOp::Hash)))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        hashHandle = sessionParameters.data.hashParams.hashHandle;

        rv = P11Crypto::HashProvider::hashUpdate(hashHandle,
                                                 reinterpret_cast<uint8_t*>(pPart),
                                                 static_cast<uint32_t>(ulPartLen));
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.activeOperation.set(ActiveOp::Hash);
        sessionParameters.activeOperation.reset(ActiveOp::Hash_Init);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);
    } while (false);

    if (P11Crypto::cleanUpRequired(rv) && gSessionCache)
    {
        CK_RV returnValue = P11Crypto::HashProvider::destroyHash(hashHandle);

        P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Hash);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV digestFinal(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR       pDigest,
                  CK_ULONG_PTR      pulDigestLen)
{
    CK_RV             rv         = CKR_FUNCTION_FAILED;
    uint32_t          hashHandle = 0;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        sessionParameters = gSessionCache->getSessionParameters(sessionId);

        if (!pulDigestLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::Hash_None))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }
        else if (sessionParameters.activeOperation.test(ActiveOp::Hash_Init))
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        if (!pDigest)
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]);
            rv = CKR_OK;
            break;
        }

        if (*pulDigestLen < static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]))
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]);
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }

        hashHandle = sessionParameters.data.hashParams.hashHandle;
        rv = P11Crypto::HashProvider::hashFinal(hashHandle,
                                                reinterpret_cast<uint8_t*>(pDigest),
                                                static_cast<uint32_t>(*pulDigestLen));
        if (CKR_OK != rv)
        {
            break;
        }

        *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]);

        sessionParameters.activeOperation.set(ActiveOp::Hash_None);
        sessionParameters.activeOperation.reset(ActiveOp::Hash_Init);
        sessionParameters.activeOperation.reset(ActiveOp::Hash);

        P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Hash);

        CK_RV returnValue = P11Crypto::HashProvider::destroyHash(hashHandle);

        gSessionCache->add(sessionId, sessionParameters);
    } while (false);

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache)
        {
            CK_RV returnValue = P11Crypto::HashProvider::destroyHash(hashHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Hash);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV digest(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR       pData,
             CK_ULONG          ulDataLen,
             CK_BYTE_PTR       pDigest,
             CK_ULONG_PTR      pulDigestLen)

{
    CK_RV             rv         = CKR_FUNCTION_FAILED;
    uint32_t          hashHandle = 0;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(hSession);

        if (!pData || !pulDigestLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::Hash_None))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }
        else if (sessionParameters.activeOperation.test(ActiveOp::Hash))
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        hashHandle = sessionParameters.data.hashParams.hashHandle;

        if (!pDigest)
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]);
            rv = CKR_OK;
            break;
        }

        if (*pulDigestLen < static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]))
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.data.hashParams.hashMode]);
            rv            = CKR_BUFFER_TOO_SMALL;
            break;
        }

        rv = digestUpdate(hSession, pData, ulDataLen);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = digestFinal(hSession, pDigest, pulDigestLen);
        if (CKR_OK != rv)
        {
            break;
        }
    } while (false);

    if (P11Crypto::cleanUpRequired(rv))
    {
        CK_RV returnValue = P11Crypto::HashProvider::destroyHash(hashHandle);

        P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Hash);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);
    }

    return rv;
}