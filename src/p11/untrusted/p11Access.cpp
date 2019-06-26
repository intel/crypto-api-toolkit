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

#include "p11Access.h"

namespace P11Crypto
{
    //---------------------------------------------------------------------------------------------
    CK_RV checkReadAccess(const CK_SESSION_HANDLE& hSession, const CK_OBJECT_HANDLE&  hKey)
    {
        CK_RV rv        = CKR_FUNCTION_FAILED;
        bool  isPrivate = false;

        do
        {
            if (!gSessionCache)
            {
                rv = CKR_CRYPTOKI_NOT_INITIALIZED;
                break;
            }

            if (gSessionCache->findObject(hKey))
            {
                isPrivate = gSessionCache->privateObject(hKey);
            }
            else
            {
                rv = CKR_KEY_HANDLE_INVALID;
                break;
            }

            if (!isPrivate) // All non private objects have read access, irrespective of any session state.
            {
                rv = CKR_OK;
                break;
            }

            SessionState sessionState = gSessionCache->getSessionState(hSession);
            if (SessionState::RWSO     == sessionState ||
                SessionState::RWPublic == sessionState ||
                SessionState::ROPublic == sessionState)
            {
                rv = CKR_USER_NOT_LOGGED_IN;
                break;
            }

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV hasWriteAccess(const CK_SESSION_HANDLE& hSession, const bool& isPrivate, const bool& isTokenObject)
    {
        CK_RV        rv = CKR_FUNCTION_FAILED;
        SessionState sessionState;

        do
        {
            if (!gSessionCache)
            {
                break;
            }

            sessionState = gSessionCache->getSessionState(hSession);
            if (SessionState::RWUser == sessionState)
            {
                rv = CKR_OK;
                break;
            }
            else if (SessionState::RWPublic == sessionState ||
                     SessionState::RWSO     == sessionState)
            {
                if (isPrivate)
                {
                    rv = CKR_USER_NOT_LOGGED_IN;
                    break;
                }
            }
            else if (SessionState::ROUser == sessionState)
            {
                if (isTokenObject)
                {
                    rv = CKR_SESSION_READ_ONLY;
                    break;
                }
            }
            else if (SessionState::ROPublic == sessionState)
            {
                if (isTokenObject)
                {
                    rv = CKR_SESSION_READ_ONLY;
                    break;
                }
                else
                {
                    if (isPrivate)
                    {
                        rv = CKR_USER_NOT_LOGGED_IN;
                        break;
                    }
                }
            }

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV checkWriteAccess(const CK_SESSION_HANDLE& hSession,
                           const CK_ATTRIBUTE_PTR   pTemplate,
                           const CK_ULONG&          ulCount)
    {
        CK_RV rv          = CKR_FUNCTION_FAILED;
        bool  isPrivate   = false;
        bool  tokenObject = false;

        do
        {
            for (CK_ULONG i = 0; i < ulCount; ++i)
            {
                switch (pTemplate[i].type)
                {
                    case CKA_TOKEN:
                        if (pTemplate[i].pValue                         &&
                            sizeof(CK_BBOOL) == pTemplate[i].ulValueLen &&
                            CK_TRUE          == *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue))
                        {
                            tokenObject = true;
                        }
                        break;
                    case CKA_PRIVATE:
                        if (pTemplate[i].pValue                         &&
                            sizeof(CK_BBOOL) == pTemplate[i].ulValueLen &&
                            CK_TRUE          == *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue))
                        {
                            isPrivate = true;
                        }
                        break;
                }
            }

            rv = hasWriteAccess(hSession, isPrivate, tokenObject);
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV checkWriteAccess(const CK_SESSION_HANDLE& hSession, const CK_OBJECT_HANDLE& hKey)
    {
        CK_RV rv          = CKR_FUNCTION_FAILED;
        bool  isPrivate   = false;
        bool  tokenObject = false;

        do
        {
            if (!gSessionCache)
            {
                break;
            }

            if (gSessionCache->findObject(hKey))
            {
                isPrivate   = gSessionCache->privateObject(hKey);
                tokenObject = gSessionCache->tokenObject(hKey);
            }
            else
            {
                rv = CKR_KEY_HANDLE_INVALID;
                break;
            }

            rv = hasWriteAccess(hSession, isPrivate, tokenObject);
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    bool cleanUpRequired(const CK_RV& rv)
    {
        bool result = true;

        switch(rv)
        {
            case CKR_OK:
            case CKR_SESSION_HANDLE_INVALID:
            case CKR_CRYPTOKI_NOT_INITIALIZED:
            case CKR_BUFFER_TOO_SMALL:
                result = false;
                break;
            default:
                result = true;
                break;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    void resetSessionParameters(SessionParameters* sessionParameters, const CurrentOperation& currentOp)
    {
        if (!sessionParameters)
        {
            return;
        }

        switch(currentOp)
        {
            case CurrentOperation::Encrypt:
                sessionParameters->activeOperation.set(ActiveOp::Encrypt_None);
                sessionParameters->activeOperation.reset(ActiveOp::AesEncrypt_Init);
                sessionParameters->activeOperation.reset(ActiveOp::AesEncrypt);
                sessionParameters->activeOperation.reset(ActiveOp::RsaEncrypt_Init);
                sessionParameters->data.encryptParams.clear();
                break;
            case CurrentOperation::Decrypt:
                sessionParameters->activeOperation.set(ActiveOp::Decrypt_None);
                sessionParameters->activeOperation.reset(ActiveOp::AesDecrypt_Init);
                sessionParameters->activeOperation.reset(ActiveOp::AesDecrypt);
                sessionParameters->activeOperation.reset(ActiveOp::RsaDecrypt_Init);
                sessionParameters->data.decryptParams.clear();
                break;
            case CurrentOperation::Sign:
                sessionParameters->activeOperation.set(ActiveOp::Sign_None);
                sessionParameters->activeOperation.reset(ActiveOp::Sign_Init);
                sessionParameters->data.signParams.clear();
                break;
            case CurrentOperation::Verify:
                sessionParameters->activeOperation.set(ActiveOp::Verify_None);
                sessionParameters->activeOperation.reset(ActiveOp::Verify_Init);
                sessionParameters->data.verifyParams.clear();
                break;
            case CurrentOperation::Hash:
                sessionParameters->activeOperation.set(ActiveOp::Hash_None);
                sessionParameters->activeOperation.reset(ActiveOp::Hash_Init);
                sessionParameters->activeOperation.reset(ActiveOp::Hash);
                sessionParameters->data.hashParams.clear();
                break;
            default:
                break;
        }
    }
}
