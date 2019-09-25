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

#include "SessionManagement.h"

//---------------------------------------------------------------------------------------------
static std::string getSOPinMaterial(const CK_SLOT_ID& slotId)
{
    std::string soPinMaterial;

    P11Crypto::Slot slot(slotId);
    if (!slot.valid())
    {
        return soPinMaterial;
    }

    P11Crypto::Token* token = slot.getToken();
    if (!token)
    {
        return soPinMaterial;
    }

    soPinMaterial = token->getSOPinMaterial();

    return soPinMaterial;
}

//---------------------------------------------------------------------------------------------
static CK_RV loadTokenObjects(const CK_SLOT_ID& slotID, const CK_SESSION_HANDLE& sessionId)
{
    CK_RV rv = CKR_OK;

    do
    {
        std::string tokenFolderPath = tokenPath + "/" + "slot" + std::to_string(slotID) + "/.tokenObjects";
        std::string fileName, tokenObjectFilePath, soPinMaterial;
        uint32_t    keyHandle = 0;
        DIR*        dir       = nullptr;

        soPinMaterial = getSOPinMaterial(slotID);
        if (soPinMaterial.empty())
        {
            break;
        }

        rv = Utils::EnclaveUtils::saveSoPinMaterial(slotID, soPinMaterial);
        if (CKR_OK != rv)
        {
            break;
        }

        dir = opendir(tokenFolderPath.c_str());
        if (!dir)
        {
            rv = CKR_GENERAL_ERROR;
            break;
        }

        struct dirent* entry = nullptr;

        while (entry = readdir(dir))
        {
            if (!std::strcmp(entry->d_name, ".") ||
                !std::strcmp(entry->d_name, ".."))
            {
                continue;
            }

            keyHandle = 0;

            fileName.clear();
            fileName = entry->d_name;

            tokenObjectFilePath.clear();
            tokenObjectFilePath = tokenFolderPath + "/" + fileName;

            std::vector<uint64_t> packedAttributes;
            uint64_t attributeBufferLenRequired = 0;

            rv = Utils::EnclaveUtils::readTokenObject(tokenObjectFilePath,
                                                      slotID,
                                                      nullptr, 0,
                                                      &attributeBufferLenRequired, &keyHandle);
            if (CKR_OK != rv)
            {
                break;
            }

            if (0 != (attributeBufferLenRequired % sizeof(CK_ULONG)))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            attributeBufferLenRequired = attributeBufferLenRequired / (sizeof(CK_ULONG));

            packedAttributes.resize(attributeBufferLenRequired);

            rv = Utils::EnclaveUtils::readTokenObject(tokenObjectFilePath,
                                                      slotID,
                                                      packedAttributes.data(), packedAttributes.size() * sizeof(CK_ULONG),
                                                      &attributeBufferLenRequired, &keyHandle);
            if (CKR_OK != rv)
            {
                break;
            }

            UlongAttributeSet  ulongAttributes;
            StringAttributeSet strAttributes;
            BoolAttributeSet   boolAttributes;

            if (!Utils::AttributeUtils::unpackAttributes(packedAttributes, &ulongAttributes, &strAttributes, &boolAttributes))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            ObjectParameters objectParams {};

            objectParams.slotId          = slotID;
            objectParams.sessionHandle   = sessionId;
            objectParams.ulongAttributes = ulongAttributes;
            objectParams.strAttributes   = strAttributes;
            objectParams.boolAttributes  = boolAttributes;
            objectParams.objectState     = ObjectState::NOT_IN_USE;

            gSessionCache->addObject(sessionId, keyHandle, objectParams);
        }

        closedir(dir);

    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV openSession(const CK_SLOT_ID&     slotID,
                  const CK_FLAGS&       flags,
                  CK_VOID_PTR           pApplication,
                  CK_NOTIFY             notify,
                  CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!phSession || pApplication || notify)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        P11Crypto::Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        *phSession = 0;

        if (!(CKF_SERIAL_SESSION & flags))
        {
            rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
            break;
        }

        if (gSessionCache->count() == maxSessionsSupported)
        {
            rv = CKR_SESSION_COUNT;
            break;
        }

        uint32_t sessionId = 0;

        rv = gSessionCache->createSession(slotID, flags, &sessionId);
        if (CKR_OK == rv)
        {
            *phSession = sessionId;
        }

        if (!gSessionCache->tokenObjectsLoaded(slotID))
        {
            rv = loadTokenObjects(slotID, sessionId);
            if (CKR_OK != rv)
            {
                gSessionCache->closeSession(sessionId);
                break;
            }

            gSessionCache->updateTokenObjectStatus(slotID);
        }

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV closeSession(const CK_SESSION_HANDLE& hSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

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

        CK_ULONG slotId = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotId);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (gSessionCache->logoutRequired(slotId, hSession))
        {
            rv = logout(hSession);
            if (CKR_OK != rv)
            {
                rv = CKR_FUNCTION_FAILED;
                break;
            }
        }

        // Remove current session from session cache
        if (!gSessionCache->closeSession(hSession))
        {
            rv = CKR_SESSION_CLOSED;
            break;
        }

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV closeAllSessions(const CK_SLOT_ID& slotID)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        P11Crypto::Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (gSessionCache->logoutRequired(slotID))
        {
            rv = token->logout();
            if (CKR_OK != rv)
            {
                break;
            }
        }

        rv = gSessionCache->closeAllSessions(slotID);

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!isInitialized() || !gSessionCache)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return gSessionCache->getSessionInfo(hSession, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV login(CK_SESSION_HANDLE hSession,
            CK_USER_TYPE      userType,
            CK_UTF8CHAR_PTR   pPin,
            CK_ULONG          ulPinLen)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pPin)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if ((ulPinLen < minPinLength) ||
            (ulPinLen > maxPinLength))
        {
            rv = CKR_PIN_LEN_RANGE;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if(CKU_SO == userType &&
           gSessionCache->sessionStateExists(slotID, SessionState::ROPublic))
        {
            rv = CKR_SESSION_READ_ONLY_EXISTS;
            break;
        }

        if((CKU_SO == userType) || (CKU_USER == userType))
        {
            rv = token->login(pPin, ulPinLen, userType);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else // User type of CKU_CONTEXT_SPECIFIC is not supported.
        {
            rv = CKR_USER_TYPE_INVALID;
            break;
        }

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV logout(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

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

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        rv = token->logout();
        if (CKR_OK != rv)
        {
            break;
        }

        rv = CKR_OK;
    } while(false);

    return rv;
}
