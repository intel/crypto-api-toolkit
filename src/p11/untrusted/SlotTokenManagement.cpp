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

#include "SlotTokenManagement.h"

//---------------------------------------------------------------------------------------------
CK_RV getSlotList(const CK_BBOOL& tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    CK_RV    rv       = CKR_FUNCTION_FAILED;
    CK_ULONG numSlots = 0;

    do
    {
        if (!isInitialized())
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pulCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        numSlots = Utils::SlotUtils::getNumSlots(tokenPath.c_str());

        numSlots = (numSlots >= maxSlotsSupported) ? maxSlotsSupported : numSlots;

        if (!pSlotList)
        {
            *pulCount = numSlots;
            rv        = CKR_OK;
            break;
        }

        if (*pulCount < numSlots)
        {
            *pulCount = numSlots;
            rv        = CKR_BUFFER_TOO_SMALL;
            break;
        }

        for (auto i = 0; i < numSlots; ++i)
        {
            pSlotList[i] = i;
        }

        *pulCount = numSlots;

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getSlotInfo(const CK_SLOT_ID& slotID, CK_SLOT_INFO_PTR pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized())
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

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        rv = slot.getSlotInfo(pInfo);

    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getTokenInfo(const CK_SLOT_ID& slotID, CK_TOKEN_INFO_PTR pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized())
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

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        rv = token->getTokenInfo(pInfo);
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    CK_RV              rv                       = CKR_FUNCTION_FAILED;
    constexpr uint32_t symmetricMechanismCount  = sizeof(symmetricMechanisms) / sizeof(CK_MECHANISM_TYPE);
    constexpr uint32_t asymmetricMechanismCount = sizeof(asymmetricMechanisms) / sizeof(CK_MECHANISM_TYPE);
    constexpr uint32_t digestMechanismCount     = sizeof(digestMechanisms) / sizeof(CK_MECHANISM_TYPE);
    constexpr uint32_t totalMechanismsSupported = symmetricMechanismCount + asymmetricMechanismCount + digestMechanismCount;

    do
    {
        if (!isInitialized())
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

        if (!pulCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!pMechanismList)
        {
            *pulCount = totalMechanismsSupported;
            rv        = CKR_OK;
            break;
        }

        if (*pulCount < totalMechanismsSupported)
        {
            *pulCount = totalMechanismsSupported;
            rv        = CKR_BUFFER_TOO_SMALL;
            break;
        }

        auto j = 0;

        for (auto i = 0; i < symmetricMechanismCount; ++i, ++j)
        {
            pMechanismList[j] = symmetricMechanisms[i];
        }

        for (auto i = 0; i < asymmetricMechanismCount; ++i, ++j)
        {
            pMechanismList[j] = asymmetricMechanisms[i];
        }

        for (auto i = 0; i < digestMechanismCount; ++i, ++j)
        {
            pMechanismList[j] = digestMechanisms[i];
        }

        *pulCount = totalMechanismsSupported;

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized())
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

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        switch(type)
        {
            case CKM_AES_KEY_GEN:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength128);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength256);
                pInfo->flags        = CKF_HW | CKF_GENERATE;
                break;
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_GENERATE_KEY_PAIR;
                break;
            case CKM_AES_CTR:
            case CKM_AES_GCM:
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength128);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength256);
                pInfo->flags        = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
                break;
            case CKM_RSA_PKCS:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP;
                break;
            case CKM_RSA_PKCS_PSS:
            case CKM_SHA256_RSA_PKCS:
            case CKM_SHA512_RSA_PKCS:
            case CKM_SHA256_RSA_PKCS_PSS:
            case CKM_SHA512_RSA_PKCS_PSS:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_SIGN | CKF_VERIFY;
                break;
            case CKM_SHA256:
            case CKM_SHA512:
                pInfo->ulMinKeySize = 0;
                pInfo->ulMaxKeySize = 0;
                pInfo->flags        = CKF_HW | CKF_DIGEST;
                break;
            case CKM_SHA256_HMAC_AES_KEYID:
            case CKM_SHA512_HMAC_AES_KEYID:
                pInfo->ulMinKeySize = 0;
                pInfo->ulMaxKeySize = maxAesKeySizeForHmacImport;
                pInfo->flags        = CKF_HW | CKF_DIGEST;
                break;
            case CKM_AES_PBIND:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength128);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength256);
                pInfo->flags        = CKF_HW | CKF_WRAP | CKF_UNWRAP;
                break;
            case CKM_RSA_PBIND_EXPORT:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_WRAP;
                break;
            case CKM_RSA_PBIND_IMPORT:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_GENERATE_KEY_PAIR;
                break;
            case CKM_EXPORT_RSA_PUBLIC_KEY:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_WRAP;
                break;
            case CKM_IMPORT_RSA_PUBLIC_KEY:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_UNWRAP;
                break;
            case CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY:
            case CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_WRAP | CKF_UNWRAP;
                break;
            default:
                return CKR_MECHANISM_INVALID;
                break;
        }

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV initToken(CK_SLOT_ID      slotID,
                CK_UTF8CHAR_PTR pPin,
                CK_ULONG        ulPinLen,
                CK_UTF8CHAR_PTR pLabel)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized())
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

        if (!pPin || !pLabel)
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

        rv = slot.initToken(pPin, ulPinLen, pLabel);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV initPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
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

        SessionState sessionState = gSessionCache->getSessionState(hSession);
        if (SessionState::RWSO != sessionState)
        {
            rv = CKR_USER_NOT_LOGGED_IN;
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

        rv = token->initPin(pPin, ulPinLen);
        if (CKR_OK != rv)
        {
            break;
        }
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV setPIN(CK_SESSION_HANDLE  hSession,
             CK_UTF8CHAR_PTR    pOldPin,
             CK_ULONG           ulOldLen,
             CK_UTF8CHAR_PTR    pNewPin,
             CK_ULONG           ulNewLen)
{
    CK_RV rv = CKR_OK;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pOldPin || !pNewPin)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if ((ulOldLen < minPinLength) || (ulOldLen > maxPinLength) ||
            (ulNewLen < minPinLength) || (ulNewLen > maxPinLength))
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

        SessionState sessionState = gSessionCache->getSessionState(hSession);

        CK_USER_TYPE userType = CKU_USER_INVALID;
        switch(sessionState)
        {
            case SessionState::RWSO:
                userType = CKU_SO;
                break;
            case SessionState::RWUser:
            case SessionState::RWPublic:
                userType = CKU_USER;
                break;
            default:
                rv = CKR_SESSION_READ_ONLY;
                break;
        }

        if (CKR_OK != rv)
        {
            break;
        }

        rv = token->setPin(pOldPin, ulOldLen,
                           pNewPin, ulNewLen,
                           userType);
    } while(false);

    return rv;
}
