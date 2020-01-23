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

#include "SlotTokenManagement.h"
#include "EnclaveInterface.h"
#include "p11Sgx.h"

//---------------------------------------------------------------------------------------------
CK_RV getSlotList(const CK_BBOOL& tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getSlotList(tokenPresent,
                                      pSlotList,
                                      pulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV getSlotInfo(const CK_SLOT_ID& slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getSlotInfo(slotID,
                                      pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV getTokenInfo(const CK_SLOT_ID& slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getTokenInfo(slotID, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV waitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::waitForSlotEvent(flags, pSlot, pReserved);
}

//---------------------------------------------------------------------------------------------
CK_RV getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getMechanismList(slotID, pMechanismList, pulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getMechanismInfo(slotID, type, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV initToken(CK_SLOT_ID      slotID,
                CK_UTF8CHAR_PTR pPin,
                CK_ULONG        ulPinLen,
                CK_UTF8CHAR_PTR pLabel)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::initToken(slotID, pPin, ulPinLen, pLabel);
}

//---------------------------------------------------------------------------------------------
CK_RV initPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::initPIN(hSession, pPin, ulPinLen);
}

//---------------------------------------------------------------------------------------------
CK_RV setPIN(CK_SESSION_HANDLE  hSession,
             CK_UTF8CHAR_PTR    pOldPin,
             CK_ULONG           ulOldLen,
             CK_UTF8CHAR_PTR    pNewPin,
             CK_ULONG           ulNewLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::setPIN(hSession,
                                 pOldPin,
                                 ulOldLen,
                                 pNewPin,
                                 ulNewLen);
}
