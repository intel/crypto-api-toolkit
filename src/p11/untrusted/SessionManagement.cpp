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

#include "SessionManagement.h"
#include "EnclaveInterface.h"
#include "p11Sgx.h"

//---------------------------------------------------------------------------------------------
CK_RV openSession(const CK_SLOT_ID&     slotID,
                  const CK_FLAGS&       flags,
                  CK_VOID_PTR           pApplication,
                  CK_NOTIFY             notify,
                  CK_SESSION_HANDLE_PTR phSession)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::openSession(slotID,
                                      flags,
                                      pApplication,
                                      notify,
                                      phSession);
}

//---------------------------------------------------------------------------------------------
CK_RV closeSession(const CK_SESSION_HANDLE& hSession)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::closeSession(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV closeAllSessions(const CK_SLOT_ID& slotID)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::closeAllSessions(slotID);
}

//---------------------------------------------------------------------------------------------
CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getSessionInfo(hSession, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV getOperationState(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pOperationState,
                        CK_ULONG_PTR pulOperationStateLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getOperationState(hSession, pOperationState, pulOperationStateLen);
}

//---------------------------------------------------------------------------------------------
CK_RV setOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::setOperationState(hSession, pOperationState,
                                            ulOperationStateLen,
                                            hEncryptionKey,
                                            hAuthenticationKey);
}

//---------------------------------------------------------------------------------------------
CK_RV login(CK_SESSION_HANDLE hSession,
            CK_USER_TYPE      userType,
            CK_UTF8CHAR_PTR   pPin,
            CK_ULONG          ulPinLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::login(hSession,
                                userType,
                                pPin,
                                ulPinLen);
}

//---------------------------------------------------------------------------------------------
CK_RV logout(CK_SESSION_HANDLE hSession)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::logout(hSession);
}
