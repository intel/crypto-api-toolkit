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

#ifndef SESSIONMANAGEMENT_H
#define SESSIONMANAGEMENT_H

#include "cryptoki.h"

/**
* Opens a session between the application and a token in a slot.
* @param  slotID        The slot ID.
* @param  flags         Flags indicating the type of session.
* @param  pApplication  Application defined pointer for notification callback.
* @param  notify        Address of notification callback function.
* @param  phSession     The pointer that holds the session handle.
* @return CK_RV         CKR_OK if the session is successfully opened, error code otherwise.
*/
CK_RV openSession(const CK_SLOT_ID&     slotID,
                  const CK_FLAGS&       flags,
                  CK_VOID_PTR           pApplication,
                  CK_NOTIFY             notify,
                  CK_SESSION_HANDLE_PTR phSession);

/**
* Closes a session.
* @param  hSession The session ID.
* @return CK_RV    CKR_OK if the session is successfully closed, error code otherwise.
*/
CK_RV closeSession(const CK_SESSION_HANDLE& hSession);

/**
* Closes all sessions in a slot.
* @param  slotID   The slot ID.
* @return CK_RV    CKR_OK if all sessions in the slot are successfully closed, error code otherwise.
*/
CK_RV closeAllSessions(const CK_SLOT_ID& slotID);

/**
* Gets the session information.
* @param  hSession The session ID.
* @param  pInfo    Pointer to CK_SESSION_INFO structure, containing the session info.
* @return CK_RV    CKR_OK if the session info is successfully populated, error code otherwise.
*/
CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

/**
 *
*/
CK_RV getOperationState(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pOperationState,
                        CK_ULONG_PTR pulOperationStateLen);

/**
 *
*/
CK_RV setOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey);
/**
* Logs in a user into the token.
* @param  hSession The session ID.
* @param  userType The type of user, CKU_SO or CKU_USER.
* @param  pPin     The pin to be used for login.
* @param  ulPinLen The pin length.
* @return CK_RV    CKR_OK if the user is successfully logged in, error code otherwise.
*/
CK_RV login(CK_SESSION_HANDLE  hSession,
            CK_USER_TYPE       userType,
            CK_UTF8CHAR_PTR    pPin,
            CK_ULONG           ulPinLen);

/**
* Logs a user out of the token.
* @param  hSession The session ID.
* @return CK_RV    CKR_OK if the user is successfully logged out, error code otherwise.
*/
CK_RV logout(CK_SESSION_HANDLE hSession);

#endif // SESSIONMANAGEMENT_H