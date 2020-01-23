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

#ifndef SLOT_TOKEN_MANAGEMENT_H
#define SLOT_TOKEN_MANAGEMENT_H

#include "cryptoki.h"

/**
* Gets a list of slots.
* @param  tokenPresent  Bool whether to return all slots or only slots with token present.
* @param  pSlotList     Pointer to a list of slot IDs.
* @param  pulCount      Pointer that holds number of slots.
* @return CK_RV         CKR_OK if the slot list or slot count is successfully populated, error code otherwise.
*/
CK_RV getSlotList(const CK_BBOOL& tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

/**
* Gets information about a slot.
* @param  slotID  The slot ID.
* @param  pInfo   Pointer to hold the slot information.
* @return CK_RV   CKR_OK if the slot information is successfully populated, error code otherwise.
*/
CK_RV getSlotInfo(const CK_SLOT_ID& slotID, CK_SLOT_INFO_PTR pInfo);

/**
* Gets information about a token in a slot.
* @param  slotID  The slot ID.
* @param  pInfo   Pointer to hold the token information.
* @return CK_RV   CKR_OK if the token information is successfully populated, error code otherwise.
*/
CK_RV getTokenInfo(const CK_SLOT_ID& slotID, CK_TOKEN_INFO_PTR pInfo);

/**
 *
*/
CK_RV waitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

/**
* Gives a pointer to a list of function pointers.
* @param  slotID            The slot ID.
* @param  pMechanismList    Pointer to a list of mechanisms.
* @param  pulCount          Pointer that holds number of mechanisms.
* @return CK_RV             CKR_OK if the mechanism list or mechanism count is successfully populated, error code otherwise.
*/
CK_RV getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);

/**
* Gets information about a mechanism.
* @param  slotID  The slot ID.
* @param  type    The type of mechanism.
* @param  pInfo   Pointer to hold mechanism information.
* @return CK_RV   CKR_OK if the mechanism information is successfully populated, error code otherwise.
*/
CK_RV getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

/**
* Initializes a token in a slot.
* @param  slotID   The slot ID.
* @param  pPin     The pin to initialize token.
* @param  ulPinLen The pin length.
* @param pLabel    Pointer holding label of token.
* @return CK_RV    CKR_OK if the token is successfully initialized, error code otherwise.
*/
CK_RV initToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);

/**
* Initializes a user pin.
* @param  hSession  The session handle.
* @param  pPin      The pin to be initialized.
* @param  ulPinLen  The pin length.
* @return CK_RV     CKR_OK if the user pin is successfully initialized, error code otherwise.
*/
CK_RV initPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

/**
* Sets a pin.
* @param  hSession  The session handle.
* @param  pOldPin   The old pin.
* @param  ulOldLen  The old pin length.
* @param  pNewPin   The new pin.
* @param  ulNewLen  The new pin length.
* @return CK_RV     CKR_OK if the pin is successfully set, error code otherwise.
*/
CK_RV setPIN(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

#endif // SLOT_TOKEN_MANAGEMENT_H