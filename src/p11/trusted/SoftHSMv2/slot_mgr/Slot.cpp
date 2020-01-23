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

/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 Slot.h

 This class represents a single PKCS #11 slot
 *****************************************************************************/

#include "config.h"
#include "SessionManager.h"
#include "SlotManager.h"
#include "Token.h"

//#include <stdio.h>
#include <string.h>
#include <mbusafecrt.h>

// Constructor
Slot::Slot(ObjectStore* inObjectStore, CK_SLOT_ID inSlotID, ObjectStoreToken* inToken /* = NULL */)
{
	objectStore = inObjectStore;
	slotID = inSlotID;

	if (inToken != NULL)
	{
		token = new Token(inToken);
	}
	else
	{
		token = new Token();
	}
}

// Destructor
Slot::~Slot()
{
	delete token;
}

// Retrieve the token in the slot
Token* Slot::getToken()
{
	return token;
}

// Initialise the token in the slot
CK_RV Slot::initToken(ByteString& soPIN, CK_UTF8CHAR_PTR label)
{
	return token->createToken(objectStore, soPIN, label);
}

// Retrieve slot information for the slot
CK_RV Slot::getSlotInfo(CK_SLOT_INFO_PTR info)
{
	if (info == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

    char slotDescription [64];
    char slotId[10];
#ifndef SGXHSM
    snprintf(slotDescription, sizeof("SoftHSM slot ID 0x"), "SoftHSM slot ID 0x");
#else
    snprintf(slotDescription, sizeof("SGXHSM slot ID 0x"), "SGXHSM slot ID 0x");
#endif
    snprintf(slotId, sizeof(slotId), "0x%lx", slotID);
    strncat_s(slotDescription, sizeof(slotDescription), slotId, 9);
	const std::string sDescription(slotDescription, sizeof(slotDescription) - 1);

	char mfgID[33];
#ifndef SGXHSM
	snprintf(mfgID, sizeof(mfgID), "SoftHSM project");
#else
	snprintf(mfgID, sizeof(mfgID), "SGXHSM project");
#endif

	memset(info->slotDescription, ' ', sizeof(info->slotDescription));
	memset(info->manufacturerID, ' ', sizeof(info->manufacturerID));
    memcpy_s(info->slotDescription, sizeof(info->slotDescription), sDescription.data(), sDescription.size());
    memcpy_s(info->manufacturerID, sizeof(info->manufacturerID), mfgID, strlen(mfgID));

	info->flags = CKF_TOKEN_PRESENT;

	info->hardwareVersion.major = 1;
	info->hardwareVersion.minor = 2;
	info->firmwareVersion.major = 3;
	info->firmwareVersion.minor = 4;
	return CKR_OK;
}

// Get the slot ID
CK_SLOT_ID Slot::getSlotID()
{
	return slotID;
}

// Is a token present?
bool Slot::isTokenPresent()
{
	return true;
}
