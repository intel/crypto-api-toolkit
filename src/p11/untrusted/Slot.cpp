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

#include "Slot.h"

namespace P11Crypto
{
    //---------------------------------------------------------------------------------------------
    bool checkSlotValidity(const CK_SLOT_ID& slotID)
    {
        CK_ULONG numSlots = 0;

        return (numSlots = Utils::SlotUtils::getNumSlots(tokenPath.c_str())) && (slotID <= numSlots);
    }

    //---------------------------------------------------------------------------------------------
    Slot::Slot (const CK_SLOT_ID& slotID)
    {
        isValid = checkSlotValidity(slotID) && (token = new (std::nothrow) Token(slotID));

        if (isValid)
        {
            this->slotID = slotID;
        }
        else
        {
            this->slotID = maxSlotsSupported + 1;
        }
    }

    //---------------------------------------------------------------------------------------------
    Slot::~Slot()
    {
        if (token)
        {
            delete token;
            token = nullptr;
        }
    }

    //---------------------------------------------------------------------------------------------
    bool Slot::valid()
    {
        return isValid;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Slot::getSlotInfo(CK_SLOT_INFO_PTR info)
    {
        if (!info)
        {
            return CKR_ARGUMENTS_BAD;
        }

        if (!valid())
        {
            return CKR_SLOT_ID_INVALID;
        }

        std::string slotDescription = "Crypto API Toolkit Slot ID: " + std::to_string(slotID);
        slotDescription.resize(64, ' ');

        memset(info->slotDescription, ' ', 64);
        memcpy(info->slotDescription, slotDescription.data(), 64);

        memset(info->manufacturerID, ' ', 32);
        memcpy(info->manufacturerID, "Crypto API Toolkit", sizeof("Crypto API Toolkit") - 1);

        info->flags = CKF_TOKEN_PRESENT;

        // (ToDo) Make these configurable via configure.ac
        info->hardwareVersion.major = hardwareVersionMajor;
        info->hardwareVersion.minor = hardwareVersionMinor;
        info->firmwareVersion.major = firmwareVersionMajor;
        info->firmwareVersion.minor = firmwareVersionMinor;

        return CKR_OK;
    }

    //---------------------------------------------------------------------------------------------
    Token* Slot::getToken()
    {
        return token;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Slot::initToken(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, CK_UTF8CHAR_PTR label)
    {
        if (token)
        {
            return token->initToken(pin, pinLength, label);
        }

        return CKR_TOKEN_NOT_PRESENT;
    }
}