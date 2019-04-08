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

#include <string>
#include <dirent.h>
#include <string.h>
#include "Slot.h"
#include "CryptoEnclaveDefs.h"

namespace P11Crypto
{
    //---------------------------------------------------------------------------------------------
    bool checkSlotValidity(const CK_SLOT_ID& slotID)
    {
        bool     result      = false;
        CK_ULONG numOfSlots  = 0;
        do
        {
            DIR* dir = opendir(tokenPath.c_str());

            if (dir == NULL_PTR)
            {
                break;
            }

            // Enumerate the directory
            struct dirent* entry = NULL_PTR;

            while (entry = readdir(dir))
            {
                if (!strcmp(entry->d_name, ".") ||
                    !strcmp(entry->d_name, ".."))
                {
                    continue;
                }
                numOfSlots++;
            }

            int retValue = closedir(dir);

            if (slotID <= numOfSlots)
            {
                result = true;
            }

        } while(false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    Slot::Slot (const CK_SLOT_ID& slotID)
    {
        this->slotID = slotID;

        isValid = checkSlotValidity(slotID);

        token = new Token(slotID);

        if (!token)
        {
            isValid = false;
        }
    }

    //---------------------------------------------------------------------------------------------
    Slot::~Slot()
    {
        delete token;
    }

    //---------------------------------------------------------------------------------------------
    bool Slot::valid()
    {
        return isValid;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Slot::getSlotInfo(CK_SLOT_INFO_PTR info)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            if (!info)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            if (!valid())
            {
                rv = CKR_SLOT_ID_INVALID;
                break;
            }

            const std::string slotDescription = "Crypto API Toolkit Slot ID " + std::to_string(slotID);
            memset(info->slotDescription, ' ', 64);
            memcpy(info->slotDescription, slotDescription.data(), slotDescription.size());

            memset(info->manufacturerID, ' ', 32);
            memcpy(info->manufacturerID, "Crypto API Toolkit", 18);

            info->flags = CKF_TOKEN_PRESENT;

            info->hardwareVersion.major = 0;
            info->hardwareVersion.minor = 0;
            info->firmwareVersion.major = 0;
            info->firmwareVersion.minor = 0;

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    Token* Slot::getToken()
    {
        return token;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Slot::initToken(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, CK_UTF8CHAR_PTR label)
    {
        return token->initToken(pin, pinLength, label);
    }
}