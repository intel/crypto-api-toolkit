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

#ifndef SLOT_H
#define SLOT_H

#include "p11Defines.h"
#include "Token.h"
#include "SlotUtils.h"
#include "CryptoEnclaveDefs.h"

#include <string>
#include <dirent.h>
#include <string.h>

namespace P11Crypto
{
    class Slot
    {
    public:
        // Constructor
        Slot(const CK_SLOT_ID& slotID);

        Slot(const Slot&) = delete;

        Slot& operator=(const Slot&) = delete;

        // Destructor
        virtual ~Slot();

        /**
        * Checks if a slot is valid.
        * @return bool  true if current slot is valid, false otherwise.
        */
        bool valid();

        /**
        * Gets the token in the current slot.
        * @return Token  A token object in current slot.
        */
        Token* getToken();

        /**
        * Initializes the token in current slot.
        * @param  pin            Pointer to the initial SO pin.
        * @param  pinLength      The length of initial SO pin.
        * @param  label          The application passed label for the token.
        * @return CK_RV          CKR_OK if token is initialized, error code otherwise.
        */
        CK_RV initToken(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, CK_UTF8CHAR_PTR label);

        /**
        * Gets the slot Information.
        * @param  info           The (pointer to) structure to be populated with slot information.
        * @return CK_RV          CKR_OK if slot information is populated, error code otherwise.
        */
        CK_RV getSlotInfo(CK_SLOT_INFO_PTR info);

    private:

        // Token in the slot
        Token* token = nullptr;

        // The slotID
        CK_SLOT_ID slotID;

        // SlotID's validity
        bool isValid;

        static const CK_BYTE hardwareVersionMajor = 1;
        static const CK_BYTE hardwareVersionMinor = 3;
        static const CK_BYTE firmwareVersionMajor = 2;
        static const CK_BYTE firmwareVersionMinor = 4;
    };
}

#endif // SLOT_H

