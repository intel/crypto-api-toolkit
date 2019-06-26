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

#ifndef LOGIN_UTILS_H
#define LOGIN_UTILS_H

#include "p11Enclave_u.h"
#include "FileUtils.h"
#include "EnclaveUtils.h"
#include "CryptoEnclaveDefs.h"

#include <sstream>
#include <fstream>
#include <string>

namespace Utils
{
    namespace TokenUtils
    {
        struct TagLength
        {
            uint32_t tag;
            uint32_t length;
        };

        struct TLV
        {
            uint32_t    tag;
            uint32_t    length;
            std::string value;

            TLV()
            {
                clear();
            }

            ~TLV()
            {
                clear();
            }

            void clear()
            {
                tag = 0;
                length = 0;
                value.clear();
            }
        };

        struct TokenData
        {
            uint32_t    slotId;
            std::string label;
            std::string soPin;
            std::string userPin;

            TokenData()
            {
                clear();
            }

            ~TokenData()
            {
                clear();
            }

            void clear()
            {
                label.clear();
                soPin.clear();
                userPin.clear();
                slotId = maxSlotsSupported + 1;
            }
        };

        const uint32_t tagSlotId  = 0x01;
        const uint32_t tagLabel   = 0x02;
        const uint32_t tagSOPIN   = 0x03;
        const uint32_t tagUserPIN = 0x04;

        //---------------------------------------------------------------------------------------------
        CK_RV validatePin(const std::string& sealedPin, const std::string& pinEntered);

        //---------------------------------------------------------------------------------------------
        CK_RV setPin(const std::string& tokenFile,
                     const uint32_t&    tag,
                     const std::string& oldPin,
                     const std::string& newPin,
                     const std::string& sealedOldPin);

        //---------------------------------------------------------------------------------------------
        TokenData loadTokenData(const std::string& fileName);

        //---------------------------------------------------------------------------------------------
        bool writeToken(const std::string& fileName, const TokenData& tokenData);

        //---------------------------------------------------------------------------------------------
        bool updateTokenFileDataField(const std::string& fileName, const uint32_t& tag, const uint32_t& data);

        //---------------------------------------------------------------------------------------------
        bool updateTokenFileDataField(const std::string& fileName, const uint32_t& tag, const std::string& data);

        //---------------------------------------------------------------------------------------------
        bool updateTokenFileData(const std::string& fileName, const uint32_t& tag, const TokenData& inTokenData);
    }
}


#endif // LOGIN_UTILS_H
