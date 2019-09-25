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

#ifndef TOKEN_H
#define TOKEN_H

#include "p11Sgx.h"
#include "p11Defines.h"
#include "TokenUtils.h"
#include "EnclaveUtils.h"
#include "Constants.h"
#include "SlotUtils.h"
#include "FileUtils.h"
#include "SessionCache.h"

#include <sys/stat.h>
#include <string.h>
#include <sstream>
#include <string>
#include <vector>


namespace P11Crypto
{
    class Token
    {
    public:
        // Constructor
        Token(const CK_SLOT_ID& slotID);

        Token(const Token&) = delete;

        Token& operator=(const Token&) = delete;

        // Destructor
        virtual ~Token();

        /**
        * Gets the token information.
        * @param  tokenInfo  The (pointer to) structure to be populated with token information.
        * @return CK_RV      CKR_OK if success, error code otherwise.
        */
        CK_RV getTokenInfo(CK_TOKEN_INFO_PTR tokenInfo);

        /**
        * Checks for token validity.
        * @return bool  true if token is valid, false otherwise.
        */
        bool isTokenValid();

        /**
        * Initializes the token.
        * @param  pin            Pointer to the initial SO pin.
        * @param  pinLength      The length of initial SO pin.
        * @param  label          The application passed label for the token.
        * @return CK_RV          CKR_OK if token is initialized, error code otherwise.
        */
        CK_RV initToken(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, CK_UTF8CHAR_PTR label);

        /**
        * Initializes a user pin.
        * @param  pin            Pointer to the user pin.
        * @param  pinLength      The length of user pin.
        * @return CK_RV          CKR_OK if user pin is initialized, error code otherwise.
        */
        CK_RV initPin(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength);

        /**
        * Sets a new pin for SO or User by validating for the old pin.
        * @param  oldPin            Pointer to the old SO pin.
        * @param  oldPinLength      The length of old SO pin.
        * @param  newPin            Pointer to the new SO pin.
        * @param  newPinLength      The length of new SO pin.
        * @param  userType          A CK_USER_TYPE representing SO or User
        * @return CK_RV             CKR_OK if new SO pin is set, error code otherwise.
        */
        CK_RV setPin(CK_UTF8CHAR_PTR oldPin, const CK_ULONG& oldPinLen,
                     CK_UTF8CHAR_PTR newPin, const CK_ULONG& newPinLen,
                     const CK_USER_TYPE&     userType);

        /**
        * Logs out a currently logged in user.
        * @return CK_RV   CKR_OK if currently loggedin user is logged out, error code otherwise.
        */
        CK_RV logout();

        /**
        * Finalizes a token in a slot. This involves logging out any user logged in, closing all sessions
        * and removing the user pin set.
        * @return CK_RV   CKR_OK if finalize successful, error code otherwise.
        */
        CK_RV finalize();

        CK_RV login(const CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, const CK_USER_TYPE& userType);

        std::string getSOPinMaterial();

    private:

        void loadTokenData();

        CK_SLOT_ID slotID;

        // Token validity
        bool isValid;

        // Token file name
        std::string tokenFile;

        // Structure to store all token file fields
        Utils::TokenUtils::TokenData tokenData{};

        bool tokenDataLoaded = false;

        static const uint8_t labelSize = 32;
    };
}

#endif // TOKEN_H

