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

#include "Token.h"
#include "FileUtils.h"

namespace P11Crypto
{
    //---------------------------------------------------------------------------------------------
    Token::Token(const CK_SLOT_ID& slotID)
    {
        this->slotID = slotID;

        std::string slotFolder    = "slot" + std::to_string(slotID);
        std::string tokenFileName = slotFolder + ".token";

        tokenFile = tokenPath + "/" + slotFolder + "/" + tokenFileName;
        isValid   = true;
        tokenData.clear();
    }

    //---------------------------------------------------------------------------------------------
    Token::~Token()
    {
        this->slotID = maxSlotsSupported + 1;
        tokenFile    = "";
        isValid      = false;
        tokenData.clear();
    }

    //---------------------------------------------------------------------------------------------
    bool Token::isTokenValid()
    {
        return isValid;
    }

    //---------------------------------------------------------------------------------------------
    void Token::loadTokenData()
    {
        tokenData = Utils::TokenUtils::loadTokenData(tokenFile);
        tokenDataLoaded = true;
    }

    //---------------------------------------------------------------------------------------------
    static bool createDirectory(const std::string& folderPath)
    {
        struct stat info;

        if (stat(folderPath.c_str(), &info) != 0)
        {
            int retValue = mkdir(folderPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            if (-1 == retValue)
            {
                return false;
            }
        }
        else if(!(info.st_mode & S_IFDIR))
        {
            return false;
        }

        return true;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::initToken(const CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, const CK_UTF8CHAR_PTR label)
    {
        CK_RV rv               = CKR_FUNCTION_FAILED;
        bool  tokenFilePresent = false;

        do
        {
            if (!gSessionCache)
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            if (!pin || !pinLength || !label ||
                strnlen(reinterpret_cast<const char*>(label), labelSize) != labelSize)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            // Create a directory(if not already present) for storing token objects in current slot.
            std::string folderPath = tokenPath + "slot" + std::to_string(slotID);

            if (!createDirectory(folderPath))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            folderPath += "/.tokenObjects";

            if (!createDirectory(folderPath))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            std::string soPin(reinterpret_cast<const char*>(pin), pinLength);
            std::string labelString(reinterpret_cast<const char*>(label), labelSize);

            // If token file is present, check for validity of SO pin and session count.
            if ((tokenFilePresent = Utils::FileUtils::isValid(tokenFile)))
            {
                if (!tokenDataLoaded)
                {
                    loadTokenData();
                }

                rv = Utils::TokenUtils::validatePin(tokenData.soPin, soPin);
                if (CKR_OK != rv)
                {
                    rv = CKR_PIN_INCORRECT;
                    break;
                }

                if (gSessionCache->sessionExists(slotID))
                {
                    rv = CKR_SESSION_EXISTS;
                    break;
                }
            }
            else
            {
                std::string sealedSoPin;

                bool sealPin = true;
                sealedSoPin = Utils::EnclaveUtils::sealDataBlob(soPin, sealPin);
                if (sealedSoPin.empty())
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                tokenData.soPin  = sealedSoPin;
            }

            // Update pin material in enclave cache.
            rv = Utils::EnclaveUtils::saveSoPinMaterial(this->slotID, tokenData.soPin);
            if (CKR_OK != rv)
            {
                break;
            }

            // A userPin once initialized for a token in a slot, will stay persistent through multiple C_InitToken calls.
            // In such cases, tokenData.userPin would already contain userPin by this point.

            tokenData.slotId = slotID;
            tokenData.label  = labelString;

            if (tokenFilePresent)
            {
                Utils::FileUtils::deleteFile(tokenFile);
            }

            if (!Utils::TokenUtils::writeToken(tokenFile, tokenData))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            rv = CKR_OK;

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::getTokenInfo(CK_TOKEN_INFO_PTR tokenInfo)
    {
        if (!tokenInfo)
        {
            return CKR_ARGUMENTS_BAD;
        }

        tokenInfo->flags = 0;

        memset(tokenInfo->label, ' ', 32);

        if (Utils::FileUtils::isValid(tokenFile))
        {
            tokenInfo->flags |= CKF_TOKEN_INITIALIZED;

            if (!tokenDataLoaded)
            {
                loadTokenData();
            }

            if (!tokenData.userPin.empty())
            {
                tokenInfo->flags |= CKF_USER_PIN_INITIALIZED;
            }

            if (tokenData.label.size() <= 32) // Size limit Check: tokenInfo->label is 32 bytes.
            {
                memcpy(tokenInfo->label, tokenData.label.data(), tokenData.label.size());
            }
        }

        tokenInfo->flags |= CKF_DUAL_CRYPTO_OPERATIONS;
        tokenInfo->flags |= CKF_LOGIN_REQUIRED;

        memset(tokenInfo->manufacturerID, ' ', 32);
        memcpy(tokenInfo->manufacturerID, "0x8086", sizeof("0x8086") - 1);

        memset(tokenInfo->model, ' ', 16);
        memcpy(tokenInfo->model, "Intel(R) SGX", sizeof("Intel(R) SGX") - 1);

        memset(tokenInfo->serialNumber, ' ', 16);
        memcpy(tokenInfo->serialNumber, "Unavailable", sizeof("Unavailable") - 1);

        tokenInfo->ulMaxSessionCount    = maxSessionsSupported;
        tokenInfo->ulSessionCount       = CK_UNAVAILABLE_INFORMATION;
        tokenInfo->ulMaxRwSessionCount  = maxRwSessionsSupported;
        tokenInfo->ulRwSessionCount     = CK_UNAVAILABLE_INFORMATION;

        tokenInfo->ulMaxPinLen = maxPinLength;
        tokenInfo->ulMinPinLen = minPinLength;

        tokenInfo->ulTotalPublicMemory  = CK_UNAVAILABLE_INFORMATION;
        tokenInfo->ulFreePublicMemory   = CK_UNAVAILABLE_INFORMATION;
        tokenInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        tokenInfo->ulFreePrivateMemory  = CK_UNAVAILABLE_INFORMATION;

        // Crypto API Toolkit release version is 1.5
        // SGX SDK version is 2.5
        tokenInfo->hardwareVersion.major = 1;
        tokenInfo->hardwareVersion.minor = 5;
        tokenInfo->firmwareVersion.major = 2;
        tokenInfo->firmwareVersion.minor = 5;

        return CKR_OK;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::login(const CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, const CK_USER_TYPE& userType)
    {
        CK_RV rv        = CKR_FUNCTION_FAILED;
        CK_RV loginRv   = CKR_FUNCTION_FAILED;
        bool  soUserType = (CKU_SO == userType);

        do
        {
            if (!pin || !pinLength ||
                ((CKU_SO != userType) && (CKU_USER != userType)))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            if (!gSessionCache)
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            // Lambda that returns CKR_USER_ALREADY_LOGGED_IN when same user is logged in and
            // returns CKR_USER_ANOTHER_ALREADY_LOGGED_IN when a different user is logged in.
            auto loginAllowed = [soUserType](const CK_SLOT_ID& slotID, CK_USER_TYPE type) -> CK_RV
                                            {
                                                if (gSessionCache->isLoggedIn(slotID, type))
                                                {
                                                    return CKR_USER_ALREADY_LOGGED_IN;
                                                }

                                                // Switch the type from CKU_USER to CKU_SO or vice versa to check the login status.
                                                type = soUserType ? CKU_USER : CKU_SO;

                                                if (gSessionCache->isLoggedIn(slotID, type))
                                                {
                                                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                                                }

                                                return CKR_OK;
                                            };

            loginRv = rv = loginAllowed(slotID, userType);
            if ((CKR_OK != rv) && (CKR_USER_ALREADY_LOGGED_IN != rv))
            {
                break;
            }

            if (!tokenDataLoaded)
            {
                loadTokenData();
            }

            std::string sealedPin;

            sealedPin = soUserType ? tokenData.soPin : tokenData.userPin;

            if (sealedPin.empty())
            {
                rv = soUserType ? CKR_GENERAL_ERROR : CKR_USER_PIN_NOT_INITIALIZED;
                break;
            }

            std::string pinEntered(reinterpret_cast<const char*>(pin), pinLength);

            rv = Utils::TokenUtils::validatePin(sealedPin, pinEntered);

            pinEntered.clear();

            if (CKR_OK != rv)
            {
                rv = CKR_PIN_INCORRECT;
                break;
            }

            if (loginRv != CKR_USER_ALREADY_LOGGED_IN)
            {
                if (!gSessionCache->login(slotID, userType))
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }
            }
            else
            {
                gSessionCache->updateSessionStateForLogin(slotID, userType);
            }
            rv = loginRv;
        } while (false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::logout()
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        if (!gSessionCache)
        {
            return rv;
        }

        if (!gSessionCache->isLoggedIn(slotID, CKU_SO) &&
            !gSessionCache->isLoggedIn(slotID, CKU_USER))
        {
            rv = CKR_USER_NOT_LOGGED_IN;
        }
        else
        {
            rv = gSessionCache->logout(slotID) ? CKR_OK : CKR_GENERAL_ERROR;
        }

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::initPin(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            if (!pin || !pinLength)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            if (!tokenDataLoaded)
            {
                loadTokenData();
            }

            if (!tokenData.userPin.empty())
            {
                rv = CKR_USER_PIN_ALREADY_INITIALIZED;
                break;
            }

            std::string userPinEntered(reinterpret_cast<const char*>(pin), pinLength);

            bool sealPin = true;
            tokenData.userPin = Utils::EnclaveUtils::sealDataBlob(userPinEntered, sealPin);

            if (tokenData.userPin.empty())
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            if (!Utils::TokenUtils::updateTokenFileDataField(tokenFile, Utils::TokenUtils::tagUserPIN, tokenData.userPin))
            {
                tokenData.userPin.clear();
                rv = CKR_GENERAL_ERROR;
                break;
            }

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::setPin(CK_UTF8CHAR_PTR oldPin, const CK_ULONG& oldPinLen,
                        CK_UTF8CHAR_PTR newPin, const CK_ULONG& newPinLen,
                        const CK_USER_TYPE&     userType)
    {
        CK_RV       rv  = CKR_FUNCTION_FAILED;
        uint32_t    tag = 0;
        std::string sealedPin;

        if (!oldPin || !newPin)
        {
            return CKR_ARGUMENTS_BAD;
        }

        std::string oldUserPin(reinterpret_cast<const char*>(oldPin), oldPinLen);
        std::string newUserPin(reinterpret_cast<const char*>(newPin), newPinLen);

        if (!tokenDataLoaded)
        {
            loadTokenData();
        }

        switch (userType)
        {
            case CKU_SO:
                tag = Utils::TokenUtils::tagSOPIN;
                sealedPin = tokenData.soPin;
                break;
            case CKU_USER:
                if (tokenData.userPin.empty())
                {
                    return CKR_USER_PIN_NOT_INITIALIZED;
                }
                tag = Utils::TokenUtils::tagUserPIN;
                sealedPin = tokenData.userPin;
                break;
            default:
                break;
        }

        if (!tag)
        {
            return CKR_USER_TYPE_INVALID;
        }

        rv = Utils::TokenUtils::setPin(tokenFile,
                                       tag,
                                       oldUserPin,
                                       newUserPin,
                                       sealedPin);
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::finalize()
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        rv = logout();
        if (CKR_OK                 != rv &&
            CKR_USER_NOT_LOGGED_IN != rv)
        {
            return rv;
        }

        return CKR_OK;
    }

    //---------------------------------------------------------------------------------------------
    std::string Token::getSOPinMaterial()
    {
        if (!tokenDataLoaded)
        {
            loadTokenData();
        }

        return tokenData.soPin;
    }
}
