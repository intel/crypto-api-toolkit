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

#include <sys/stat.h>
#include <string.h>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>

#include "Token.h"
#include "CryptoEnclaveDefs.h"
#include "EnclaveHelpers.h"
#include "p11Enclave_u.h"

#include <iomanip>

namespace P11Crypto
{
    // Separator string to be placed in token file
    std::string separator("**********");

    std::string slotKeyword         = "Slot :";
    std::string sessionCountKeyword = "No of Sessions :";
    std::string soPinKeyword        = "SO PIN :";
    std::string userPinKeyword      = "User PIN :";
    std::string labelKeyword        = "label :";
    std::string soLoginKeyword      = "SO LoggedIn :";
    std::string userLoginKeyword    = "USER LoggedIn :";

    //---------------------------------------------------------------------------------------------
    bool isTokenFilePresent(const CK_SLOT_ID& slotID)
    {
        bool tokenFilePresent = false;
        struct stat buffer;

        std::string tokenFileName(tokenPath + "slot" + std::to_string(slotID) + ".token");
        tokenFilePresent = (stat(tokenFileName.c_str(), &buffer) == 0);

        return tokenFilePresent;
    }

    //---------------------------------------------------------------------------------------------
    Token::Token(const CK_SLOT_ID& slotID)
    {
        this->slotID = slotID;
        isValid      = true;
    }

    //---------------------------------------------------------------------------------------------
    Token::~Token()
    {
    }

    //---------------------------------------------------------------------------------------------
    void populateStringFromVector(const std::vector<uint8_t>& source,
                                  std::string&                destination)
    {
        destination.clear();
        uint32_t length = source.size();
        for (auto i = 0; i < length; i ++)
        {
            destination.push_back(source[i]);
        }
    }

    //---------------------------------------------------------------------------------------------
    CK_RV sealString(std::string& input,
                     std::string& sealedOutput,
                     bool         pin = false)
    {
        CK_RV                rv              = CKR_FUNCTION_FAILED;
        sgx_status_t         sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus       enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        uint32_t             bytesNeeded     = 0;
        EnclaveHelpers       enclaveHelpers;
        std::vector<uint8_t> destBuffer;

        do
        {
            if (!pin)
            {
                sgxStatus = sealData(enclaveHelpers.getSgxEnclaveId(),
                                     reinterpret_cast<int32_t*>(&enclaveStatus),
                                     reinterpret_cast<uint8_t*>(&input.at(0)),
                                     input.size(),
                                     nullptr,
                                     destBuffer.size(),
                                     &bytesNeeded);
            }
            else
            {
                sgxStatus = sealPin(enclaveHelpers.getSgxEnclaveId(),
                                    reinterpret_cast<int32_t*>(&enclaveStatus),
                                    reinterpret_cast<uint8_t*>(&input.at(0)),
                                    input.size(),
                                    nullptr,
                                    destBuffer.size(),
                                    &bytesNeeded);
            }

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                break;
            }

            destBuffer.resize(bytesNeeded);

            if (!pin)
            {
                sgxStatus = sealData(enclaveHelpers.getSgxEnclaveId(),
                                     reinterpret_cast<int32_t*>(&enclaveStatus),
                                     reinterpret_cast<uint8_t*>(&input.at(0)),
                                     input.size(),
                                     destBuffer.data(),
                                     destBuffer.size(),
                                     &bytesNeeded);
            }
            else
            {
                sgxStatus = sealPin(enclaveHelpers.getSgxEnclaveId(),
                                    reinterpret_cast<int32_t*>(&enclaveStatus),
                                    reinterpret_cast<uint8_t*>(&input.at(0)),
                                    input.size(),
                                    destBuffer.data(),
                                    destBuffer.size(),
                                    &bytesNeeded);
            }

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            populateStringFromVector(destBuffer, sealedOutput);

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    bool getDataFromTokenFile(const CK_SLOT_ID&  slotID,
                              std::string&       sealedString,
                              const std::string& keyword)
    {
        bool          result       = false;
        bool          keywordFound = false;
        bool          endOfFile    = false;
        std::string   line;
        std::string   tokenFileName(tokenPath + "slot" + std::to_string(slotID) + ".token");
        std::ifstream fileHandle;

        do
        {
            fileHandle.open(tokenFileName, std::ios::binary);
            if (!fileHandle.good())
            {
                break;
            }

            while(!keywordFound)
            {
                getline(fileHandle, line);

                if (line.find(keyword) != std::string::npos)
                {
                    keywordFound = true;

                    getline(fileHandle, line);
                    while(line.find(separator) == std::string::npos)
                    {
                        sealedString += line;

                        getline(fileHandle, line);

                        if (line.find(separator) == std::string::npos)
                        {
                            sealedString.append("\n");
                        }
                    }
                }

                if (fileHandle.eof())
                {
                    endOfFile = true;
                    break;
                }
            }

            if (!endOfFile)
            {
                result = true;
            }

        } while(false);

        if (fileHandle.good())
        {
            fileHandle.close();
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getUpdatedSessionCount(std::string&   sessionCount,
                                 std::string&   updatedSessionCount,
                                 UpdateSession& flag)
    {
        CK_RV                rv              = CKR_FUNCTION_FAILED;
        sgx_status_t         sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus       enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        uint32_t             bytesNeeded     = 0;
        EnclaveHelpers       enclaveHelpers;
        std::vector<uint8_t> destBuffer;

        do
        {
            sgxStatus = updateSessionCount(enclaveHelpers.getSgxEnclaveId(),
                                           reinterpret_cast<int32_t*>(&enclaveStatus),
                                           reinterpret_cast<uint8_t*>(&sessionCount.at(0)),
                                           sessionCount.size(),
                                           nullptr,
                                           destBuffer.size(),
                                           &bytesNeeded,
                                           static_cast<uint8_t>(flag));

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                break;
            }

            destBuffer.resize(bytesNeeded);

            sgxStatus = updateSessionCount(enclaveHelpers.getSgxEnclaveId(),
                                           reinterpret_cast<int32_t*>(&enclaveStatus),
                                           reinterpret_cast<uint8_t*>(&sessionCount.at(0)),
                                           sessionCount.size(),
                                           destBuffer.data(),
                                           destBuffer.size(),
                                           &bytesNeeded,
                                           static_cast<uint8_t>(flag));

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            populateStringFromVector(destBuffer, updatedSessionCount);

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV updateSealedString(const CK_SLOT_ID&  slotID,
                             const std::string& sealedString,
                             const std::string& keyword)
    {
        CK_RV           rv = CKR_GENERAL_ERROR;
        std::string     tokenFileName(tokenPath + "slot" + std::to_string(slotID) + ".token");
        std::string     tempTokenFileName = tokenFileName + "temp";
        std::string     line;
        std::ifstream   fileHandle;
        std::ofstream   tempFileHandle;

        do
        {
            fileHandle.open(tokenFileName, std::ifstream::binary);
            tempFileHandle.open(tempTokenFileName, std::ofstream::out | std::ofstream::binary);

            if (!fileHandle.good() ||
                !tempFileHandle.good())
            {
                break;
            }

            while(getline(fileHandle, line))
            {
                if (line.find(keyword) != std::string::npos)
                {
                    tempFileHandle << keyword << std::endl;
                    tempFileHandle << sealedString << std::endl;

                    getline(fileHandle, line);
                    while(line.find(separator) == std::string::npos)
                    {
                        getline(fileHandle, line);
                    }

                    tempFileHandle << separator << std::endl;
                }
                else
                {
                    tempFileHandle << line << std::endl;
                    continue;
                }
            }

            fileHandle.close();
            tempFileHandle.close();

            remove(tokenFileName.c_str());
            rename(tempTokenFileName.c_str(), tokenFileName.c_str());

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    bool isLoggedIn(const CK_SLOT_ID& slotID, const std::string& keyword)
    {
        CK_RV          rv              = 0x00000001UL;
        bool           result          = false;
        sgx_status_t   sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        EnclaveHelpers enclaveHelpers;
        std::string    sealedPin;

        do
        {
            result = getDataFromTokenFile(slotID, sealedPin, keyword);
            if (!result)
            {
                break;
            }

            sgxStatus = checkLoginStatus(enclaveHelpers.getSgxEnclaveId(),
                                         reinterpret_cast<int32_t*>(&enclaveStatus),
                                         reinterpret_cast<uint8_t*>(&sealedPin.at(0)),
                                         sealedPin.size());

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }
        } while(false);

        if (CKR_LOGGED_IN == rv)
        {
            result = true;
        }
        else
        {
            result = false;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool isSOUserLoggedIn(const CK_SLOT_ID& slotID)
    {
        return isLoggedIn(slotID, soLoginKeyword);
    }

    //---------------------------------------------------------------------------------------------
    bool isUserLoggedIn(const CK_SLOT_ID& slotID)
    {
        return isLoggedIn(slotID, userLoginKeyword);
    }

    //---------------------------------------------------------------------------------------------
    CK_RV isPinValid(const CK_SLOT_ID& slotID, std::string oldPin, const std::string& keyword)
    {
        CK_RV          rv              = CKR_FUNCTION_FAILED;
        bool           result          = false;
        sgx_status_t   sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        EnclaveHelpers enclaveHelpers;
        std::string    sealedPin;

        do
        {
            result = getDataFromTokenFile(slotID, sealedPin, keyword);
            if (!result)
            {
                rv = CKR_USER_PIN_NOT_INITIALIZED;
                break;
            }

            sgxStatus = validatePin(enclaveHelpers.getSgxEnclaveId(),
                                    reinterpret_cast<int32_t*>(&enclaveStatus),
                                    reinterpret_cast<uint8_t*>(&oldPin.at(0)),
                                    oldPin.size(),
                                    reinterpret_cast<uint8_t*>(&sealedPin.at(0)),
                                    sealedPin.size());

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV setPin(const CK_SLOT_ID&  slotID,
                 const std::string& keyword,
                 CK_UTF8CHAR_PTR    oldPin,
                 const CK_ULONG&    oldPinLen,
                 CK_UTF8CHAR_PTR    newPin,
                 const CK_ULONG&    newPinLen)
    {
        CK_RV       rv = CKR_FUNCTION_FAILED;
        std::string sealedPin;

        do
        {
            if (!oldPin || !newPin)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            std::string oldUserPin((const char*)oldPin, oldPinLen);
            std::string newUserPin((const char*)newPin, newPinLen);

            if (!getDataFromTokenFile(slotID, sealedPin, keyword))
            {
                rv = CKR_USER_PIN_NOT_INITIALIZED;
                break;
            }

            rv = isPinValid(slotID, oldUserPin, keyword);
            if (CKR_OK != rv)
            {
                rv = CKR_PIN_INCORRECT;
                break;
            }

            rv = sealString(newUserPin, sealedPin, true);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = updateSealedString(slotID, sealedPin, keyword);

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV sessionExists(const CK_SLOT_ID& slotID)
    {
        CK_RV          rv              = CKR_FUNCTION_FAILED;
        bool           result          = false;
        sgx_status_t   sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        EnclaveHelpers enclaveHelpers;
        std::string    sealedSessionCount;

        do
        {
            result = getDataFromTokenFile(slotID, sealedSessionCount, sessionCountKeyword);
            if (!result)
            {
                break;
            }

            sgxStatus = checkSessionExistence(enclaveHelpers.getSgxEnclaveId(),
                                              reinterpret_cast<int32_t*>(&enclaveStatus),
                                              reinterpret_cast<uint8_t*>(&sealedSessionCount.at(0)),
                                              sealedSessionCount.size());

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getUpdatedLoginStatus(std::string& loginStatus,
                                std::string& updatedLoginStatus)
    {
        CK_RV                rv              = CKR_FUNCTION_FAILED;
        sgx_status_t         sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
        SgxCryptStatus       enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        uint32_t             bytesNeeded     = 0;
        EnclaveHelpers       enclaveHelpers;
        std::vector<uint8_t> destBuffer;

        do
        {
            sgxStatus = updateLoginStatus(enclaveHelpers.getSgxEnclaveId(),
                                          reinterpret_cast<int32_t*>(&enclaveStatus),
                                          reinterpret_cast<uint8_t*>(&loginStatus.at(0)),
                                          loginStatus.size(),
                                          nullptr,
                                          destBuffer.size(),
                                          &bytesNeeded);

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            if (CKR_OK != rv)
            {
                break;
            }

            destBuffer.resize(bytesNeeded);

            sgxStatus = updateLoginStatus(enclaveHelpers.getSgxEnclaveId(),
                                          reinterpret_cast<int32_t*>(&enclaveStatus),
                                          reinterpret_cast<uint8_t*>(&loginStatus.at(0)),
                                          loginStatus.size(),
                                          destBuffer.data(),
                                          destBuffer.size(),
                                          &bytesNeeded);

            if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
            {
                rv = CKR_POWER_STATE_INVALID;
            }
            else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
            }

            populateStringFromVector(destBuffer, updatedLoginStatus);

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV toggleLoginStatus(const CK_SLOT_ID& slotID, const std::string& keyword)
    {
        CK_RV       rv      = CKR_FUNCTION_FAILED;
        bool        result  = false;
        std::string loginStatus, newLoginStatus;

        do
        {
            result = getDataFromTokenFile(slotID, loginStatus, keyword);
            if (!result)
            {
                break;
            }

            rv = getUpdatedLoginStatus(loginStatus, newLoginStatus);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = updateSealedString(slotID,
                                    newLoginStatus,
                                    keyword);
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    bool isUserPinInitialized(const CK_SLOT_ID& slotID)
    {
        std::string userPin;
        return getDataFromTokenFile(slotID, userPin, userPinKeyword);
    }

    //---------------------------------------------------------------------------------------------
    bool Token::isTokenValid()
    {
        return isValid;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV updateSessionCount(const CK_SLOT_ID& slotID, UpdateSession& flag)
    {
        CK_RV           rv      = CKR_FUNCTION_FAILED;
        bool            result  = false;
        std::string     sessionCount, updatedSessionCount;

        do
        {
            result = getDataFromTokenFile(slotID, sessionCount, sessionCountKeyword);
            if (!result)
            {
                break;
            }

            rv = getUpdatedSessionCount(sessionCount, updatedSessionCount, flag);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = updateSealedString(slotID,
                                    updatedSessionCount,
                                    sessionCountKeyword);
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::addSession()
    {
        UpdateSession sessionFlag = UpdateSession::OPEN;
        return updateSessionCount(slotID, sessionFlag);
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::removeSession()
    {
        UpdateSession sessionFlag = UpdateSession::CLOSE;
        return updateSessionCount(slotID, sessionFlag);
    }

    //---------------------------------------------------------------------------------------------
    bool populateTokenFile(std::ofstream&     fileHandle,
                           const CK_SLOT_ID&  slotID,
                           const std::string& sealedSoPin,
                           const std::string& sealedLabel,
                           const std::string& sealedSessionCount,
                           const std::string& sealedLoginStatus)
    {
        bool result = false;

        do
        {
            if (!fileHandle.good())
            {
                break;
            }

            fileHandle << separator << std::endl;

            fileHandle << slotKeyword << std::endl;
            fileHandle << slotID      << std::endl;

            fileHandle << separator    << std::endl;
            fileHandle << soPinKeyword << std::endl;
            fileHandle.write(&sealedSoPin.at(0), sealedSoPin.size());
            fileHandle << std::endl;

            fileHandle << separator    << std::endl;
            fileHandle << labelKeyword << std::endl;
            fileHandle.write(&sealedLabel.at(0), sealedLabel.size());
            fileHandle << std::endl;

            fileHandle << separator           << std::endl;
            fileHandle << sessionCountKeyword << std::endl;
            fileHandle.write(&sealedSessionCount.at(0), sealedSessionCount.size());
            fileHandle << std::endl;

            fileHandle << separator       << std::endl;
            fileHandle << soLoginKeyword  << std::endl;
            fileHandle.write(&sealedLoginStatus.at(0), sealedLoginStatus.size());
            fileHandle << std::endl;

            fileHandle << separator        << std::endl;
            fileHandle << userLoginKeyword << std::endl;
            fileHandle.write(&sealedLoginStatus.at(0), sealedLoginStatus.size());
            fileHandle << std::endl;

            fileHandle << separator << std::endl;

            result = true;
        }while(false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::initToken(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength, CK_UTF8CHAR_PTR label)
    {
        CK_RV           rv                 = CKR_FUNCTION_FAILED;
        bool            result             = false;
        std::string     loginStatus        = "FALSE";
        std::string     sessionCountString = "0";
        std::string     sealedUserPin      = "";
        bool            userPinInitialized = false;
        EnclaveHelpers  enclaveHelpers;
        std::string     sealedSoPin, sealedSessionCount, sealedLoginStatus;

        do
        {
            if (!pin   ||
                !label ||
                strnlen(reinterpret_cast<const char*>(label), 32) != 32)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            std::string tokenFileName(tokenPath + "slot" + std::to_string(slotID) + ".token");
            std::string soPin((const char*)pin, pinLength);
            std::string labelString((const char*)label, 32);
            bool        tokenFilePresent = isTokenFilePresent(slotID);

            // If token file is present, check for validity of SO pin and session count.
            if (tokenFilePresent)
            {
                rv = isPinValid(slotID, soPin, soPinKeyword);
                if (CKR_OK != rv)
                {
                    rv = CKR_PIN_INCORRECT;
                    break;
                }

                rv = sessionExists(slotID);
                if (CKR_SESSION_EXISTS == rv ||
                    CKR_OK             != rv)
                {
                    break;
                }

                userPinInitialized = getDataFromTokenFile(slotID, sealedUserPin, userPinKeyword);
            }

            rv = sealString(soPin, sealedSoPin, true);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = sealString(sessionCountString, sealedSessionCount);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = sealString(loginStatus, sealedLoginStatus);
            if (CKR_OK != rv)
            {
                break;
            }

            if (tokenFilePresent)
            {
                remove(tokenFileName.c_str());
            }

            std::ofstream fileHandle;
            fileHandle.open(tokenFileName, std::ios::binary);

            if (!fileHandle.good())
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            result = populateTokenFile(fileHandle,
                                       slotID,      // Slot ID can be saved without sealing, since it isn't a secret.
                                       sealedSoPin,
                                       labelString, // Label can be saved without sealing, since it isn't a secret.
                                       sealedSessionCount,
                                       sealedLoginStatus);
            if (!result)
            {
                fileHandle.close();
                rv = CKR_GENERAL_ERROR;
                break;
            }

            if (userPinInitialized)
            {
                fileHandle << userPinKeyword << std::endl;
                fileHandle.write(&sealedUserPin.at(0), sealedUserPin.size());
                fileHandle << std::endl << separator << std::endl;
            }

            fileHandle.close();

            rv = CKR_OK;

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::getTokenInfo(CK_TOKEN_INFO_PTR tokenInfo)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            if (!tokenInfo)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            tokenInfo->flags = 0;

            std::string userPin;
            std::string tokenLabel;

            memset(tokenInfo->label, ' ', 32);

            if (isTokenFilePresent(slotID))
            {
                tokenInfo->flags |= CKF_TOKEN_INITIALIZED;

                if (getDataFromTokenFile(slotID, userPin, userPinKeyword))
                {
                    tokenInfo->flags |= CKF_USER_PIN_INITIALIZED;
                }

                if (getDataFromTokenFile(slotID, tokenLabel, labelKeyword))
                {
                    size_t labelSize = tokenLabel.size();
                    if (labelSize <= 32)    // Size limit Check: tokenInfo->label is 32 bytes.
                    {
                        memcpy(tokenInfo->label, tokenLabel.data(), labelSize);
                    }
                }
            }

            tokenInfo->flags |= CKF_DUAL_CRYPTO_OPERATIONS;
            tokenInfo->flags |= CKF_LOGIN_REQUIRED;

            memset(tokenInfo->manufacturerID, ' ', 32);
            memcpy(tokenInfo->manufacturerID, "Crypto API Toolkit", 18);

            memset(tokenInfo->model, ' ', 16);

            memset(tokenInfo->serialNumber, ' ', 16);

            tokenInfo->ulMaxSessionCount   = maxSessionCount;
            tokenInfo->ulSessionCount      = CK_UNAVAILABLE_INFORMATION;
            tokenInfo->ulMaxRwSessionCount = maxSessionCount;
            tokenInfo->ulRwSessionCount    = CK_UNAVAILABLE_INFORMATION;

            tokenInfo->ulMaxPinLen = minPinLength;
            tokenInfo->ulMinPinLen = maxPinLength;

            tokenInfo->ulTotalPublicMemory  = CK_UNAVAILABLE_INFORMATION;
            tokenInfo->ulFreePublicMemory   = CK_UNAVAILABLE_INFORMATION;
            tokenInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
            tokenInfo->ulFreePrivateMemory  = CK_UNAVAILABLE_INFORMATION;

            tokenInfo->hardwareVersion.major = 0;
            tokenInfo->hardwareVersion.minor = 0;
            tokenInfo->firmwareVersion.major = 0;
            tokenInfo->firmwareVersion.minor = 0;

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::loginSO(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength)
    {
        CK_RV       rv     = CKR_FUNCTION_FAILED;
        bool        result = false;
        std::string sealedPin;

        do
        {
            if (!pin)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            if (isUserLoggedIn(slotID))
            {
                rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                break;
            }

            if (isSOUserLoggedIn(slotID))
            {
                rv = CKR_USER_ALREADY_LOGGED_IN;
                break;
            }

            result = getDataFromTokenFile(slotID, sealedPin, soPinKeyword);
            if (!result)
            {
                rv = CKR_USER_PIN_NOT_INITIALIZED;
                break;
            }

            std::string soPin((const char*)pin, pinLength);

            rv = isPinValid(slotID, soPin, soPinKeyword);
            if (CKR_OK != rv)
            {
                rv = CKR_PIN_INCORRECT;
                break;
            }

            rv = toggleLoginStatus(slotID, soLoginKeyword);

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::initUserPin(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength)
    {
        CK_RV         rv = CKR_FUNCTION_FAILED;
        std::string   tokenFileName(tokenPath + "slot" + std::to_string(slotID) + ".token");
        std::string   sealedUserPin;
        std::ofstream fileHandle;

        do
        {
            if (!pin)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            if (isUserPinInitialized(slotID))
            {
                rv = CKR_USER_PIN_ALREADY_INITIALIZED;
                break;
            }

            std::string userPin((const char*)pin, pinLength);

            rv = sealString(userPin, sealedUserPin, true);
            if (CKR_OK != rv)
            {
                break;
            }

            fileHandle.open(tokenFileName, std::ios::binary | std::ios::app);

            if (!fileHandle.good())
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            fileHandle << userPinKeyword << std::endl;
            fileHandle.write(&sealedUserPin.at(0), sealedUserPin.size());
            fileHandle << std::endl << separator << std::endl;

            fileHandle.close();

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::setSOPin(CK_UTF8CHAR_PTR  oldPin,
                          const CK_ULONG&  oldPinLen,
                          CK_UTF8CHAR_PTR  newPin,
                          const CK_ULONG&  newPinLen)
    {
        return setPin(slotID,
                      soPinKeyword,
                      oldPin,
                      oldPinLen,
                      newPin,
                      newPinLen);
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::setUserPin(CK_UTF8CHAR_PTR oldPin,
                            const CK_ULONG& oldPinLen,
                            CK_UTF8CHAR_PTR newPin,
                            const CK_ULONG& newPinLen)
    {
        return setPin(slotID,
                      userPinKeyword,
                      oldPin,
                      oldPinLen,
                      newPin,
                      newPinLen);
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::loginUser(CK_UTF8CHAR_PTR pin, const CK_ULONG& pinLength)
    {
        CK_RV       rv     = CKR_FUNCTION_FAILED;
        bool        result = false;
        std::string sealedPin;

        do
        {
            if (!pin)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            if (isUserLoggedIn(slotID))
            {
                rv = CKR_USER_ALREADY_LOGGED_IN;
                break;
            }

            if (isSOUserLoggedIn(slotID))
            {
                rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                break;
            }

            result = getDataFromTokenFile(slotID, sealedPin, userPinKeyword);
            if (!result)
            {
                rv = CKR_USER_PIN_NOT_INITIALIZED;
                break;
            }

            std::string userPin((const char*)pin, pinLength);

            rv = isPinValid(slotID, userPin, userPinKeyword);
            if (CKR_OK != rv)
            {
                rv = CKR_PIN_INCORRECT;
                break;
            }

            rv = toggleLoginStatus(slotID, userLoginKeyword);

            rv = CKR_OK;
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::logOut()
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            if (isSOUserLoggedIn(slotID))
            {
                rv = toggleLoginStatus(slotID, soLoginKeyword);
            }
            else if (isUserLoggedIn(slotID))
            {
                rv = toggleLoginStatus(slotID, userLoginKeyword);
            }
            else
            {
                rv = CKR_USER_NOT_LOGGED_IN;
                break;
            }
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    /* This function sets the session count to 0.*/
    CK_RV finalizeTokenFile(const CK_SLOT_ID& slotID)
    {
        CK_RV         rv           = CKR_FUNCTION_FAILED;
        std::string   sessionCount = "0";
        std::string   sealedSessionCount;
        std::string   tokenFileName(tokenPath + "slot" + std::to_string(slotID) + ".token");
        std::string   tempTokenFileName = tokenFileName + "temp";
        std::string   line;
        std::ifstream fileHandle;
        std::ofstream tempFileHandle;

        do
        {
            rv = sealString(sessionCount, sealedSessionCount);
            if (CKR_OK != rv)
            {
                break;
            }

            fileHandle.open(tokenFileName, std::ifstream::binary);
            tempFileHandle.open(tempTokenFileName, std::ofstream::out | std::ofstream::binary);

            if (!fileHandle.good() ||
                !tempFileHandle.good())
            {
                break;
            }

            while(getline(fileHandle, line))
            {
                if (line.find(sessionCountKeyword) != std::string::npos) // Updating sessionCount.
                {
                    tempFileHandle << sessionCountKeyword << std::endl;
                    tempFileHandle << sealedSessionCount << std::endl;

                    getline(fileHandle, line);
                    while(line.find(separator) == std::string::npos)
                    {
                        getline(fileHandle, line);
                    }

                    tempFileHandle << separator << std::endl;
                }
                else
                {
                    tempFileHandle << line << std::endl;
                    continue;
                }
            }

            fileHandle.close();
            tempFileHandle.close();

            remove(tokenFileName.c_str());
            rename(tempTokenFileName.c_str(), tokenFileName.c_str());

            rv = CKR_OK;

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV Token::finalize()
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            rv = logOut();
            if (CKR_OK                 != rv &&
                CKR_USER_NOT_LOGGED_IN != rv)
            {
                break;
            }

            rv = finalizeTokenFile(slotID);
            if (CKR_OK != rv)
            {
                break;
            }

        } while(false);

        return rv;
    }
}