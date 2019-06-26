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

#include "TokenUtils.h"

namespace Utils
{
    namespace TokenUtils
    {
        //---------------------------------------------------------------------------------------------
        static uint32_t getUint32(const TLV& tlvData)
        {
            uint32_t value = 0;
            std::stringstream sstr;
            sstr.write(reinterpret_cast<const char*>(tlvData.value.data()), tlvData.length);
            sstr.read(reinterpret_cast<char*>(&value), tlvData.length);

            return value;
        }

        //---------------------------------------------------------------------------------------------
        static std::string getString(const TLV& tlvData)
        {
            return tlvData.value;
        }

        //---------------------------------------------------------------------------------------------
        static std::stringstream putUint32(const uint32_t& tag, const uint32_t& data)
        {
            std::stringstream sstr;
            TagLength tl;
            tl.tag = tag;
            tl.length = sizeof(data);

            sstr.write(reinterpret_cast<char*>(&tl), sizeof(tl));
            sstr.write(reinterpret_cast<const char*>(&data), sizeof(data));

            return sstr;
        }

        //---------------------------------------------------------------------------------------------
        static std::stringstream putString(const uint32_t& tag, const std::string& data)
        {
            TagLength tl;
            tl.tag = tag;
            tl.length = data.length();
            std::stringstream sstr;
            sstr.write(reinterpret_cast<char*>(&tl), sizeof(tl));
            sstr.write(data.data(), data.length());

            return sstr;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV validatePin(const std::string& sealedPin, const std::string& pinEntered)
        {
            CK_RV          rv            = CKR_FUNCTION_FAILED;
            sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
            SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
            P11Crypto::EnclaveHelpers enclaveHelpers;

            do
            {
                if (sealedPin.empty())
                {
                    rv = CKR_USER_PIN_NOT_INITIALIZED;
                    break;
                }

                sgxStatus = ::validatePin(enclaveHelpers.getSgxEnclaveId(),
                                          reinterpret_cast<int32_t*>(&enclaveStatus),
                                          const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&pinEntered.at(0))),
                                          pinEntered.size(),
                                          const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&sealedPin.at(0))),
                                          sealedPin.size());

                rv = Utils::EnclaveUtils::getPkcsStatus(sgxStatus, enclaveStatus);
            } while(false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV setPin(const std::string& tokenFile,
                     const uint32_t&    tag,
                     const std::string& oldPin,
                     const std::string& newPin,
                     const std::string& sealedOldPin)
        {
            CK_RV       rv = CKR_FUNCTION_FAILED;
            std::string sealedNewPin;

            do
            {
                rv = validatePin(sealedOldPin, oldPin);
                if (CKR_OK != rv)
                {
                    rv = CKR_PIN_INCORRECT;
                    break;
                }

                bool sealPin = true;
                sealedNewPin = Utils::EnclaveUtils::sealDataBlob(newPin, sealPin);
                if (sealedNewPin.empty())
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                if (!updateTokenFileDataField(tokenFile, tag, sealedNewPin))
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                rv = CKR_OK;
            } while(false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        TokenData loadTokenData(const std::string& fileName)
        {
            std::stringstream sstr = FileUtils::readData(fileName);
            TokenData tokenData{};

            if (!sstr.str().empty())
            {
                std::vector<TLV> tlvData;
                tlvData.clear();

                while (!sstr.eof())
                {
                    TLV tlv;
                    sstr.read(reinterpret_cast<char*>(&tlv.tag), sizeof(tlv.tag));
                    sstr.read(reinterpret_cast<char*>(&tlv.length), sizeof(tlv.length));
                    tlv.value.resize(tlv.length);
                    sstr.read(reinterpret_cast<char*>(&tlv.value[0]), tlv.length);
                    tlvData.push_back(tlv);
                    tlv.clear();
                }

                for (int i = 0; i < tlvData.size(); ++i)
                {
                    switch (tlvData[i].tag)
                    {
                        case tagSlotId:
                            tokenData.slotId = getUint32(tlvData[i]);
                            break;
                        case tagLabel:
                            tokenData.label = getString(tlvData[i]);
                            break;
                        case tagSOPIN:
                            tokenData.soPin = getString(tlvData[i]);
                            break;
                        case tagUserPIN:
                            tokenData.userPin = getString(tlvData[i]);
                            break;
                        default:
                            break;
                    }
                }
            }

            return tokenData;
        }

        //---------------------------------------------------------------------------------------------
        bool writeToken(const std::string& fileName, const TokenData& tokenData)
        {
            std::stringstream sstr;
            bool result = false;

            //write
            sstr << putString(tagLabel, tokenData.label).rdbuf();

            //write slotId
            sstr << putUint32(tagSlotId, tokenData.slotId).rdbuf();

            //write
            sstr << putString(tagSOPIN, tokenData.soPin).rdbuf();

            // write
            sstr << putString(tagUserPIN, tokenData.userPin).rdbuf();

            result = FileUtils::writeData(fileName, sstr);

            return result;
        }

        //---------------------------------------------------------------------------------------------
        bool updateTokenFileDataField(const std::string& fileName, const uint32_t& tag, const uint32_t& data)
        {
            TokenData tokenData = loadTokenData(fileName);
            switch (tag)
            {
                case tagSlotId:
                    tokenData.slotId = data;
                    break;
                default:
                    return false;
            }

            return updateTokenFileData(fileName, tag, tokenData);
        }

        //---------------------------------------------------------------------------------------------
        bool updateTokenFileDataField(const std::string& fileName, const uint32_t& tag, const std::string& data)
        {
            TokenData tokenData = loadTokenData(fileName);
            std::string updatedSessionCount;

            switch (tag)
            {
                case tagLabel:
                    tokenData.label = data;
                    break;
                case tagSOPIN:
                    tokenData.soPin = data;
                    break;
                case tagUserPIN:
                    tokenData.userPin = data;
                    break;
                default:
                    return false;
            }

            return updateTokenFileData(fileName, tag, tokenData);
        }

        //---------------------------------------------------------------------------------------------
        bool updateTokenFileData(const std::string& fileName, const uint32_t& tag, const TokenData& inTokenData)
        {
            bool updateRequired = true;
            std::stringstream sstr;
            TokenData tokenData = loadTokenData(fileName);

            switch (tag)
            {
                case tagSlotId:
                    tokenData.slotId = inTokenData.slotId;
                    break;
                case tagLabel:
                    tokenData.label = inTokenData.label;
                    break;
                case tagSOPIN:
                    tokenData.soPin = inTokenData.soPin;
                    break;
                case tagUserPIN:
                    tokenData.userPin = inTokenData.userPin;
                    break;
                default:
                    updateRequired = false;
                    break;
            }

            if (!updateRequired)
            {
                return false;
            }

            return writeToken(fileName, tokenData);
        }
    }
}
