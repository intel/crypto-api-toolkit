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

#include "TokenObjectParser.h"

namespace Utils
{
    namespace TokenObjectParser
    {
        static const size_t ulongSize = sizeof(uint64_t);

        //-------------------------------------------------------------------------------------------------------------
        uint64_t getSlotId(const uint64_t* attributeBuffer, const uint32_t& attributeBufferLen)
        {
            uint64_t slotId = (maxSlotsSupported + 1);

            if (attributeBufferLen < ulongSize)
            {
                return slotId;
            }

            memcpy_s(&slotId, ulongSize, attributeBuffer, ulongSize);

            return slotId;
        }

        /**********************************************************************************
         *
         * Buffer written into file : pinMaterial || KeyBufferLen || attributeBufferLen ||
         * attributeBuffer || keyBuffer || usedForWrapping || pairKeyId
         *
         * First 32 bits will be pinMaterial.
         * Next sizeof(uint64_t) bytes will be keyBufferLen.
         * Next sizeof(uint64_t) bytes will be attributeBufferLen.
         *
         * *******************************************************************************/
        //-------------------------------------------------------------------------------------------------------------
        bool writeTokenObject(const std::string&           fileName,
                              const CryptoSgx::ByteBuffer& pinMaterial,
                              const uint64_t*              attributeBuffer,
                              const uint64_t&              attributeBufferLen,
                              const uint8_t*               keyBuffer,
                              const uint64_t&              keyBufferLen,
                              const bool&                  usedForWrapping,
                              const uint64_t&              pairKeyId,
                              std::string*                 filePath)
        {
            if (!attributeBuffer || !keyBuffer || !filePath || fileName.empty())
            {
                return false;
            }

            bool result  = false;

            do
            {
                if (pinMaterial.size() != static_cast<size_t>(HashDigestLength::sha256))
                {
                    break;
                }

                uint64_t slotId = getSlotId(attributeBuffer, attributeBufferLen);
                if ((1 + maxSlotsSupported) == slotId)
                {
                    break;
                }

                *filePath = Utils::SgxFileUtils::getTokenObjectPath(slotId) + fileName;
                std::string mode = "w";

                // Remove the token object file if present already.
                Utils::SgxFileUtils::remove(*filePath);

                SGX_FILE* sgxFile = Utils::SgxFileUtils::open(*filePath, mode);
                if (!sgxFile)
                {
                    break;
                }

                // Write pinMaterial into token object file.
                if (!Utils::SgxFileUtils::write(pinMaterial.get(), pinMaterial.size(), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write size of key into token object file.
                if (!Utils::SgxFileUtils::write(&keyBufferLen, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write attributeBuffer length into token object file.
                if (!Utils::SgxFileUtils::write(&attributeBufferLen, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write attribute buffer into token object file.
                if (!Utils::SgxFileUtils::write(attributeBuffer, attributeBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write the key buffer into token object file.
                if (!Utils::SgxFileUtils::write(keyBuffer, keyBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write used for wrapping status into token object file.
                if (!Utils::SgxFileUtils::write(&usedForWrapping, sizeof(bool), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write pair key id into token object file.
                if (!Utils::SgxFileUtils::write(&pairKeyId, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                Utils::SgxFileUtils::close(sgxFile);

                result = true;
            } while(false);

            if (!result)
            {
                Utils::SgxFileUtils::remove(*filePath);
            }

            return result;
        }

        //-------------------------------------------------------------------------------------------------------------
        bool readTokenObject(const std::string&           filePath,
                             const CryptoSgx::ByteBuffer& pinMaterial,
                             uint64_t*                    attributeBuffer,
                             uint64_t                     attributeBufferLen,
                             uint64_t*                    attributeBufferLenRequired,
                             uint8_t*                     keyBuffer,
                             uint64_t                     keyBufferLen,
                             uint64_t*                    keyBufferLenRequired,
                             bool*                        usedForWrapping,
                             uint64_t*                    pairKeyId,
                             bool                         bufferLenRequest)
        {
            size_t pinMaterialSize = static_cast<size_t>(HashDigestLength::sha256);

            if (!attributeBufferLenRequired ||
                !keyBufferLenRequired       ||
                !usedForWrapping            ||
                !pairKeyId                  ||
                pinMaterial.size() != pinMaterialSize)
            {
                return false;
            }

            bool result = false;

            do
            {
                std::string mode = "r";
                SGX_FILE* sgxFile = Utils::SgxFileUtils::open(filePath, mode);
                if (!sgxFile)
                {
                    break;
                }

                CryptoSgx::ByteBuffer pinMaterialInFile(pinMaterialSize);

                if (!Utils::SgxFileUtils::read(pinMaterialInFile.get(), pinMaterialSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Validate pin material present in token file.
                if (pinMaterialInFile.toString() != pinMaterial.toString())
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    result = false;
                    break;
                }

                if (!Utils::SgxFileUtils::read(keyBufferLenRequired, ulongSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                if (!Utils::SgxFileUtils::read(attributeBufferLenRequired, ulongSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Break if it's a size request.
                if (bufferLenRequest)
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    result = true;
                    break;
                }

                if (!attributeBuffer    || !attributeBufferLen         ||
                    (attributeBufferLen < *attributeBufferLenRequired) ||
                    (keyBufferLen       < *keyBufferLenRequired))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    result = false;
                    break;
                }

                // Read the attributeBuffer.
                if (!Utils::SgxFileUtils::read(attributeBuffer, *attributeBufferLenRequired, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Read keyBuffer.
                if (!Utils::SgxFileUtils::read(keyBuffer, *keyBufferLenRequired, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Read used for wrapping status
                if (!Utils::SgxFileUtils::read(usedForWrapping, sizeof(bool), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Read pairKeyId
                if (!Utils::SgxFileUtils::read(pairKeyId, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                Utils::SgxFileUtils::close(sgxFile);

                result = true;

            } while(false);

            return result;
        }

        //-------------------------------------------------------------------------------------------------------------
        bool updatePinMaterial(const std::string&           filePath,
                               const CryptoSgx::ByteBuffer& pinMaterial)
        {
            bool result = false;

            do
            {
                size_t pinMaterialSize = static_cast<size_t>(HashDigestLength::sha256);

                if (filePath.empty() ||
                    (pinMaterial.size() != pinMaterialSize))
                {
                    return false;
                }

                uint64_t keyBufferLen = 0;
                uint64_t attributeBufferLen = 0;

                std::string mode = "r";

                SGX_FILE* sgxFile = Utils::SgxFileUtils::open(filePath, mode);
                if (!sgxFile)
                {
                    break;
                }

                if (!Utils::SgxFileUtils::seek(sgxFile, pinMaterialSize, SEEK_CUR))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                if (!Utils::SgxFileUtils::read(&keyBufferLen, ulongSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                if (!Utils::SgxFileUtils::read(&attributeBufferLen, ulongSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                std::vector<uint64_t> keyBuffer;
                std::vector<uint64_t> attributeBuffer;

                keyBuffer.resize(keyBufferLen);
                attributeBuffer.resize(attributeBufferLen);

                // Read the attributeBuffer.
                if (!Utils::SgxFileUtils::read(attributeBuffer.data(), attributeBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Read keyBuffer.
                if (!Utils::SgxFileUtils::read(keyBuffer.data(), keyBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                bool     usedForWrapping = false;
                uint64_t pairKeyId       = 0;

                // Read used for wrapping status
                if (!Utils::SgxFileUtils::read(&usedForWrapping, sizeof(bool), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Read pairKeyId
                if (!Utils::SgxFileUtils::read(&pairKeyId, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                Utils::SgxFileUtils::close(sgxFile);

                Utils::SgxFileUtils::remove(filePath);

                mode = "w";
                sgxFile = Utils::SgxFileUtils::open(filePath, mode);
                if (!sgxFile)
                {
                    break;
                }

                // Write pinMaterial into token object file.
                if (!Utils::SgxFileUtils::write(pinMaterial.get(), pinMaterial.size(), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write size of key into token object file.
                if (!Utils::SgxFileUtils::write(&keyBufferLen, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write attributeBuffer length into token object file.
                if (!Utils::SgxFileUtils::write(&attributeBufferLen, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write attribute buffer into token object file.
                if (!Utils::SgxFileUtils::write(attributeBuffer.data(), attributeBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write the key buffer into token object file.
                if (!Utils::SgxFileUtils::write(keyBuffer.data(), keyBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write used for wrapping status into token object file.
                if (!Utils::SgxFileUtils::write(&usedForWrapping, sizeof(bool), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write pair key id into token object file.
                if (!Utils::SgxFileUtils::write(&pairKeyId, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                Utils::SgxFileUtils::close(sgxFile);

                result = true;

            } while(false);

            return result;
        }

        //-------------------------------------------------------------------------------------------------------------
        bool setWrappingStatus(const std::string& filePath,
                               const uint64_t&    pairKeyId)
        {
            bool result = false;

            do
            {
                if (filePath.empty())
                {
                    return false;
                }

                uint64_t keyBufferLen = 0;
                uint64_t attributeBufferLen = 0;

                std::string mode = "r";

                SGX_FILE* sgxFile = Utils::SgxFileUtils::open(filePath, mode);
                if (!sgxFile)
                {
                    break;
                }

                std::vector<uint64_t> pinMaterial;
                size_t                pinMaterialSize = static_cast<size_t>(HashDigestLength::sha256);

                pinMaterial.resize(pinMaterialSize);

                if (!Utils::SgxFileUtils::read(pinMaterial.data(), pinMaterialSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                if (!Utils::SgxFileUtils::read(&keyBufferLen, ulongSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                if (!Utils::SgxFileUtils::read(&attributeBufferLen, ulongSize, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                std::vector<uint64_t> keyBuffer;
                std::vector<uint64_t> attributeBuffer;

                keyBuffer.resize(keyBufferLen);
                attributeBuffer.resize(attributeBufferLen);

                // Read the attributeBuffer.
                if (!Utils::SgxFileUtils::read(attributeBuffer.data(), attributeBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Read keyBuffer.
                if (!Utils::SgxFileUtils::read(keyBuffer.data(), keyBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                Utils::SgxFileUtils::close(sgxFile);

                Utils::SgxFileUtils::remove(filePath);

                mode = "w";
                sgxFile = Utils::SgxFileUtils::open(filePath, mode);
                if (!sgxFile)
                {
                    break;
                }

                // Write pinMaterial into token object file.
                if (!Utils::SgxFileUtils::write(pinMaterial.data(), pinMaterial.size(), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write size of key into token object file.
                if (!Utils::SgxFileUtils::write(&keyBufferLen, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write attributeBuffer length into token object file.
                if (!Utils::SgxFileUtils::write(&attributeBufferLen, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write attribute buffer into token object file.
                if (!Utils::SgxFileUtils::write(attributeBuffer.data(), attributeBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write the key buffer into token object file.
                if (!Utils::SgxFileUtils::write(keyBuffer.data(), keyBufferLen, 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                bool usedForWrapping = true;

                // Write used for wrapping status into token object file.
                if (!Utils::SgxFileUtils::write(&usedForWrapping, sizeof(bool), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                // Write pair key id into token object file.
                if (!Utils::SgxFileUtils::write(&pairKeyId, sizeof(uint64_t), 1, sgxFile))
                {
                    Utils::SgxFileUtils::close(sgxFile);
                    break;
                }

                Utils::SgxFileUtils::close(sgxFile);

                result = true;

            } while(false);

            return result;
        }
    }
}