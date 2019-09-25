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

#include "SgxFileUtils.h"
#include <errno.h>
#include <sgx_error.h>

namespace Utils
{
    namespace SgxFileUtils
    {
        //-------------------------------------------------------------------------------------------------------------
        std::string getTokenObjectPath(const uint64_t& slotId)
        {
            return tokenPath + "slot" + std::to_string(slotId) + "/.tokenObjects/";
        }

        //-------------------------------------------------------------------------------------------------------------
        SGX_FILE* open(const std::string& filePath, const std::string& mode)
        {
            return sgx_fopen_auto_key(filePath.c_str(), mode.c_str());
        }

        //-------------------------------------------------------------------------------------------------------------
        bool write(const void* ptr, const size_t& size, const size_t& count, SGX_FILE* sgxFile)
        {
            if (!ptr || !sgxFile)
            {
                return false;
            }

            size_t blocksWritten = sgx_fwrite(ptr, size, count, sgxFile);
            if (blocksWritten != count)
            {
                return false;
            }

            return true;
        }

        //-------------------------------------------------------------------------------------------------------------
        bool read(void* ptr, const size_t& size, const size_t& count, SGX_FILE* sgxFile)
        {
            if (!ptr || !sgxFile)
            {
                return false;
            }

            size_t blocksRead = sgx_fread(ptr, size, count, sgxFile);
            if (blocksRead != count)
            {
                return false;
            }

            return true;
        }

        //-------------------------------------------------------------------------------------------------------------
        bool close(SGX_FILE* sgxFile)
        {
            if (!sgxFile)
            {
                return false;
            }

            return !sgx_fclose(sgxFile);
        }

        //-------------------------------------------------------------------------------------------------------------
        bool remove(const std::string& filePath)
        {
            return !sgx_remove(filePath.c_str());
        }

        //-------------------------------------------------------------------------------------------------------------
        bool seek(SGX_FILE* sgxFile, int64_t offset, int origin)
        {
            if (!sgxFile)
            {
                return false;
            }

            return !sgx_fseek(sgxFile, offset, origin);
        }

        //-------------------------------------------------------------------------------------------------------------
        static bool isProhibitedFilenameCharacter(unsigned int index)
        {
            switch (static_cast<char>(index))
            {
                case '.':
                case '/':
                case '?':
                case '*':
                case '\\':
                case '>':
                case '<':
                case '|':
                case '"':
                case ' ':
                case '%':
                case ':':
                case '!':
                case '`':
                case '&':
                case ';':
                case '\'':
                case '\n':
                case '(':
                case ')':
                    return true;
                    break;
                default:
                    return false;
                    break;
            }

            return false;
        }

        //-------------------------------------------------------------------------------------------------------------
        std::string generateRandomFilename()
        {
            uint8_t randomNum[tokenObjectFileNameLength];
            std::string fileName;

            sgx_status_t status = sgx_read_rand(randomNum, tokenObjectFileNameLength);

            // Printable characters are from 33 to 127
            if (SGX_SUCCESS == status)
            {
                // Initialize with a random character
                static unsigned char lastValidChar = '@';

                for (unsigned int i = 0; i < tokenObjectFileNameLength; i++)
                {
                    if (randomNum[i] > 127)
                    {
                        randomNum[i] -= 128;
                    }

                    if (randomNum[i] < 32)
                    {
                        randomNum[i] += 33;
                    }

                    if (isProhibitedFilenameCharacter(randomNum[i]))
                    {
                        randomNum[i] = lastValidChar;
                    }

                    fileName.push_back(static_cast<unsigned char>(randomNum[i]));

                    lastValidChar = static_cast<char>(randomNum[i]);
                }
            }

            return fileName;
        }
    }
}