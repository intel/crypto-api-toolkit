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

#include "FileUtils.h"

namespace Utils
{
    namespace FileUtils
    {
        //-------------------------------------------------------------------------------------------------------------
        bool isValid(const std::string& fileName)
        {
            struct stat buffer;

            return (stat(fileName.c_str(), &buffer) == 0);
        }

        //-------------------------------------------------------------------------------------------------------------
        void deleteFile(const std::string& fileName)
        {
            remove(fileName.c_str());
        }

        //-------------------------------------------------------------------------------------------------------------
        bool writeData(const std::string& fileName, const std::stringstream& data)
        {
            std::ofstream fileHandle(fileName, std::ios::binary);

            if (!fileHandle.is_open())
            {
                return false;
            }

            fileHandle << data.rdbuf();
            fileHandle.close();

            return true;
        }

        //-------------------------------------------------------------------------------------------------------------
        std::stringstream readData(const std::string& fileName)
        {
            std::ifstream fileHandle(fileName, std::ios::binary);
            std::stringstream sstr;

            if (fileHandle.is_open())
            {
                fileHandle >> sstr.rdbuf();
            }

            fileHandle.close();

            return sstr;
        }
    }
}