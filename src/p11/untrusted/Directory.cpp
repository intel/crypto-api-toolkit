/*
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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

/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 Directory.cpp

 Helper functions for accessing directories.
 *****************************************************************************/

#include "config.h"
#include "Directory.h"
#include <string>
#include <vector>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "p11Enclave_u.h"

namespace Directory
{
	// Refresh the directory listing
	size_t refresh(std::string fullPath, char* subDirsBuffer, uint32_t subDirsSize, uint32_t* subDirsBufferSize, char* filesBuffer, uint32_t filesSize, uint32_t* filesBufferSize)
	{
        std::string subDirsString;
        std::string filesString;

		subDirs.clear();
		files.clear();

		if (!subDirsBufferSize || !filesBufferSize)
		{
			return CKR_FUNCTION_FAILED;
		}

        *subDirsBufferSize = 0;
        *filesBufferSize = 0;

		// Enumerate the directory
		DIR* dir = opendir(fullPath.c_str());

		if (dir == NULL)
		{
			return CKR_FUNCTION_FAILED;
		}

		// Enumerate the directory
		struct dirent* entry = NULL;

		while ((entry = readdir(dir)) != NULL)
		{
			bool pushed = false;

			// Check if this is the . or .. entry
			if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			{
				continue;
			}

			// Convert the name of the entry to a C++ string
			std::string name(entry->d_name);

	#if defined(_DIRENT_HAVE_D_TYPE) && defined(_BSD_SOURCE)

			// Determine the type of the entry
			switch(entry->d_type)
			{
			case DT_DIR:
				// This is a directory
				subDirs.push_back(name);
				pushed = true;
				break;
			case DT_REG:
				// This is a regular file
				files.push_back(name);
				pushed = true;
				break;
			default:
				break;
			}
	#endif
			
			if (!pushed) {
				// The entry type has to be determined using lstat
				struct stat entryStatus;

				std::string entryWithFullPath = fullPath + "/" + name;

				int err = lstat(entryWithFullPath.c_str(), &entryStatus);

				if (!err)
				{
					if (S_ISDIR(entryStatus.st_mode))
					{
						//subDirs.push_back(name);
                        subDirsString +=  name + "*";
					}
                    else if (S_ISREG(entryStatus.st_mode))
					{
						//files.push_back(name);
                        filesString += name + "*";
					}
				}
			}
		}

		// Close the directory
		closedir(dir);

		if ((!subDirsBuffer && subDirsString.length()) 	||
			(!filesBuffer && filesString.length())		||
			(subDirsBuffer && (subDirsSize < subDirsString.length())) ||
			(filesBuffer && (filesSize < filesString.length())))
		{
            // Flow to retrieve size required for subDirs and files buffers.
			if (((!subDirsBuffer && subDirsString.length()) ||
				(subDirsBuffer && (subDirsSize < subDirsString.length()))) &&
				subDirsBufferSize)
			{
				*subDirsBufferSize = subDirsString.length();
			}

			if (((!filesBuffer && filesString.length()) ||
				(filesBuffer && (filesSize < filesString.length()))) &&
				filesBufferSize)
			{
				*filesBufferSize = filesString.length();
			}

            if (MAX_TRANSFER_BYTES < (*subDirsBufferSize + *filesBufferSize))
            {
                *subDirsBufferSize = 0;
                *filesBufferSize = 0;

                return CKR_DEVICE_MEMORY;
            }

			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
            // Flow to copy subDirs and files buffers.
            if (MAX_TRANSFER_BYTES < (subDirsSize + filesSize))
            {
                return CKR_DEVICE_MEMORY;
            }

			if (subDirsBuffer && (subDirsSize >= subDirsString.length()))
			{
				if ((subDirsString.length() > 0) && (subDirsSize >= subDirsString.length()))
				{
					*subDirsBufferSize = subDirsString.length();
					memcpy(subDirsBuffer, subDirsString.c_str(), subDirsString.length());
				}
			}

			if (filesBuffer)
			{
				if ((filesString.length()) && (filesSize >= filesString.length()))
				{
					*filesBufferSize = filesString.length();
					memcpy(filesBuffer, filesString.c_str(), filesString.length());
				}
			}
		}

        return CKR_OK;
	}

	// Create a new subdirectory
	bool mkdir(std::string fullPath)
	{
		int rv = ::mkdir(fullPath.c_str(), S_IFDIR | S_IRWXU);

		if (rv != 0)
		{
			return false;
		}

		return true; 
	}

	// Delete a subdirectory in the directory
	bool rmdir(std::string fullPath)
	{
		if (::rmdir(fullPath.c_str()) != 0)
        {
			return false;
        }

		return true;
	}
}

CK_RV ocall_refresh(const char* path, char* subDirsBuffer, uint32_t subDirsSize, uint32_t* subDirsBufferSize, char* filesBuffer, uint32_t filesSize, uint32_t* filesBufferSize)
{
   return Directory::refresh(path, subDirsBuffer, subDirsSize, subDirsBufferSize, filesBuffer, filesSize, filesBufferSize);
}

uint8_t ocall_mkdir(const char* path)
{
    return Directory::mkdir(path);
}

uint8_t ocall_rmdir(const char* path)
{
    return Directory::rmdir(path);
}


