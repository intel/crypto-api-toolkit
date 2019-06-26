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

#include "GPFunctions.h"

//---------------------------------------------------------------------------------------------
CK_RV initializeProvider(CK_VOID_PTR pInitArgs)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (isInitialized())
        {
            rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
            break;
        }

        if (pInitArgs)
        {
            CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

            if (args->pReserved)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            // If CKF_LIBRARY_CANT_CREATE_OS_THREADS is set, the library shouldn't create its own threads.
            // Hence rejecting it.
            if (CKF_LIBRARY_CANT_CREATE_OS_THREADS & args->flags)
            {
                rv = CKR_NEED_TO_CREATE_THREADS;
                break;
            }

            bool appProvidedLock {true};
            appProvidedLock = args->CreateMutex || args->DestroyMutex || args->LockMutex || args->UnlockMutex;

            // Rejecting if CKF_OS_LOCKING_OK is not set AND mutex locks are passed from application.
            if (!(CKF_OS_LOCKING_OK & args->flags) && appProvidedLock)
            {
                rv = CKR_CANT_LOCK;
                break;
            }

            rv = CKR_OK;
        }
        else
        {
            rv = CKR_OK;
        }
    } while (false);

    if (CKR_OK == rv)
    {
        if (Utils::EnclaveUtils::loadEnclave())
        {
            initialize();
        }
        else
        {
            rv = CKR_DEVICE_ERROR;
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV finalizeProvider(CK_VOID_PTR pReserved)
{
    CK_RV rv = CKR_OK;

    do
    {
        if (pReserved)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized())
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        // Clear provider caches.
        if (gSessionCache)
        {
            std::vector<CK_SLOT_ID> slotIDs;

            // Remove all slot/token files used by this application.
            slotIDs = gSessionCache->getAllSlotIDs();
            unsigned int slotCount = slotIDs.size();

            for (unsigned int i = 0; i < slotCount; ++i)
            {
                P11Crypto::Slot slot(slotIDs[i]);
                if (!slot.valid())
                {
                    rv = CKR_SLOT_ID_INVALID;
                    continue;
                }

                P11Crypto::Token* token = slot.getToken();
                if (!token)
                {
                    rv = CKR_TOKEN_NOT_PRESENT;
                    continue;
                }

                rv = token->finalize();
            }

            // Clear session handle cache.
            gSessionCache->clear();

            rv = CKR_OK;
        }

        // Destroy Enclave.
        Utils::EnclaveUtils::unloadEnclave();
        deinitialize();
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getInfo(CK_INFO_PTR pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized())
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
        pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;

        std::memset(pInfo->manufacturerID, ' ', 32);
        std::memcpy(pInfo->manufacturerID, MANUFACTURER_ID, sizeof(MANUFACTURER_ID) - 1);

        pInfo->flags = 0;

        std::memset(pInfo->libraryDescription, ' ', 32);
        std::memcpy(pInfo->libraryDescription, LIBRARY_DESC, sizeof(LIBRARY_DESC) - 1);

        // (Todo) Make this a configurable option via configure.ac
        pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
        pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (!ppFunctionList)
    {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &functionList;

    return CKR_OK;
}