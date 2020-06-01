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

#include "GPFunctions.h"
#include "p11Sgx.h"
#include "EnclaveInterface.h"

#include <iostream>

CK_RV checkInitArgs(CK_VOID_PTR pInitArgs)
{
    CK_C_INITIALIZE_ARGS_PTR args;

    if (pInitArgs != NULL_PTR)
    {
        args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

        // Must be set to NULL_PTR in this version of PKCS#11
        if (args->pReserved != NULL_PTR)
        {
            // ERROR_MSG("pReserved must be set to NULL_PTR");
            return CKR_ARGUMENTS_BAD;
        }

        // SGXHSM does not support application provided mutex callbacks
        if (args->CreateMutex != NULL_PTR ||
            args->DestroyMutex != NULL_PTR ||
            args->LockMutex != NULL_PTR ||
            args->UnlockMutex != NULL_PTR)
        {
            return CKR_ARGUMENTS_BAD;
        }
    }

    return CKR_OK;
}

//---------------------------------------------------------------------------------------------
CK_RV initialize(CK_VOID_PTR pInitArgs)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    rv = checkInitArgs(pInitArgs);
    if (rv != CKR_OK)
    {
        return rv;
    }

    if (isInitialized() && EnclaveInterface::eIsInitialized(pInitArgs))
    {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    // I think we need to verify this flow - this is not correct - the tests are failing if this is not forced as CKR_OK;
    //rv = CKR_OK;

    if (EnclaveInterface::loadEnclave())
    {
        rv == EnclaveInterface::initialize(pInitArgs);

        if(CKR_OK == rv)
        {
            init();
        }
        else
        {
            return rv;
        }
    }
    else
    {
        rv = CKR_DEVICE_ERROR;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV finalize(CK_VOID_PTR pReserved)
{
    CK_RV rv = CKR_OK;

    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (pReserved != NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }

    // Destroy Enclave.
    rv = EnclaveInterface::finalize(pReserved);
    EnclaveInterface::unloadEnclave();
    deinit();

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getInfo(CK_INFO_PTR pInfo)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::getInfo(pInfo);
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
