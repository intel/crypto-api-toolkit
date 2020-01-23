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

#include "Verify.h"
#include "EnclaveInterface.h"
#include "p11Sgx.h"

//---------------------------------------------------------------------------------------------
CK_RV verifyInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR  pMechanism,
                 CK_OBJECT_HANDLE  hKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::verifyInit(hSession,
                                     pMechanism,
                                     hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV verify(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR       pData,
             CK_ULONG          ulDataLen,
             CK_BYTE_PTR       pSignature,
             CK_ULONG          ulSignatureLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::verify(hSession,
                                 pData,
                                 ulDataLen,
                                 pSignature,
                                 ulSignatureLen);
}

CK_RV verifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::verifyUpdate(hSession, pPart, ulPartLen);
}

CK_RV verifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::verifyFinal(hSession, pSignature, ulSignatureLen);
}

CK_RV verifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::verifyRecoverInit(hSession, pMechanism, hKey);
}

CK_RV verifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen)
{
    if (!isInitialized())
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    return EnclaveInterface::verifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}

