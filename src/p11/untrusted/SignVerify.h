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

#ifndef SIGNVERIFY_H
#define SIGNVERIFY_H

#include "p11Defines.h"
#include "p11Access.h"
#include "SessionCache.h"
#include "AttributeUtils.h"
#include "AsymmetricProvider.h"
#include "Digest.h"

//---------------------------------------------------------------------------------------------
/**
* Initializes the sign process.
* @param   hSession     The session handle.
* @param   pMechanism   Pointer to CK_MECHANISM structure.
* @param   hKey         The key handle to be used for signing.
* @return  CK_RV        CKR_OK if signInit is successful, error code otherwise.
*/
CK_RV signInit(CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR  pMechanism,
               CK_OBJECT_HANDLE  hKey);

//---------------------------------------------------------------------------------------------
/**
* Completes the sign process.
* @param   hSession            The session handle.
* @param   pData               Pointer to data to be signed.
* @param   ulDataLen           The size of data to be signed.
* @param   pSignature          Pointer where signature is to be populated.
* @param   pulSignatureLen     Pointer to size of signature.
* @return  CK_RV               CKR_OK if sign is successful, error code otherwise
*/
CK_RV sign(CK_SESSION_HANDLE hSession,
           CK_BYTE_PTR       pData,
           CK_ULONG          ulDataLen,
           CK_BYTE_PTR       pSignature,
           CK_ULONG_PTR      pulSignatureLen);

//---------------------------------------------------------------------------------------------
/**
* Initializes the verify process.
* @param   hSession     The session handle.
* @param   pMechanism   Pointer to CK_MECHANISM structure.
* @param   hKey         The key handle to be used for verifying.
* @return  CK_RV        CKR_OK if verifyInit is successful, error code otherwise.
*/
CK_RV verifyInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR  pMechanism,
                 CK_OBJECT_HANDLE  hKey);

//---------------------------------------------------------------------------------------------
/**
* Completes the verify process.
* @param   hSession            The session handle.
* @param   pData               Pointer to data.
* @param   ulDataLen           The size of data.
* @param   pSignature          Pointer to signature.
* @param   ulSignatureLen     Size of signature.
* @return  CK_RV               CKR_OK if sign is successful, error code otherwise
*/
CK_RV verify(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR       pData,
             CK_ULONG          ulDataLen,
             CK_BYTE_PTR       pSignature,
             CK_ULONG          ulSignatureLen);

#endif // SIGNVERIFY_H