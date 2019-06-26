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

#ifndef DIGEST_H
#define DIGEST_H

#include "CryptoEnclaveDefs.h"
#include "p11Defines.h"
#include "p11Sgx.h"
#include "p11Access.h"
#include "HashProvider.h"

#include <map>

static std::map<HashMode, HashDigestLength> hashDigestLengthMap = {
                                                                    { HashMode::sha256, HashDigestLength::sha256 },
                                                                    { HashMode::sha512, HashDigestLength::sha512 }
                                                                  };

//---------------------------------------------------------------------------------------------
/**
* Initializes the digest operation.
* @param   hSession     The session handle.
* @param   pMechanism   Pointer to CK_MECHANISM structure.
* @return  CK_RV        CKR_OK if digestInit is successful, error code otherwise
*/
CK_RV digestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);


//---------------------------------------------------------------------------------------------
/**
* Continues the digest operation.
* @param   hSession  The session handle.
* @param   pPart     Pointer to data to be digested.
* @param   ulPartLen The size of data to be digested.
* @return  CK_RV     CKR_OK if digestUpdate is successful, error code otherwise
*/
CK_RV digestUpdate(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pPart,
                   CK_ULONG          ulPartLen);

//---------------------------------------------------------------------------------------------
/**
* Completes the digest operation.
* @param   hSession     The session handle.
* @param   pData        Pointer to data to be digested.
* @param   ulDataLen    The size of data to be digested.
* @param   pDigest      Pointer where digested data is to be populated.
* @param   pulDigestLen Pointer to size of digested data.
* @return  CK_RV        CKR_OK if digest is successful, error code otherwise.
*/
CK_RV digest(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR       pData,
             CK_ULONG          ulDataLen,
             CK_BYTE_PTR       pDigest,
             CK_ULONG_PTR      pulDigestLen);

//---------------------------------------------------------------------------------------------
/**
* Finalizes the digest operation.
* @param   hSession     The session handle.
* @param   pDigest      Pointer where digested data is to be populated.
* @param   pulDigestLen Pointer to size of digested data.
* @return  CK_RV        CKR_OK if digestFinal is successful, error code otherwise
*/
CK_RV digestFinal(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR       pDigest,
                  CK_ULONG_PTR      pulDigestLen);

#endif //DIGEST_H