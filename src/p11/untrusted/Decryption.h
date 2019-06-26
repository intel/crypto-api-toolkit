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

#ifndef DECRYPTION_H
#define DECRYPTION_H

#include "p11Sgx.h"
#include "p11Access.h"
#include "p11Defines.h"
#include "AttributeUtils.h"
#include "SymmetricProvider.h"
#include "AsymmetricProvider.h"

//---------------------------------------------------------------------------------------------
/**
* Initializes the decryption process.
* @param   hSession     The session handle.
* @param   pMechanism   Pointer to CK_MECHANISM structure.
* @param   hKey         The key handle to be used for decryption.
* @return  CK_RV        CKR_OK if decryptInit is successful, error code otherwise
*/
CK_RV decryptInit(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR  pMechanism,
                  CK_OBJECT_HANDLE  hKey);

//---------------------------------------------------------------------------------------------
/**
* Continues the decryption process.
* @param   hSession            The session handle.
* @param   pEncryptedData      Pointer to data to be decrypted.
* @param   ulEncryptedDataLen  The size of data to be decrypted.
* @param   pData               Pointer where decrypted data is to be populated.
* @param   pulDataLen          Pointer to size of decrypted data.
* @return  CK_RV               CKR_OK if decryptUpdate is successful, error code otherwise
*/
CK_RV decryptUpdate(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR       pEncryptedData,
                    CK_ULONG          ulEncryptedDataLen,
                    CK_BYTE_PTR       pData,
                    CK_ULONG_PTR      pDataLen);

//---------------------------------------------------------------------------------------------
/**
* Completes the decryption process.
* @param   hSession            The session handle.
* @param   pEncryptedData      Pointer to data to be decrypted.
* @param   ulEncryptedDataLen  The size of data to be decrypted.
* @param   pData               Pointer where decrypted data is to be populated.
* @param   pulDataLen          Pointer to size of decrypted data.
* @return  CK_RV               CKR_OK if decrypt is successful, error code otherwise
*/
CK_RV decrypt(CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR       pEncryptedData,
              CK_ULONG          ulEncryptedDataLen,
              CK_BYTE_PTR       pData,
              CK_ULONG_PTR      pulDataLen);

//---------------------------------------------------------------------------------------------
/**
* Finalizes the decryption process.
* @param   hSession The session handle.
* @param   pData    Pointer where decrypted data is to be populated.
* @param   pDataLen Pointer to size of decrypted data.
* @return  CK_RV    CKR_OK if decryptFinal is successful, error code otherwise
*/
CK_RV decryptFinal(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pData,
                   CK_ULONG_PTR      pDataLen);

#endif // DECRYPTION_H