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

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "cryptoki.h"

//---------------------------------------------------------------------------------------------
/**
* Initializes the encryption process.
* @param   hSession     The session handle.
* @param   pMechanism   Pointer to CK_MECHANISM structure.
* @param   hKey         The key handle to be used for encryption.
* @return  CK_RV        CKR_OK if encryptInit is successful, error code otherwise
*/
CK_RV encryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

//---------------------------------------------------------------------------------------------
/**
* Completes the encryption process.
* @param   hSession            The session handle.
* @param   pData               Pointer to data to be encrypted.
* @param   ulDataLen           The size of data to be encrypted.
* @param   pEncryptedData      Pointer where encrypted data is to be populated.
* @param   pulEncryptedDataLen Pointer to size of encrypted data.
* @return  CK_RV               CKR_OK if encrypt is successful, error code otherwise
*/
CK_RV encrypt(CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR       pData,
              CK_ULONG          ulDataLen,
              CK_BYTE_PTR       pEncryptedData,
              CK_ULONG_PTR      pulEncryptedDataLen);


//---------------------------------------------------------------------------------------------
/**
* Continues the encryption process.
* @param   hSession            The session handle.
* @param   pData               Pointer to data to be encrypted.
* @param   ulDataLen           The size of data to be encrypted.
* @param   pEncryptedData      Pointer where encrypted data is to be populated.
* @param   pulEncryptedDataLen Pointer to size of encrypted data.
* @return  CK_RV               CKR_OK if encryptUpdate is successful, error code otherwise
*/
CK_RV encryptUpdate(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR       pData,
                    CK_ULONG          ulDataLen,
                    CK_BYTE_PTR       pEncryptedData,
                    CK_ULONG_PTR      pulEncryptedDataLen);

//---------------------------------------------------------------------------------------------
/**
* Finalizes the encryption process.
* @param   hSession            The session handle.
* @param   pEncryptedData      Pointer where encrypted data is to be populated.
* @param   pulEncryptedDataLen Pointer to size of encrypted data.
* @return  CK_RV               CKR_OK if encryptFinal is successful, error code otherwise
*/
CK_RV encryptFinal(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pEncryptedData,
                   CK_ULONG_PTR      pulEncryptedDataLen);

#endif //ENCRYPTION_H