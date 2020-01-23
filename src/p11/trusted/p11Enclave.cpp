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

#include <string>

#include "p11Enclave_t.h"
#include "main.h"
#include "Configuration.h"

#define TOKENDIR_CONFIGSTR "directories.tokendir"
#define OBJECTSTORE_CONFIGSTR "objectstore.backend"
#define SLOTREMOVABLE_CONFIGSTR "slots.removable"

void configure()
{
    Configuration::i()->setString(TOKENDIR_CONFIGSTR, DEFAULT_TOKENDIR);
    Configuration::i()->setString(OBJECTSTORE_CONFIGSTR, "file");
    Configuration::i()->setBool(SLOTREMOVABLE_CONFIGSTR, false);
}


//---------------------------------------------------------------------------------------------
/* Crypto API toolkit currently does not support application passed mutex locks.
 *
 * Flag(CKF_OS_LOCKING_OK)           Mutexes                          Result
 *          SET                       NULL              Uses OS primitives for thread safet.
 *          SET      w                 NON NULL          Uses OS primitives for thread safet.
 *          NOT SET                   NULL              Uses OS primitives for thread safet.
 *          NOT SET                   NON NULL          (UNSUPPORTED) Rejects with CKR_CANT_LOCK.
 *
 */
CK_RV sgx_C_Initialize(CK_VOID_PTR pInitArgs)
{
    configure();

    return C_Initialize(pInitArgs);
}

//------------------- --------------------------------------------------------------------------
CK_RV sgx_C_Finalize(CK_VOID_PTR pReserved)
{
    return C_Finalize(pReserved);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetInfo(CK_INFO_PTR pInfo)
{
    return C_GetInfo(pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetSlotList(CK_BBOOL       tokenPresent,
                        CK_SLOT_ID_PTR pSlotList,
                        CK_ULONG_PTR   pulCount)
{
    return C_GetSlotList(tokenPresent, pSlotList, pulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    return C_GetSlotInfo(slotID, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_EncryptInit(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR  pMechanism,
                        CK_OBJECT_HANDLE  hKey)
{
    return C_EncryptInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR       pData,
                          CK_ULONG          ulDataLen,
                          CK_BYTE_PTR       pEncryptedData,
                          CK_ULONG_PTR      pulEncryptedDataLen)
{
    return C_EncryptUpdate(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Encrypt(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR       pData,
                    CK_ULONG          ulDataLen,
                    CK_BYTE_PTR       pEncryptedData,
                    CK_ULONG_PTR      pulEncryptedDataLen)
{
    return C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_EncryptFinal(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR       pEncryptedData,
                         CK_ULONG_PTR      pulEncryptedDataLen)
{
    return C_EncryptFinal(hSession, pEncryptedData, pulEncryptedDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DecryptInit(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR  pMechanism,
                        CK_OBJECT_HANDLE  hKey)
{
    return C_DecryptInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Decrypt(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR       pEncryptedData,
                    CK_ULONG          ulEncryptedDataLen,
                    CK_BYTE_PTR       pData,
                    CK_ULONG_PTR      pulDataLen)
{
    return C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR       pEncryptedData,
                          CK_ULONG          ulEncryptedDataLen,
                          CK_BYTE_PTR       pData,
                          CK_ULONG_PTR      pDataLen)
{

    return C_DecryptUpdate(hSession, pEncryptedData, ulEncryptedDataLen, pData, pDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DecryptFinal(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR       pData,
                         CK_ULONG_PTR      pDataLen)
{
    return C_DecryptFinal(hSession, pData, pDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    return C_DigestInit(hSession, pMechanism);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Digest(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pData,
                   CK_ULONG          ulDataLen,
                   CK_BYTE_PTR       pDigest,
                   CK_ULONG_PTR      pulDigestLen)

{
    return C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DigestUpdate(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR       pPart,
                         CK_ULONG          ulPartLen)
{
    return C_DigestUpdate(hSession, pPart, ulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DigestFinal(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR       pDigest,
                        CK_ULONG_PTR      pulDigestLen)
{
    return C_DigestFinal(hSession, pDigest,pulDigestLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SignInit(CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_PTR  pMechanism,
                     CK_OBJECT_HANDLE  hKey)
{
    return C_SignInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Sign(CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR       pData,
                 CK_ULONG          ulDataLen,
                 CK_BYTE_PTR       pSignature,
                 CK_ULONG_PTR      pulSignatureLen)
{
    return C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_VerifyInit(CK_SESSION_HANDLE hSession,
                       CK_MECHANISM_PTR  pMechanism,
                       CK_OBJECT_HANDLE  hKey)
{

    return C_VerifyInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Verify(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pData,
                   CK_ULONG          ulDataLen,
                   CK_BYTE_PTR       pSignature,
                   CK_ULONG          ulSignatureLen)
{
    return C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GenerateKey(CK_SESSION_HANDLE   hSession,
                        CK_MECHANISM_PTR    pMechanism,
                        CK_ATTRIBUTE_PTR    pTemplate,
                        CK_ULONG            ulCount,
                        CK_ULONG_PTR        phKey)
{
    return C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GenerateKeyPair(CK_SESSION_HANDLE   hSession,
                            CK_MECHANISM_PTR    pMechanism,
                            CK_ATTRIBUTE_PTR    pPublicKeyTemplate,
                            CK_ULONG            ulPublicKeyAttributeCount,
                            CK_ATTRIBUTE_PTR    pPrivateKeyTemplate,
                            CK_ULONG            ulPrivateKeyAttributeCount,
                            CK_ULONG_PTR        phPublicKey,
                            CK_ULONG_PTR        phPrivateKey)
{

    return C_GenerateKeyPair(hSession, pMechanism,
                             pPublicKeyTemplate,  ulPublicKeyAttributeCount,
                             pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                             phPublicKey, phPrivateKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_WrapKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR  pMechanism,
                    CK_OBJECT_HANDLE  hWrappingKey,
                    CK_OBJECT_HANDLE  hKey,
                    CK_BYTE_PTR       pWrappedKey,
                    CK_ULONG_PTR      pulWrappedKeyLen)
{
    return C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_UnwrapKey(CK_SESSION_HANDLE    hSession,
                      CK_MECHANISM_PTR     pMechanism,
                      CK_OBJECT_HANDLE     hUnwrappingKey,
                      CK_BYTE_PTR          pWrappedKey,
                      CK_ULONG             ulWrappedKeyLen,
                      CK_ATTRIBUTE_PTR     pTemplate,
                      CK_ULONG             ulCount,
                      CK_OBJECT_HANDLE_PTR hKey)
{
    return C_UnwrapKey(hSession, pMechanism,
                       hUnwrappingKey,
                       pWrappedKey, ulWrappedKeyLen,
                       pTemplate, ulCount, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetTokenInfo(CK_SLOT_ID        slotID,
                         CK_TOKEN_INFO_PTR pInfo)
{
    return C_GetTokenInfo(slotID, pInfo);
}

#if 0 // Unsupported by Crypto API Toolkit
//---------------------------------------------------------------------------------------------
CK_RV sgx_C_WaitForSlotEvent(CK_FLAGS       flags,
                             CK_SLOT_ID_PTR pSlot,
                             CK_VOID_PTR    pReserved)
{
    return C_WaitForSlotEvent(flags, pSlot, pReserved); ;
}
#endif // Unsupported by Crypto API Toolkit

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetMechanismInfo(CK_SLOT_ID            slotID,
                             CK_MECHANISM_TYPE     type,
                             CK_MECHANISM_INFO_PTR pInfo)
{
    return C_GetMechanismInfo(slotID, type, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetMechanismList(CK_SLOT_ID            slotID,
                             CK_MECHANISM_TYPE_PTR pMechanismList,
                             CK_ULONG_PTR          pulCount)
{
    return C_GetMechanismList(slotID, pMechanismList, pulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_InitToken(CK_SLOT_ID      slotID,
                      CK_UTF8CHAR_PTR pPin,
                      CK_ULONG        ulPinLen,
                      CK_UTF8CHAR_PTR pLabel)
{
    return C_InitToken(slotID, pPin, ulPinLen, pLabel);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_InitPIN(CK_SESSION_HANDLE hSession,
                    CK_UTF8CHAR_PTR   pPin,
                    CK_ULONG          ulPinLen)
{
    return C_InitPIN(hSession, pPin, ulPinLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SetPIN(CK_SESSION_HANDLE hSession,
                   CK_UTF8CHAR_PTR   pOldPin,
                   CK_ULONG          ulOldLen,
                   CK_UTF8CHAR_PTR   pNewPin,
                   CK_ULONG          ulNewLen)
{
    return C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_OpenSession(CK_SLOT_ID            slotID,
                        CK_FLAGS              flags,
                        CK_VOID_PTR           pApplication,
                        CK_NOTIFY             notify,
                        CK_SESSION_HANDLE_PTR phSession)
{
    return C_OpenSession(slotID, flags, pApplication, notify, phSession);
}

//---------------------------------------------------------------------------------------------
CK_RV  sgx_C_CloseSession(CK_SESSION_HANDLE hSession)
{
    return C_CloseSession(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_CloseAllSessions(CK_SLOT_ID slotID)
{
    return C_CloseAllSessions(slotID);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetSessionInfo(CK_SESSION_HANDLE   hSession,
                           CK_SESSION_INFO_PTR pInfo)
{
    return C_GetSessionInfo(hSession, pInfo);
}

#if 0 // Unsupported by Crypto API Toolkit
//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetOperationState(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR       pOperationState,
                              CK_ULONG_PTR      pulOperationStateLen)
{
    return C_GetOperationState(hSession, pOperationState, pulOperationStateLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SetOperationState(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR       pOperationState,
                              CK_ULONG          ulOperationStateLen,
                              CK_OBJECT_HANDLE  hEncryptionKey,
                              CK_OBJECT_HANDLE  hAuthenticationKey)
{
    return C_SetOperationState(hSession, pOperationState,
                              ulOperationStateLen,
                              hEncryptionKey,
                              hAuthenticationKey);
}
#endif // Unsupported by Crypto API Toolkit

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Login(CK_SESSION_HANDLE hSession,
                  CK_USER_TYPE      userType,
                  CK_UTF8CHAR_PTR   pPin,
                  CK_ULONG          ulPinLen)
{
    return C_Login(hSession, userType, pPin, ulPinLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_Logout(CK_SESSION_HANDLE hSession)
{
    return C_Logout(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_CreateObject(CK_SESSION_HANDLE    hSession,
                         CK_ATTRIBUTE_PTR     pTemplate,
                         CK_ULONG             ulCount,
                         CK_OBJECT_HANDLE_PTR phObject)
{
    return C_CreateObject(hSession, pTemplate, ulCount, phObject);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_CopyObject(CK_SESSION_HANDLE    hSession,
                       CK_OBJECT_HANDLE     hObject,
                       CK_ATTRIBUTE_PTR     pTemplate,
                       CK_ULONG             ulCount,
                       CK_OBJECT_HANDLE_PTR phNewObject)
{
    return C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    return C_GetObjectSize(hSession, hObject, pulSize);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetAttributeValue(CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE  hObject,
        CK_ATTRIBUTE_PTR  pTemplate,
        CK_ULONG          ulCount)
{
    return C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SetAttributeValue(CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE  hObject,
        CK_ATTRIBUTE_PTR  pTemplate,
        CK_ULONG          ulCount)
{
    return C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                            CK_ATTRIBUTE_PTR  pTemplate,
                            CK_ULONG          ulCount)
{
    return C_FindObjectsInit(hSession, pTemplate, ulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_FindObjects(CK_SESSION_HANDLE    hSession,
                        CK_OBJECT_HANDLE_PTR phObject,
                        CK_ULONG             ulMaxObjectCount,
                        CK_ULONG_PTR         pulObjectCount)
{
    return C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    return C_FindObjectsFinal(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DestroyObject(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE  hKey)
{
    return C_DestroyObject(hSession, hKey);
}

#if 0 // Unsupported by Crypto API Toolkit
//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    return C_GetFunctionStatus(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    return C_DigestKey(hSession, hKey);
}
#endif // Unsupported by Crypto API Toolkit

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return C_SignUpdate(hSession, pPart, ulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return C_SignFinal(hSession, pSignature, pulSignatureLen);
}

#if 0 // Unsupported by Crypto API Toolkit
//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return C_SignRecoverInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}
#endif // Unsupported by Crypto API Toolkit

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return C_VerifyUpdate(hSession, pPart, ulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return C_VerifyFinal(hSession, pSignature, ulSignatureLen);
}

#if 0 // Unsupported by Crypto API Toolkit
//---------------------------------------------------------------------------------------------
CK_RV sgx_C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return C_VerifyRecoverInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    return C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    return C_SeedRandom(hSession, pSeed, ulSeedLen);
}
#endif // Unsupported by Crypto API Toolkit

//---------------------------------------------------------------------------------------------
CK_RV sgx_C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    return C_GenerateRandom(hSession, pRandomData, ulRandomLen);
}

#if 0 // Unsupported by Crypto API Toolkit
//---------------------------------------------------------------------------------------------
CK_RV sgx_C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    return C_CancelFunction(hSession);
}
#endif // Unsupported by Crypto API Toolkit

