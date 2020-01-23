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

#include "P11Provider.h"

//---------------------------------------------------------------------------------------------
/* Crypto API toolkit currently does not support application passed mutex locks.
 *
 * Flag(CKF_OS_LOCKING_OK)           Mutexes                          Result
 *          SET                       NULL              Uses OS primitives for thread safet.
 *          SET                       NON NULL          Uses OS primitives for thread safet.
 *          NOT SET                   NULL              Uses OS primitives for thread safet.
 *          NOT SET                   NON NULL          (UNSUPPORTED) Rejects with CKR_CANT_LOCK.
 *
*/
CK_RV __attribute__((visibility("default"))) C_Initialize(CK_VOID_PTR pInitArgs)
{
    return initialize(pInitArgs);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Finalize(CK_VOID_PTR pReserved)
{
    return finalize(pReserved);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetInfo(CK_INFO_PTR pInfo)
{
    return getInfo(pInfo);
}

//---------------------------------------------------------------------------------------------
PKCS_API CK_RV __attribute__((visibility("default"))) C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    return getFunctionList(ppFunctionList);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetSlotList(CK_BBOOL       tokenPresent,
                                                           CK_SLOT_ID_PTR pSlotList,
                                                           CK_ULONG_PTR   pulCount)
{
    return getSlotList(tokenPresent, pSlotList, pulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    return getSlotInfo(slotID, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_EncryptInit(CK_SESSION_HANDLE hSession,
                                                           CK_MECHANISM_PTR  pMechanism,
                                                           CK_OBJECT_HANDLE  hKey)
{
    return encryptInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                                                             CK_BYTE_PTR       pData,
                                                             CK_ULONG          ulDataLen,
                                                             CK_BYTE_PTR       pEncryptedData,
                                                             CK_ULONG_PTR      pulEncryptedDataLen)
{
    return encryptUpdate(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Encrypt(CK_SESSION_HANDLE hSession,
                                                       CK_BYTE_PTR       pData,
                                                       CK_ULONG          ulDataLen,
                                                       CK_BYTE_PTR       pEncryptedData,
                                                       CK_ULONG_PTR      pulEncryptedDataLen)
{
    return encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_EncryptFinal(CK_SESSION_HANDLE hSession,
                                                            CK_BYTE_PTR       pEncryptedData,
                                                            CK_ULONG_PTR      pulEncryptedDataLen)
{
    return encryptFinal(hSession, pEncryptedData, pulEncryptedDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptInit(CK_SESSION_HANDLE hSession,
                                                           CK_MECHANISM_PTR  pMechanism,
                                                           CK_OBJECT_HANDLE  hKey)
{
    return decryptInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Decrypt(CK_SESSION_HANDLE hSession,
                                                       CK_BYTE_PTR       pEncryptedData,
                                                       CK_ULONG          ulEncryptedDataLen,
                                                       CK_BYTE_PTR       pData,
                                                       CK_ULONG_PTR      pulDataLen)
{
    return decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                                                             CK_BYTE_PTR       pEncryptedData,
                                                             CK_ULONG          ulEncryptedDataLen,
                                                             CK_BYTE_PTR       pData,
                                                             CK_ULONG_PTR      pDataLen)
{

    return decryptUpdate(hSession, pEncryptedData, ulEncryptedDataLen, pData, pDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptFinal(CK_SESSION_HANDLE hSession,
                                                            CK_BYTE_PTR       pData,
                                                            CK_ULONG_PTR      pDataLen)
{
    return decryptFinal(hSession, pData, pDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    return digestInit(hSession, pMechanism);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Digest(CK_SESSION_HANDLE hSession,
                                                      CK_BYTE_PTR       pData,
                                                      CK_ULONG          ulDataLen,
                                                      CK_BYTE_PTR       pDigest,
                                                      CK_ULONG_PTR      pulDigestLen)

{
    return digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestUpdate(CK_SESSION_HANDLE hSession,
                                                            CK_BYTE_PTR       pPart,
                                                            CK_ULONG          ulPartLen)
{
    return digestUpdate(hSession, pPart, ulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestFinal(CK_SESSION_HANDLE hSession,
                                                           CK_BYTE_PTR       pDigest,
                                                           CK_ULONG_PTR      pulDigestLen)
{
    return digestFinal(hSession, pDigest,pulDigestLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignInit(CK_SESSION_HANDLE hSession,
                                                        CK_MECHANISM_PTR  pMechanism,
                                                        CK_OBJECT_HANDLE  hKey)
{
    return signInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Sign(CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR       pData,
                                                    CK_ULONG          ulDataLen,
                                                    CK_BYTE_PTR       pSignature,
                                                    CK_ULONG_PTR      pulSignatureLen)
{
    return sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyInit(CK_SESSION_HANDLE hSession,
                                                          CK_MECHANISM_PTR  pMechanism,
                                                          CK_OBJECT_HANDLE  hKey)
{

    return verifyInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Verify(CK_SESSION_HANDLE hSession,
                                                      CK_BYTE_PTR       pData,
                                                      CK_ULONG          ulDataLen,
                                                      CK_BYTE_PTR       pSignature,
                                                      CK_ULONG          ulSignatureLen)
{
    return verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GenerateKey(CK_SESSION_HANDLE    hSession,
                                                           CK_MECHANISM_PTR     pMechanism,
                                                           CK_ATTRIBUTE_PTR     pTemplate,
                                                           CK_ULONG             ulCount,
                                                           CK_OBJECT_HANDLE_PTR phKey)
{
    return generateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GenerateKeyPair(CK_SESSION_HANDLE    hSession,
                                                               CK_MECHANISM_PTR     pMechanism,
                                                               CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
                                                               CK_ULONG             ulPublicKeyAttributeCount,
                                                               CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
                                                               CK_ULONG             ulPrivateKeyAttributeCount,
                                                               CK_OBJECT_HANDLE_PTR phPublicKey,
                                                               CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    return generateKeyPair(hSession, pMechanism,
                           pPublicKeyTemplate,  ulPublicKeyAttributeCount,
                           pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                           phPublicKey, phPrivateKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_WrapKey(CK_SESSION_HANDLE hSession,
                                                       CK_MECHANISM_PTR  pMechanism,
                                                       CK_OBJECT_HANDLE  hWrappingKey,
                                                       CK_OBJECT_HANDLE  hKey,
                                                       CK_BYTE_PTR       pWrappedKey,
                                                       CK_ULONG_PTR      pulWrappedKeyLen)
{
    return wrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_UnwrapKey(CK_SESSION_HANDLE    hSession,
                                                         CK_MECHANISM_PTR     pMechanism,
                                                         CK_OBJECT_HANDLE     hUnwrappingKey,
                                                         CK_BYTE_PTR          pWrappedKey,
                                                         CK_ULONG             ulWrappedKeyLen,
                                                         CK_ATTRIBUTE_PTR     pTemplate,
                                                         CK_ULONG             ulCount,
                                                         CK_OBJECT_HANDLE_PTR hKey)
{
    return unwrapKey(hSession, pMechanism,
                     hUnwrappingKey,
                     pWrappedKey, ulWrappedKeyLen,
                     pTemplate, ulCount, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetTokenInfo(CK_SLOT_ID        slotID,
                                                            CK_TOKEN_INFO_PTR pInfo)
{
    return getTokenInfo(slotID, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_WaitForSlotEvent(CK_FLAGS       flags,
                                                                CK_SLOT_ID_PTR pSlot,
                                                                CK_VOID_PTR    pReserved)
{
    return waitForSlotEvent(flags, pSlot, pReserved);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetMechanismInfo(CK_SLOT_ID            slotID,
                                                                CK_MECHANISM_TYPE     type,
                                                                CK_MECHANISM_INFO_PTR pInfo)
{
    return getMechanismInfo(slotID, type, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetMechanismList(CK_SLOT_ID            slotID,
                                                                CK_MECHANISM_TYPE_PTR pMechanismList,
                                                                CK_ULONG_PTR          pulCount)
{
    return getMechanismList(slotID, pMechanismList, pulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_InitToken(CK_SLOT_ID      slotID,
                                                         CK_UTF8CHAR_PTR pPin,
                                                         CK_ULONG        ulPinLen,
                                                         CK_UTF8CHAR_PTR pLabel)
{
    return initToken(slotID, pPin, ulPinLen, pLabel);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_InitPIN(CK_SESSION_HANDLE hSession,
                                                       CK_UTF8CHAR_PTR   pPin,
                                                       CK_ULONG          ulPinLen)
{
    return initPIN(hSession, pPin, ulPinLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SetPIN(CK_SESSION_HANDLE hSession,
                                                      CK_UTF8CHAR_PTR   pOldPin,
                                                      CK_ULONG          ulOldLen,
                                                      CK_UTF8CHAR_PTR   pNewPin,
                                                      CK_ULONG          ulNewLen)
{
    return setPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_OpenSession(CK_SLOT_ID            slotID,
                                                           CK_FLAGS              flags,
                                                           CK_VOID_PTR           pApplication,
                                                           CK_NOTIFY             notify,
                                                           CK_SESSION_HANDLE_PTR phSession)
{
    return openSession(slotID, flags, pApplication, notify, phSession);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default")))  C_CloseSession(CK_SESSION_HANDLE hSession)
{
    return closeSession(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CloseAllSessions(CK_SLOT_ID slotID)
{
    return closeAllSessions(slotID);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetSessionInfo(CK_SESSION_HANDLE   hSession,
                                                              CK_SESSION_INFO_PTR pInfo)
{
    return getSessionInfo(hSession, pInfo);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetOperationState(CK_SESSION_HANDLE hSession,
                                                                 CK_BYTE_PTR       pOperationState,
                                                                 CK_ULONG_PTR      pulOperationStateLen)
{
    return getOperationState(hSession, pOperationState, pulOperationStateLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SetOperationState(CK_SESSION_HANDLE hSession,
                                                                 CK_BYTE_PTR       pOperationState,
                                                                 CK_ULONG          ulOperationStateLen,
                                                                 CK_OBJECT_HANDLE  hEncryptionKey,
                                                                 CK_OBJECT_HANDLE  hAuthenticationKey)
{
    return setOperationState(hSession, pOperationState,
                             ulOperationStateLen,
                             hEncryptionKey,
                             hAuthenticationKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Login(CK_SESSION_HANDLE hSession,
                                                     CK_USER_TYPE      userType,
                                                     CK_UTF8CHAR_PTR   pPin,
                                                     CK_ULONG          ulPinLen)
{
    return login(hSession, userType, pPin, ulPinLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Logout(CK_SESSION_HANDLE hSession)
{
    return logout(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CreateObject(CK_SESSION_HANDLE    hSession,
                                                            CK_ATTRIBUTE_PTR     pTemplate,
                                                            CK_ULONG             ulCount,
                                                            CK_OBJECT_HANDLE_PTR phObject)
{
    return createObject(hSession, pTemplate, ulCount, phObject);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CopyObject(CK_SESSION_HANDLE    hSession,
                                                          CK_OBJECT_HANDLE     hObject,
                                                          CK_ATTRIBUTE_PTR     pTemplate,
                                                          CK_ULONG             ulCount,
                                                          CK_OBJECT_HANDLE_PTR phNewObject)
{
    return copyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    return getObjectSize(hSession, hObject, pulSize);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                                                 CK_OBJECT_HANDLE  hObject,
                                                                 CK_ATTRIBUTE_PTR  pTemplate,
                                                                 CK_ULONG          ulCount)
{
    return getAttributeValue(hSession, hObject, pTemplate, ulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                                                 CK_OBJECT_HANDLE  hObject,
                                                                 CK_ATTRIBUTE_PTR  pTemplate,
                                                                 CK_ULONG          ulCount)
{
    return setAttributeValue(hSession, hObject, pTemplate, ulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                                               CK_ATTRIBUTE_PTR  pTemplate,
                                                               CK_ULONG          ulCount)
{
    return findObjectsInit(hSession, pTemplate, ulCount);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_FindObjects(CK_SESSION_HANDLE    hSession,
                                                           CK_OBJECT_HANDLE_PTR phObject,
                                                           CK_ULONG             ulMaxObjectCount,
                                                           CK_ULONG_PTR         pulObjectCount)
{
    return findObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    return findObjectsFinal(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DestroyObject(CK_SESSION_HANDLE hSession,
                                                             CK_OBJECT_HANDLE  hKey)
{
    return destroyObject(hSession, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    return getFunctionStatus(hSession);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    return digestKey(hSession, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return signUpdate(hSession, pPart, ulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return signFinal(hSession, pSignature, pulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return signRecoverInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return signRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return verifyUpdate(hSession, pPart, ulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return verifyFinal(hSession, pSignature, ulSignatureLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return verifyRecoverInit(hSession, pMechanism, hKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return verifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return digestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return decryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return signEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return decryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,  CK_OBJECT_HANDLE_PTR phKey)
{
    return deriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    return seedRandom(hSession, pSeed, ulSeedLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    return generateRandom(hSession, pRandomData, ulRandomLen);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    return cancelFunction(hSession);
}
