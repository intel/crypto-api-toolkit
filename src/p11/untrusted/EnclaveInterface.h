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

#ifndef ENCLAVE_INTERFACE_H
#define ENCLAVE_INTERFACE_H

#include <cstdint>
#include <cstddef>

#include "cryptoki.h"

namespace EnclaveInterface
{
    bool loadEnclave();
    void unloadEnclave();

    //---------------------------------------------------------------------------------------------
    bool eIsInitialized(CK_VOID_PTR pInitArgs);

    //---------------------------------------------------------------------------------------------
    CK_RV initialize(CK_VOID_PTR pInitArgs);

    //---------------------------------------------------------------------------------------------
    CK_RV finalize(CK_VOID_PTR pReserved);

    //---------------------------------------------------------------------------------------------
    CK_RV getInfo(CK_INFO_PTR pInfo);

    //---------------------------------------------------------------------------------------------
    CK_RV getSlotList(CK_BBOOL       tokenPresent,
                      CK_SLOT_ID_PTR pSlotList,
                      CK_ULONG_PTR   pulCount);

    //---------------------------------------------------------------------------------------------
    CK_RV getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);

    //---------------------------------------------------------------------------------------------
    CK_RV encryptInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR  pMechanism,
                      CK_OBJECT_HANDLE  hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV encryptUpdate(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR       pData,
                        CK_ULONG          ulDataLen,
                        CK_BYTE_PTR       pEncryptedData,
                        CK_ULONG_PTR      pulEncryptedDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV encrypt(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR       pData,
                  CK_ULONG          ulDataLen,
                  CK_BYTE_PTR       pEncryptedData,
                  CK_ULONG_PTR      pulEncryptedDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV encryptFinal(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR       pEncryptedData,
                       CK_ULONG_PTR      pulEncryptedDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV decryptInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR  pMechanism,
                      CK_OBJECT_HANDLE  hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV decrypt(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR       pEncryptedData,
                  CK_ULONG          ulEncryptedDataLen,
                  CK_BYTE_PTR       pData,
                  CK_ULONG_PTR      pulDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV decryptUpdate(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR       pEncryptedData,
                        CK_ULONG          ulEncryptedDataLen,
                        CK_BYTE_PTR       pData,
                        CK_ULONG_PTR      pDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV decryptFinal(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR       pData,
                       CK_ULONG_PTR      pDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV digestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);

    //---------------------------------------------------------------------------------------------
    CK_RV digest(CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR       pData,
                 CK_ULONG          ulDataLen,
                 CK_BYTE_PTR       pDigest,
                 CK_ULONG_PTR      pulDigestLen);


    //---------------------------------------------------------------------------------------------
    CK_RV digestUpdate(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR       pPart,
                       CK_ULONG          ulPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV digestFinal(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR       pDigest,
                      CK_ULONG_PTR      pulDigestLen);

    //---------------------------------------------------------------------------------------------
    CK_RV signInit(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR  pMechanism,
                   CK_OBJECT_HANDLE  hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV sign(CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR       pData,
               CK_ULONG          ulDataLen,
               CK_BYTE_PTR       pSignature,
               CK_ULONG_PTR      pulSignatureLen);

    //---------------------------------------------------------------------------------------------
    CK_RV verifyInit(CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_PTR  pMechanism,
                     CK_OBJECT_HANDLE  hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV verify(CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR       pData,
                 CK_ULONG          ulDataLen,
                 CK_BYTE_PTR       pSignature,
                 CK_ULONG          ulSignatureLen);

    //---------------------------------------------------------------------------------------------
    CK_RV generateKey(CK_SESSION_HANDLE    hSession,
                      CK_MECHANISM_PTR     pMechanism,
                      CK_ATTRIBUTE_PTR     pTemplate,
                      CK_ULONG             ulCount,
                      unsigned long int* phKey);

    //---------------------------------------------------------------------------------------------
    CK_RV generateKeyPair(CK_SESSION_HANDLE    hSession,
                          CK_MECHANISM_PTR     pMechanism,
                          CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
                          CK_ULONG             ulPublicKeyAttributeCount,
                          CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
                          CK_ULONG             ulPrivateKeyAttributeCount,
                          unsigned long int* phPublicKey,
                          unsigned long int* phPrivateKey);

    //---------------------------------------------------------------------------------------------
    CK_RV wrapKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR  pMechanism,
                  CK_OBJECT_HANDLE  hWrappingKey,
                  CK_OBJECT_HANDLE  hKey,
                  CK_BYTE_PTR       pWrappedKey,
                  CK_ULONG_PTR      pulWrappedKeyLen);

    //---------------------------------------------------------------------------------------------
    CK_RV unwrapKey(CK_SESSION_HANDLE    hSession,
                    CK_MECHANISM_PTR     pMechanism,
                    CK_OBJECT_HANDLE     hUnwrappingKey,
                    CK_BYTE_PTR          pWrappedKey,
                    CK_ULONG             ulWrappedKeyLen,
                    CK_ATTRIBUTE_PTR     pTemplate,
                    CK_ULONG             ulCount,
                    CK_OBJECT_HANDLE_PTR hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV getTokenInfo(CK_SLOT_ID        slotID,
                       CK_TOKEN_INFO_PTR pInfo);

    //---------------------------------------------------------------------------------------------
    CK_RV waitForSlotEvent(CK_FLAGS       flags,
                           CK_SLOT_ID_PTR pSlot,
                           CK_VOID_PTR    pReserved);

    //---------------------------------------------------------------------------------------------
    CK_RV getMechanismInfo(CK_SLOT_ID            slotID,
                           CK_MECHANISM_TYPE     type,
                           CK_MECHANISM_INFO_PTR pInfo);

    //---------------------------------------------------------------------------------------------
    CK_RV getMechanismList(CK_SLOT_ID            slotID,
                           CK_MECHANISM_TYPE_PTR pMechanismList,
                           CK_ULONG_PTR          pulCount);

    //---------------------------------------------------------------------------------------------
    CK_RV initToken(CK_SLOT_ID      slotID,
                    CK_UTF8CHAR_PTR pPin,
                    CK_ULONG        ulPinLen,
                    CK_UTF8CHAR_PTR pLabel);

    //---------------------------------------------------------------------------------------------
    CK_RV initPIN(CK_SESSION_HANDLE hSession,
                  CK_UTF8CHAR_PTR   pPin,
                  CK_ULONG          ulPinLen);

    //---------------------------------------------------------------------------------------------
    CK_RV setPIN(CK_SESSION_HANDLE hSession,
                 CK_UTF8CHAR_PTR   pOldPin,
                 CK_ULONG          ulOldLen,
                 CK_UTF8CHAR_PTR   pNewPin,
                 CK_ULONG          ulNewLen);

    //---------------------------------------------------------------------------------------------
    CK_RV openSession(CK_SLOT_ID            slotID,
                      CK_FLAGS              flags,
                      CK_VOID_PTR           pApplication,
                      CK_NOTIFY             notify,
                      CK_SESSION_HANDLE_PTR phSession);

    //---------------------------------------------------------------------------------------------
    CK_RV  closeSession(CK_SESSION_HANDLE hSession);

    //---------------------------------------------------------------------------------------------
    CK_RV closeAllSessions(CK_SLOT_ID slotID);

    //---------------------------------------------------------------------------------------------
    CK_RV getSessionInfo(CK_SESSION_HANDLE   hSession, CK_SESSION_INFO_PTR pInfo);

    //---------------------------------------------------------------------------------------------
    CK_RV getOperationState(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR       pOperationState,
                            CK_ULONG_PTR      pulOperationStateLen);

    //---------------------------------------------------------------------------------------------
    CK_RV setOperationState(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR       pOperationState,
                            CK_ULONG          ulOperationStateLen,
                            CK_OBJECT_HANDLE  hEncryptionKey,
                            CK_OBJECT_HANDLE  hAuthenticationKey);

    //---------------------------------------------------------------------------------------------
    CK_RV login(CK_SESSION_HANDLE hSession,
                CK_USER_TYPE      userType,
                CK_UTF8CHAR_PTR   pPin,
                CK_ULONG          ulPinLen);

    //---------------------------------------------------------------------------------------------
    CK_RV logout(CK_SESSION_HANDLE hSession);

    //---------------------------------------------------------------------------------------------
    CK_RV createObject(CK_SESSION_HANDLE    hSession,
                       CK_ATTRIBUTE_PTR     pTemplate,
                       CK_ULONG             ulCount,
                       CK_OBJECT_HANDLE_PTR phObject);

    //---------------------------------------------------------------------------------------------
    CK_RV copyObject(CK_SESSION_HANDLE    hSession,
                     CK_OBJECT_HANDLE     hObject,
                     CK_ATTRIBUTE_PTR     pTemplate,
                     CK_ULONG             ulCount,
                     CK_OBJECT_HANDLE_PTR phNewObject);

    //---------------------------------------------------------------------------------------------
    CK_RV getObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);

    //---------------------------------------------------------------------------------------------
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE  hObject,
                            CK_ATTRIBUTE_PTR  pTemplate,
                            CK_ULONG          ulCount);

    //---------------------------------------------------------------------------------------------
    CK_RV setAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE  hObject,
                            CK_ATTRIBUTE_PTR  pTemplate,
                            CK_ULONG          ulCount);

    //---------------------------------------------------------------------------------------------
    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession,
                          CK_ATTRIBUTE_PTR  pTemplate,
                          CK_ULONG          ulCount);

    //---------------------------------------------------------------------------------------------
    CK_RV findObjects(CK_SESSION_HANDLE    hSession,
                      CK_OBJECT_HANDLE_PTR phObject,
                      CK_ULONG             ulMaxObjectCount,
                      CK_ULONG_PTR         pulObjectCount);

    //---------------------------------------------------------------------------------------------
    CK_RV findObjectsFinal(CK_SESSION_HANDLE hSession);

    //---------------------------------------------------------------------------------------------
    CK_RV destroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE  hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV getFunctionStatus(CK_SESSION_HANDLE hSession);

    //---------------------------------------------------------------------------------------------
    CK_RV digestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

    //---------------------------------------------------------------------------------------------
    CK_RV signUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV signFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

    //---------------------------------------------------------------------------------------------
    CK_RV signRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV signRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

    //---------------------------------------------------------------------------------------------
    CK_RV verifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV verifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

    //---------------------------------------------------------------------------------------------
    CK_RV verifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

    //---------------------------------------------------------------------------------------------
    CK_RV verifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

    //---------------------------------------------------------------------------------------------
    CK_RV digestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV decryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV signEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV decryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

    //---------------------------------------------------------------------------------------------
    CK_RV deriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,  CK_OBJECT_HANDLE_PTR phKey);

    //---------------------------------------------------------------------------------------------
    CK_RV seedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);

    //---------------------------------------------------------------------------------------------
    CK_RV generateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

    //---------------------------------------------------------------------------------------------
    CK_RV cancelFunction(CK_SESSION_HANDLE hSession);
}

#endif
