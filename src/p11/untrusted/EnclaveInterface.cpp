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

#include "EnclaveInterface.h"
#include "EnclaveHelpers.h"

#include "p11Enclave_u.h"

namespace EnclaveInterface
{
    //---------------------------------------------------------------------------------------------
    bool loadEnclave()
    {
        P11Crypto::EnclaveHelpers enclaveHelpers;

        if (!enclaveHelpers.isSgxEnclaveLoaded())
        {
            if (sgx_status_t::SGX_SUCCESS != enclaveHelpers.loadSgxEnclave())
            {
                return false;
            }
        }

        return true;
    }

    //---------------------------------------------------------------------------------------------
    void unloadEnclave()
    {
        P11Crypto::EnclaveHelpers enclaveHelpers;

        if (enclaveHelpers.isSgxEnclaveLoaded())
        {
            enclaveHelpers.unloadSgxEnclave();
        }
    }

    //---------------------------------------------------------------------------------------------
    bool eIsInitialized(CK_VOID_PTR pInitArgs)
    {
        bool           retValue      = true;
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Initialize(enclaveHelpers.getSgxEnclaveId(),
                                     &rv,
                                     pInitArgs);

        if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
        {
            __sync_lock_test_and_set(&enclaveHelpers.mSgxEnclaveLoadedCount, 0);
            retValue = false;
        }

        return retValue;
    }


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
    CK_RV initialize(CK_VOID_PTR pInitArgs)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Initialize(enclaveHelpers.getSgxEnclaveId(),
                                    &rv,
                                    pInitArgs);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV finalize(CK_VOID_PTR pReserved)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Finalize(enclaveHelpers.getSgxEnclaveId(),
                                   &rv,
                                   pReserved);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getInfo(CK_INFO_PTR pInfo)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetInfo(enclaveHelpers.getSgxEnclaveId(),
                                  &rv,
                                  pInfo);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getSlotList(CK_BBOOL          tokenPresent,
                      CK_SLOT_ID_PTR    pSlotList,
                      CK_ULONG_PTR      pulCount)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetSlotList(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      tokenPresent,
                                      pSlotList,
                                      pulCount);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetSlotInfo(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      slotID,
                                      pInfo);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV encryptInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR  pMechanism,
                      CK_OBJECT_HANDLE  hKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_EncryptInit(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pMechanism,
                                      hKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV encryptUpdate(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR       pData,
                        CK_ULONG          ulDataLen,
                        CK_BYTE_PTR       pEncryptedData,
                        CK_ULONG_PTR      pulEncryptedDataLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_EncryptUpdate(enclaveHelpers.getSgxEnclaveId(),
                                        &rv,
                                        hSession,
                                        pData,
                                        ulDataLen,
                                        pEncryptedData,
                                        pulEncryptedDataLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV encrypt(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR       pData,
                  CK_ULONG          ulDataLen,
                  CK_BYTE_PTR       pEncryptedData,
                  CK_ULONG_PTR      pulEncryptedDataLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Encrypt(enclaveHelpers.getSgxEnclaveId(),
                                  &rv,
                                  hSession,
                                  pData,
                                  ulDataLen,
                                  pEncryptedData,
                                  pulEncryptedDataLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV encryptFinal(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR       pEncryptedData,
                       CK_ULONG_PTR      pulEncryptedDataLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_EncryptFinal(enclaveHelpers.getSgxEnclaveId(),
                                       &rv,
                                       hSession,
                                       pEncryptedData,
                                       pulEncryptedDataLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV decryptInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR  pMechanism,
                      CK_OBJECT_HANDLE  hKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DecryptInit(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pMechanism,
                                      hKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV decrypt(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR       pEncryptedData,
                  CK_ULONG          ulEncryptedDataLen,
                  CK_BYTE_PTR       pData,
                  CK_ULONG_PTR      pulDataLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Decrypt(enclaveHelpers.getSgxEnclaveId(),
                                  &rv,
                                  hSession,
                                  pEncryptedData,
                                  ulEncryptedDataLen,
                                  pData,
                                  pulDataLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV decryptUpdate(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR       pEncryptedData,
                        CK_ULONG          ulEncryptedDataLen,
                        CK_BYTE_PTR       pData,
                        CK_ULONG_PTR      pDataLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DecryptUpdate(enclaveHelpers.getSgxEnclaveId(),
                                        &rv,
                                        hSession,
                                        pEncryptedData,
                                        ulEncryptedDataLen,
                                        pData,
                                        pDataLen);
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV decryptFinal(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR       pData,
                       CK_ULONG_PTR      pDataLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DecryptFinal(enclaveHelpers.getSgxEnclaveId(),
                                       &rv,
                                       hSession,
                                       pData,
                                       pDataLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV digestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DigestInit(enclaveHelpers.getSgxEnclaveId(),
                                       &rv,
                                       hSession,
                                       pMechanism);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV digest(CK_SESSION_HANDLE  hSession,
                 CK_BYTE_PTR        pData,
                 CK_ULONG           ulDataLen,
                 CK_BYTE_PTR        pDigest,
                 CK_ULONG_PTR       pulDigestLen)

    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Digest(enclaveHelpers.getSgxEnclaveId(),
                                 &rv,
                                 hSession,
                                 pData,
                                 ulDataLen,
                                 pDigest,
                                 pulDigestLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV digestUpdate(CK_SESSION_HANDLE    hSession,
                       CK_BYTE_PTR          pPart,
                       CK_ULONG             ulPartLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DigestUpdate(enclaveHelpers.getSgxEnclaveId(),
                                       &rv,
                                       hSession,
                                       pPart,
                                       ulPartLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV digestFinal(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR       pDigest,
                      CK_ULONG_PTR      pulDigestLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DigestFinal(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pDigest,
                                      pulDigestLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV signInit(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR  pMechanism,
                   CK_OBJECT_HANDLE  hKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SignInit(enclaveHelpers.getSgxEnclaveId(),
                                   &rv,
                                   hSession,
                                   pMechanism,
                                   hKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV sign(CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR       pData,
               CK_ULONG          ulDataLen,
               CK_BYTE_PTR       pSignature,
               CK_ULONG_PTR      pulSignatureLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Sign(enclaveHelpers.getSgxEnclaveId(),
                               &rv,
                               hSession,
                               pData,
                               ulDataLen,
                               pSignature,
                               pulSignatureLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV verifyInit(CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_PTR  pMechanism,
                     CK_OBJECT_HANDLE  hKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_VerifyInit(enclaveHelpers.getSgxEnclaveId(),
                                     &rv,
                                     hSession,
                                     pMechanism,
                                     hKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV verify(CK_SESSION_HANDLE hSession,
                                                        CK_BYTE_PTR       pData,
                                                        CK_ULONG          ulDataLen,
                                                        CK_BYTE_PTR       pSignature,
                                                        CK_ULONG          ulSignatureLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Verify(enclaveHelpers.getSgxEnclaveId(),
                                 &rv,
                                 hSession,
                                 pData,
                                 ulDataLen,
                                 pSignature,
                                 ulSignatureLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV generateKey(CK_SESSION_HANDLE     hSession,
                      CK_MECHANISM_PTR      pMechanism,
                      CK_ATTRIBUTE_PTR      pTemplate,
                      CK_ULONG              ulCount,
                      unsigned long int*    phKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GenerateKey(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pMechanism,
                                      pTemplate,
                                      ulCount,
                                      phKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV generateKeyPair(CK_SESSION_HANDLE     hSession,
                          CK_MECHANISM_PTR      pMechanism,
                          CK_ATTRIBUTE_PTR      pPublicKeyTemplate,
                          CK_ULONG              ulPublicKeyAttributeCount,
                          CK_ATTRIBUTE_PTR      pPrivateKeyTemplate,
                          CK_ULONG              ulPrivateKeyAttributeCount,
                          unsigned long int*    phPublicKey,
                          unsigned long int*    phPrivateKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GenerateKeyPair(enclaveHelpers.getSgxEnclaveId(),
                                          &rv,
                                          hSession,
                                          pMechanism,
                                          pPublicKeyTemplate,
                                          ulPublicKeyAttributeCount,
                                          pPrivateKeyTemplate,
                                          ulPrivateKeyAttributeCount,
                                          phPublicKey,
                                          phPrivateKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV wrapKey(CK_SESSION_HANDLE hSession,
                                                        CK_MECHANISM_PTR  pMechanism,
                                                        CK_OBJECT_HANDLE  hWrappingKey,
                                                        CK_OBJECT_HANDLE  hKey,
                                                        CK_BYTE_PTR       pWrappedKey,
                                                        CK_ULONG_PTR      pulWrappedKeyLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_WrapKey(enclaveHelpers.getSgxEnclaveId(),
                                  &rv,
                                  hSession,
                                  pMechanism,
                                  hWrappingKey,
                                  hKey,
                                  pWrappedKey,
                                  pulWrappedKeyLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV unwrapKey(CK_SESSION_HANDLE    hSession,
                    CK_MECHANISM_PTR     pMechanism,
                    CK_OBJECT_HANDLE     hUnwrappingKey,
                    CK_BYTE_PTR          pWrappedKey,
                    CK_ULONG             ulWrappedKeyLen,
                    CK_ATTRIBUTE_PTR     pTemplate,
                    CK_ULONG             ulCount,
                    CK_OBJECT_HANDLE_PTR hKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_UnwrapKey(enclaveHelpers.getSgxEnclaveId(),
                                    &rv,
                                    hSession,
                                    pMechanism,
                                    hUnwrappingKey,
                                    pWrappedKey,
                                    ulWrappedKeyLen,
                                    pTemplate,
                                    ulCount,
                                    hKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getTokenInfo(CK_SLOT_ID        slotID,
                       CK_TOKEN_INFO_PTR pInfo)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetTokenInfo(enclaveHelpers.getSgxEnclaveId(),
                                       &rv,
                                       slotID,
                                       pInfo);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV waitForSlotEvent(CK_FLAGS       flags,
                           CK_SLOT_ID_PTR pSlot,
                           CK_VOID_PTR    pReserved)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_WaitForSlotEvent(enclaveHelpers.getSgxEnclaveId(),
                                           &rv,
                                           flags,
                                           pSlot,
                                           pReserved);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getMechanismInfo(CK_SLOT_ID            slotID,
                           CK_MECHANISM_TYPE     type,
                           CK_MECHANISM_INFO_PTR pInfo)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetMechanismInfo(enclaveHelpers.getSgxEnclaveId(),
                                           &rv,
                                           slotID,
                                           type,
                                           pInfo);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getMechanismList(CK_SLOT_ID            slotID,
                            CK_MECHANISM_TYPE_PTR pMechanismList,
                            CK_ULONG_PTR          pulCount)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetMechanismList(enclaveHelpers.getSgxEnclaveId(),
                                           &rv,
                                           slotID,
                                           pMechanismList,
                                           pulCount);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV initToken(CK_SLOT_ID      slotID,
                    CK_UTF8CHAR_PTR pPin,
                    CK_ULONG        ulPinLen,
                    CK_UTF8CHAR_PTR pLabel)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_InitToken(enclaveHelpers.getSgxEnclaveId(),
                                    &rv,
                                    slotID,
                                    pPin,
                                    ulPinLen,
                                    pLabel);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV initPIN(CK_SESSION_HANDLE hSession,
                  CK_UTF8CHAR_PTR   pPin,
                  CK_ULONG          ulPinLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_InitPIN(enclaveHelpers.getSgxEnclaveId(),
                                  &rv,
                                  hSession,
                                  pPin,
                                  ulPinLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV setPIN(CK_SESSION_HANDLE hSession,
                 CK_UTF8CHAR_PTR   pOldPin,
                 CK_ULONG          ulOldLen,
                 CK_UTF8CHAR_PTR   pNewPin,
                 CK_ULONG          ulNewLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SetPIN(enclaveHelpers.getSgxEnclaveId(),
                                 &rv,
                                 hSession,
                                 pOldPin,
                                 ulOldLen,
                                 pNewPin,
                                 ulNewLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV openSession(CK_SLOT_ID            slotID,
                      CK_FLAGS              flags,
                      CK_VOID_PTR           pApplication,
                      CK_NOTIFY             notify,
                      CK_SESSION_HANDLE_PTR phSession)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_OpenSession(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      slotID,
                                      flags,
                                      pApplication,
                                      notify,
                                      phSession);
        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV  closeSession(CK_SESSION_HANDLE hSession)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_CloseSession(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV closeAllSessions(CK_SLOT_ID slotID)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_CloseAllSessions(enclaveHelpers.getSgxEnclaveId(),
                                           &rv,
                                           slotID);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getSessionInfo(CK_SESSION_HANDLE   hSession,
                                                                CK_SESSION_INFO_PTR pInfo)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetSessionInfo(enclaveHelpers.getSgxEnclaveId(),
                                         &rv,
                                         hSession,
                                         pInfo);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getOperationState(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR       pOperationState,
                            CK_ULONG_PTR      pulOperationStateLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetOperationState(enclaveHelpers.getSgxEnclaveId(),
                                            &rv,
                                            hSession,
                                            pOperationState,
                                            pulOperationStateLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV setOperationState(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR       pOperationState,
                            CK_ULONG          ulOperationStateLen,
                            CK_OBJECT_HANDLE  hEncryptionKey,
                            CK_OBJECT_HANDLE  hAuthenticationKey)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SetOperationState(enclaveHelpers.getSgxEnclaveId(),
                                            &rv,
                                            hSession,
                                            pOperationState,
                                            ulOperationStateLen,
                                            hEncryptionKey,
                                            hAuthenticationKey);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV login(CK_SESSION_HANDLE hSession,
                CK_USER_TYPE      userType,
                CK_UTF8CHAR_PTR   pPin,
                CK_ULONG          ulPinLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Login(enclaveHelpers.getSgxEnclaveId(),
                                &rv,
                                hSession,
                                userType,
                                pPin,
                                ulPinLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV logout(CK_SESSION_HANDLE hSession)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_Logout(enclaveHelpers.getSgxEnclaveId(),
                                  &rv,
                                  hSession);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV createObject(CK_SESSION_HANDLE    hSession,
                                                                CK_ATTRIBUTE_PTR     pTemplate,
                                                                CK_ULONG             ulCount,
                                                                CK_OBJECT_HANDLE_PTR phObject)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_CreateObject(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pTemplate,
                                      ulCount,
                                      phObject);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV copyObject(CK_SESSION_HANDLE    hSession,
                     CK_OBJECT_HANDLE     hObject,
                     CK_ATTRIBUTE_PTR     pTemplate,
                     CK_ULONG             ulCount,
                     CK_OBJECT_HANDLE_PTR phNewObject)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_CopyObject(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      hObject,
                                      pTemplate,
                                      ulCount,
                                      phNewObject);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetObjectSize(enclaveHelpers.getSgxEnclaveId(),
                                        &rv,
                                        hSession,
                                        hObject,
                                        pulSize);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE  hObject,
                            CK_ATTRIBUTE_PTR  pTemplate,
                            CK_ULONG          ulCount)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetAttributeValue(enclaveHelpers.getSgxEnclaveId(),
                                            &rv,
                                            hSession,
                                            hObject,
                                            pTemplate,
                                            ulCount);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV setAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE  hObject,
                            CK_ATTRIBUTE_PTR  pTemplate,
                            CK_ULONG          ulCount)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SetAttributeValue(enclaveHelpers.getSgxEnclaveId(),
                                            &rv,
                                            hSession,
                                            hObject,
                                            pTemplate,
                                            ulCount);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession,
                          CK_ATTRIBUTE_PTR  pTemplate,
                          CK_ULONG          ulCount)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_FindObjectsInit(enclaveHelpers.getSgxEnclaveId(),
                                          &rv,
                                          hSession,
                                          pTemplate,
                                          ulCount);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV findObjects(CK_SESSION_HANDLE    hSession,
                      CK_OBJECT_HANDLE_PTR phObject,
                      CK_ULONG             ulMaxObjectCount,
                      CK_ULONG_PTR         pulObjectCount)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_FindObjects(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      phObject,
                                      ulMaxObjectCount,
                                      pulObjectCount);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV findObjectsFinal(CK_SESSION_HANDLE hSession)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_FindObjectsFinal(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV destroyObject(CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hKey)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DestroyObject(enclaveHelpers.getSgxEnclaveId(),
                                        &rv,
                                        hSession,
                                        hKey);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV getFunctionStatus(CK_SESSION_HANDLE hSession)
    {
        CK_RV rv = CKR_FUNCTION_NOT_PARALLEL;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GetFunctionStatus(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV digestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DigestKey(enclaveHelpers.getSgxEnclaveId(),
                                    &rv,
                                    hSession,
                                    hKey);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV signUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SignUpdate(enclaveHelpers.getSgxEnclaveId(),
                                     &rv,
                                     hSession,
                                     pPart,
                                     ulPartLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV signFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SignFinal(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pSignature,
                                      pulSignatureLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV signRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SignRecoverInit(enclaveHelpers.getSgxEnclaveId(),
                                          &rv,
                                          hSession,
                                          pMechanism,
                                          hKey);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV signRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SignRecover(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pData,
                                      ulDataLen,
                                      pSignature,
                                      pulSignatureLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV verifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_VerifyUpdate(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pPart,
                                      ulPartLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV verifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_VerifyFinal(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pSignature,
                                      ulSignatureLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV verifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_VerifyRecoverInit(enclaveHelpers.getSgxEnclaveId(),
                                            &rv,
                                            hSession,
                                            pMechanism,
                                            hKey);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV verifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_VerifyRecover(enclaveHelpers.getSgxEnclaveId(),
                                        &rv,
                                        hSession,
                                        pSignature,
                                        ulSignatureLen,
                                        pData,
                                        pulDataLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV digestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DigestEncryptUpdate(enclaveHelpers.getSgxEnclaveId(),
                                              &rv,
                                              hSession,
                                              pPart,
                                              ulPartLen,
                                              pEncryptedPart,
                                              pulEncryptedPartLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV decryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DecryptDigestUpdate(enclaveHelpers.getSgxEnclaveId(),
                                              &rv,
                                              hSession,
                                              pPart,
                                              ulPartLen,
                                              pDecryptedPart,
                                              pulDecryptedPartLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV signEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SignEncryptUpdate(enclaveHelpers.getSgxEnclaveId(),
                                            &rv,
                                            hSession,
                                            pPart,
                                            ulPartLen,
                                            pEncryptedPart,
                                            pulEncryptedPartLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV decryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DecryptVerifyUpdate(enclaveHelpers.getSgxEnclaveId(),
                                              &rv,
                                              hSession,
                                              pEncryptedPart,
                                              ulEncryptedPartLen,
                                              pPart,
                                              pulPartLen);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV deriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,  CK_OBJECT_HANDLE_PTR phKey)
    {
        CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_DeriveKey(enclaveHelpers.getSgxEnclaveId(),
                                      &rv,
                                      hSession,
                                      pMechanism,
                                      hBaseKey,
                                      pTemplate,
                                      ulAttributeCount,
                                      phKey);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV seedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
    {
        CK_RV rv = CKR_RANDOM_SEED_NOT_SUPPORTED;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_SeedRandom(enclaveHelpers.getSgxEnclaveId(),
                                     &rv,
                                     hSession,
                                      pSeed,
                                      ulSeedLen,
                                      phKey);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV generateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
    {
        CK_RV          rv            = CKR_FUNCTION_FAILED;
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_GenerateRandom(enclaveHelpers.getSgxEnclaveId(),
                                         &rv,
                                         hSession,
                                         pRandomData,
                                         ulRandomLen);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV cancelFunction(CK_SESSION_HANDLE hSession)
    {
        CK_RV rv = CKR_FUNCTION_NOT_PARALLEL;
#if 0 // Unsupported by Crypto API Toolkit
        sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
        P11Crypto::EnclaveHelpers enclaveHelpers;

        sgxStatus = sgx_C_CancelFunction(enclaveHelpers.getSgxEnclaveId(),
                                         &rv,
                                         hSession);
#endif // Unsupported by Crypto API Toolkit

        return rv;
    }
}
