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

#include <memory>
#include <vector>
#include <mutex>
#include <string>
#include <dirent.h>
#include "EnclaveHelpers.h"
#include "CryptoEnclaveDefs.h"
#include "Constants.h"
#include "p11Enclave_u.h"
#include "SymmetricProvider.h"
#include "AsymmetricProvider.h"
#include "HashProvider.h"
#include "SymmetricKeyHandleCache.h"
#include "AsymmetricKeyHandleCache.h"
#include "HashHandleCache.h"
#include "SessionHandleCache.h"
#include "p11Defines.h"
#include "Slot.h"
#include "AttributeCache.h"

#define PKCS_API

using namespace P11Crypto;

std::shared_ptr<SymmetricProvider>        gSymmetricCrypto          = nullptr;
std::shared_ptr<AsymmetricProvider>       gAsymmetricCrypto         = nullptr;
std::shared_ptr<HashProvider>             gCryptoHash               = nullptr;
std::shared_ptr<SessionHandleCache>       gSessionHandleCache       = nullptr;
std::shared_ptr<SymmetricKeyHandleCache>  gSymmetricKeyHandleCache  = nullptr;
std::shared_ptr<AsymmetricKeyHandleCache> gAsymmetricKeyHandleCache = nullptr;
std::shared_ptr<HashHandleCache>          gHashHandleCache          = nullptr;
std::shared_ptr<AttributeCache>           gAttributeCache           = nullptr;

bool isInitialized = false;

std::mutex initializeMutex;
std::mutex finalizeMutex;
std::mutex getFunctionListMutex;
std::mutex initTokenMutex;
std::mutex openSessionMutex;
std::mutex closeSessionMutex;
std::mutex closeAllSessionsMutex;
std::mutex destroyObjectMutex;
std::mutex encryptInitMutex;
std::mutex encryptMutex;
std::mutex encryptUpdateMutex;
std::mutex encryptFinalMutex;
std::mutex decryptInitMutex;
std::mutex decryptMutex;
std::mutex decryptUpdateMutex;
std::mutex decryptFinalMutex;
std::mutex digestInitMutex;
std::mutex digestMutex;
std::mutex digestUpdateMutex;
std::mutex digestFinalMutex;
std::mutex signInitMutex;;
std::mutex signMutex;
std::mutex verifyInitMutex;
std::mutex verifyMutex;
std::mutex generateKeyMutex;
std::mutex generateKeyPairMutex;
std::mutex wrapKeyMutex;
std::mutex unwrapKeyMutex;
std::mutex getInfoMutex;
std::mutex getMechanismListMutex;
std::mutex getMechanismInfoMutex;
std::mutex getTokenInfoMutex;
std::mutex getSlotListMutex;
std::mutex getSlotInfoMutex;
std::mutex loginMutex;
std::mutex initPinMutex;
std::mutex logoutMutex;
std::mutex setPinMutex;
std::mutex getSessionInfoMutex;
std::mutex findObjectsInitMutex;
std::mutex findObjectsMutex;
std::mutex findObjectsFinalMutex;
std::mutex getAttributeValueMutex;
std::mutex setAttributeValueMutex;
std::mutex createObejctMutex;

// PKCS #11 function list
static CK_FUNCTION_LIST functionList =
{
    // Version information
    { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
    // Function pointers
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent
};

static CK_MECHANISM_TYPE supportedMechanisms[] =
{
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_AES_CTR,
    CKM_AES_GCM,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA512,
    CKM_SHA256_HMAC_AES_KEYID,
    CKM_SHA512_HMAC_AES_KEYID,
    CKM_AES_PBIND,
    CKM_RSA_PBIND_EXPORT,
    CKM_RSA_PBIND_IMPORT,
    CKM_EXPORT_RSA_PUBLIC_KEY,
    CKM_IMPORT_RSA_PUBLIC_KEY,
    CKM_EXPORT_QUOTE_RSA_PUBLIC_KEY
};

//---------------------------------------------------------------------------------------------
bool cleanUpRequired(const CK_RV& rv)
{
    bool result = true;

    switch(rv)
    {
        case CKR_OK:
        case CKR_SESSION_HANDLE_INVALID:
        case CKR_CRYPTOKI_NOT_INITIALIZED:
        case CKR_BUFFER_TOO_SMALL:
            result = false;
            break;
        default:
            result = true;
            break;
    }

    return result;
}

//---------------------------------------------------------------------------------------------
void cleanUpState(const uint32_t& keyId)
{
    sgx_status_t   sgxStatus     = sgx_status_t::SGX_ERROR_UNEXPECTED;
    SgxCryptStatus enclaveStatus = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
    EnclaveHelpers enclaveHelpers;

    if (gSymmetricKeyHandleCache && gSymmetricKeyHandleCache->find(keyId))
    {
        sgxStatus = clearCacheState(enclaveHelpers.getSgxEnclaveId(),
                                    reinterpret_cast<int32_t*>(&enclaveStatus),
                                    keyId);
    }
}

//---------------------------------------------------------------------------------------------
void resetSessionParameters(SessionParameters& sessionParameters, ActiveOperation activeOperation)
{
    switch(activeOperation)
    {
        case ActiveOperation::ENCRYPT:
            sessionParameters.encryptOperation                = SessionOperation::SESSION_OP_ENCRYPT_NONE;
            sessionParameters.encryptParams.blockCipherMode   = BlockCipherMode::unknown;
            sessionParameters.encryptParams.padding           = false;
            sessionParameters.encryptParams.keyHandle         = 0;
            sessionParameters.encryptParams.currentBufferSize = 0;
            sessionParameters.encryptParams.tagBytes          = 0;
            break;
        case ActiveOperation::DECRYPT:
            sessionParameters.decryptOperation                = SessionOperation::SESSION_OP_DECRYPT_NONE;
            sessionParameters.decryptParams.blockCipherMode   = BlockCipherMode::unknown;
            sessionParameters.decryptParams.padding           = false;
            sessionParameters.decryptParams.keyHandle         = 0;
            sessionParameters.decryptParams.currentBufferSize = 0;
            sessionParameters.decryptParams.tagBytes          = 0;
            break;
        case ActiveOperation::SIGN:
            sessionParameters.signOperation         = SessionOperation::SESSION_OP_SIGN_NONE;
            sessionParameters.signParams.rsaPadding = RsaPadding::rsaNoPadding;
            sessionParameters.signParams.keyHandle  = 0;
            sessionParameters.signParams.hashMode   = HashMode::invalid;
            break;
        case ActiveOperation::VERIFY:
            sessionParameters.verifyOperation         = SessionOperation::SESSION_OP_VERIFY_NONE;
            sessionParameters.verifyParams.rsaPadding = RsaPadding::rsaNoPadding;
            sessionParameters.verifyParams.keyHandle  = 0;
            sessionParameters.verifyParams.hashMode   = HashMode::invalid;
            break;
        case ActiveOperation::HASH:
            sessionParameters.hashOperation         = SessionOperation::SESSION_HASH_OP_NONE;
            sessionParameters.hashParams.hashMode   = HashMode::invalid;
            sessionParameters.hashParams.hashHandle = 0;
            break;
        default:
            break;
    }
}

// Return the list of PKCS #11 functions
PKCS_API CK_RV __attribute__((visibility("default"))) C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(getFunctionListMutex)> ulock(getFunctionListMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!ppFunctionList)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        *ppFunctionList = &functionList;

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) checkReadAccess(const CK_SESSION_HANDLE& hSession,
                                                            const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV        rv           = CKR_FUNCTION_FAILED;
    bool         isPrivate    = false;
    SessionState sessionState = SessionState::STATE_NONE;

    do
    {
        if (!gSessionHandleCache       ||
            !gSymmetricKeyHandleCache  ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (gSymmetricKeyHandleCache->find(hKey) ||
            gAsymmetricKeyHandleCache->find(hKey))
        {
            isPrivate = gAttributeCache->isPrivateObject(hKey);
        }
        else
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (!isPrivate) // All non private objects have read access, irrespective of any session state.
        {
            rv = CKR_OK;
            break;
        }

        sessionState = gSessionHandleCache->getSessionState(hSession);
        if (SessionState::RW_SO_STATE     == sessionState ||
            SessionState::RW_PUBLIC_STATE == sessionState ||
            SessionState::RO_PUBLIC_STATE == sessionState)
        {
            rv = CKR_USER_NOT_LOGGED_IN;
            break;
        }

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) hasWriteAccess(const CK_SESSION_HANDLE& hSession,
                                                           const bool&              isPrivate,
                                                           const bool&              isTokenObject)
{
    CK_RV        rv           = CKR_FUNCTION_FAILED;
    SessionState sessionState = SessionState::STATE_NONE;

    do
    {
        if (!gSessionHandleCache)
        {
            break;
        }

        sessionState = gSessionHandleCache->getSessionState(hSession);
        if (SessionState::RW_USER_STATE == sessionState)
        {
            rv = CKR_OK;
            break;
        }
        else if (SessionState::RW_PUBLIC_STATE == sessionState ||
                 SessionState::RW_SO_STATE     == sessionState)
        {
            if (isPrivate)
            {
                rv = CKR_USER_NOT_LOGGED_IN;
                break;
            }
        }
        else if (SessionState::RO_USER_STATE == sessionState)
        {
            if (isTokenObject)
            {
                rv = CKR_SESSION_READ_ONLY;
                break;
            }
        }
        else if (SessionState::RO_PUBLIC_STATE == sessionState)
        {
            if (isTokenObject)
            {
                rv = CKR_SESSION_READ_ONLY;
                break;
            }
            else
            {
                if (isPrivate)
                {
                    rv = CKR_USER_NOT_LOGGED_IN;
                    break;
                }
            }
        }

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) checkWriteAccess(const CK_SESSION_HANDLE& hSession,
                                                             const CK_ATTRIBUTE_PTR   pTemplate,
                                                             const CK_ULONG&          ulCount)
{
    CK_RV rv          = CKR_FUNCTION_FAILED;
    bool  isPrivate   = false;
    bool  tokenObject = false;

    do
    {
        for (CK_ULONG i = 0; i < ulCount; ++i)
        {
            switch (pTemplate[i].type)
            {
                case CKA_TOKEN:
                    if (pTemplate[i].pValue                         &&
                        sizeof(CK_BBOOL) == pTemplate[i].ulValueLen &&
                        CK_TRUE          == *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue))
                    {
                        tokenObject = true;
                    }
                    break;
                case CKA_PRIVATE:
                    if (pTemplate[i].pValue                         &&
                        sizeof(CK_BBOOL) == pTemplate[i].ulValueLen &&
                        CK_TRUE          == *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue))
                    {
                        isPrivate = true;
                    }
                    break;
            }
        }

        rv = hasWriteAccess(hSession, isPrivate, tokenObject);
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) checkWriteAccess(const CK_SESSION_HANDLE& hSession,
                                                             const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV rv          = CKR_FUNCTION_FAILED;
    bool  isPrivate   = false;
    bool  tokenObject = false;

    do
    {
        if (!gSymmetricKeyHandleCache  ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            break;
        }

        if (gSymmetricKeyHandleCache->find(hKey) ||
            gAsymmetricKeyHandleCache->find(hKey))
        {
            isPrivate   = gAttributeCache->isPrivateObject(hKey);
            tokenObject = gAttributeCache->isTokenObject(hKey);
        }
        else
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = hasWriteAccess(hSession, isPrivate, tokenObject);
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
/* Crypto API toolkit does not support application passed mutex locks.
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
    CK_RV          rv             = CKR_FUNCTION_FAILED;
    bool           allMutexesNull = true;
    sgx_status_t   sgxStatus      = sgx_status_t::SGX_ERROR_UNEXPECTED;
    EnclaveHelpers enclaveHelpers;

    std::unique_lock<decltype(initializeMutex)> ulock(initializeMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (isInitialized)
        {
            rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
            break;
        }

        if (pInitArgs)
        {
            CK_C_INITIALIZE_ARGS_PTR args;

            args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

            if (args->pReserved)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            // If CKF_LIBRARY_CANT_CREATE_OS_THREADS is set, the library shouldn't create its own threads.
            // Hence rejecting it.
            if (CKF_LIBRARY_CANT_CREATE_OS_THREADS & args->flags)
            {
                rv = CKR_NEED_TO_CREATE_THREADS;
                break;
            }

            if (args->CreateMutex  ||
                args->DestroyMutex ||
                args->LockMutex    ||
                args->UnlockMutex)
            {
                allMutexesNull = false;
            }

            // Rejecting if CKF_OS_LOCKING_OK is not set AND mutex locks are passed from application.
            if (!(CKF_OS_LOCKING_OK & args->flags) &&
                !allMutexesNull)
            {
                rv = CKR_CANT_LOCK;
                break;
            }

            rv = CKR_OK;
        }
        else
        {
            rv = CKR_OK;
        }
    } while (false);

    if (CKR_OK == rv)
    {
        isInitialized = true;

        if (!enclaveHelpers.isSgxEnclaveLoaded())
        {
            sgxStatus = enclaveHelpers.loadSgxEnclave(ProviderType::PKCS11);
            if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                isInitialized = false;
                rv            = CKR_DEVICE_ERROR;
            }
        }

        if (isInitialized)
        {
            // Initialize provider caches
            if (!gSessionHandleCache)
            {
                gSessionHandleCache = SessionHandleCache::getSessionHandleCache();
            }

            if (!gSymmetricCrypto)
            {
                gSymmetricCrypto = SymmetricProvider::getSymmetricProvider();
            }

            if (!gSymmetricKeyHandleCache)
            {
                gSymmetricKeyHandleCache = SymmetricKeyHandleCache::getSymmetricKeyHandleCache();
            }

            if (!gAsymmetricCrypto)
            {
                gAsymmetricCrypto = AsymmetricProvider::getAsymmetricProvider();
            }

            if (!gAsymmetricKeyHandleCache)
            {
                gAsymmetricKeyHandleCache = AsymmetricKeyHandleCache::getAsymmetricKeyHandleCache();
            }

            if (!gCryptoHash)
            {
                gCryptoHash = HashProvider::getHashProvider();
            }

            if (!gHashHandleCache)
            {
                gHashHandleCache = HashHandleCache::getHashHandleCache();
            }

            if (!gAttributeCache)
            {
                gAttributeCache = AttributeCache::getAttributeCache();
            }
        }
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Finalize(CK_VOID_PTR pReserved)
{
    CK_RV                   rv = CKR_FUNCTION_FAILED;
    EnclaveHelpers          enclaveHelpers;
    std::vector<CK_SLOT_ID> slotIDs;
    uint32_t                slotCount = 0;

    std::unique_lock<decltype(finalizeMutex)> ulock(finalizeMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (pReserved)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        // Clear provider caches..
        if (gSessionHandleCache)
        {
            // Remove all slot/token files used by this application..
            gSessionHandleCache->getAllSlotIDs(slotIDs);
            slotCount = slotIDs.size();

            for (auto i = 0; i < slotCount; i++)
            {
                Slot slot(slotIDs[i]);
                if (!slot.valid())
                {
                    rv = CKR_SLOT_ID_INVALID;
                    break;
                }

                Token* token = slot.getToken();
                if (!token)
                {
                    rv = CKR_TOKEN_NOT_PRESENT;
                    break;
                }

                rv = token->logOut();

                rv = token->finalize();
            }

            // Clear session handle cache..
            gSessionHandleCache->clear();
        }

        if (gSymmetricKeyHandleCache)
        {
            gSymmetricKeyHandleCache->clear();
        }

        if (gAsymmetricKeyHandleCache)
        {
            gAsymmetricKeyHandleCache->clear();
        }

        if (gHashHandleCache)
        {
            gHashHandleCache->clear();
        }

        // Destroy Enclave..
        enclaveHelpers.unloadSgxEnclave(ProviderType::PKCS11);

        isInitialized = false;

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_InitToken(CK_SLOT_ID        slotID,
                                                         CK_UTF8CHAR_PTR   pPin,
                                                         CK_ULONG          ulPinLen,
                                                         CK_UTF8CHAR_PTR   pLabel)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(initTokenMutex)> ulock(initTokenMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        if (!pPin || !pLabel)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (ulPinLen < minPinLength ||
            ulPinLen > maxPinLength)
        {
            rv = CKR_PIN_LEN_RANGE;
            break;
        }

        rv = slot.initToken(pPin, ulPinLen, pLabel);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_OpenSession(CK_SLOT_ID              slotID,
                                                           CK_FLAGS                flags,
                                                           CK_VOID_PTR             pApplication,
                                                           CK_NOTIFY               notify,
                                                           CK_SESSION_HANDLE_PTR   phSession)
{
    CK_RV                   rv              = CKR_FUNCTION_FAILED;
    sgx_status_t            sgxStatus       = sgx_status_t::SGX_ERROR_UNEXPECTED;
    SgxCryptStatus          enclaveStatus   = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
    uint32_t                sessionCount    = 0;
    SessionState            sessionState    = SessionState::STATE_NONE;
    EnclaveHelpers          enclaveHelpers;
    std::vector<uint32_t>   sessionHandlesInSlot;
    SessionParameters       sessionParameters{};

    std::unique_lock<decltype(openSessionMutex)> ulock(openSessionMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (!phSession   ||
            pApplication ||
            notify)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!(CKF_SERIAL_SESSION & flags))
        {
            rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
            break;
        }

        if (gSessionHandleCache->count() == maxSessionCount)
        {
            rv = CKR_SESSION_COUNT;
            break;
        }

        gSessionHandleCache->getSessionHandlesInSlot(slotID, sessionHandlesInSlot);
        sessionCount = sessionHandlesInSlot.size();

        if (!(CKF_RW_SESSION & flags))  // Open an RO session..
        {
            rv = CKR_OK;

            for (auto i = 0; i < sessionCount; i++)
            {
                sessionParameters = gSessionHandleCache->get(sessionHandlesInSlot[i]);

                // Any attempt to open RO session with already existing RWSO session should fail..
                if (SessionState::RW_SO_STATE == sessionParameters.sessionState)
                {
                    rv = CKR_SESSION_READ_WRITE_SO_EXISTS;
                    break;
                }
            }

            if (CKR_OK != rv)
            {
                break;
            }

            if (gSessionHandleCache->hasUserLoggedInROSession(slotID))
            {
                sessionState = SessionState::RO_USER_STATE;
            }
            else
            {
                sessionState = SessionState::RO_PUBLIC_STATE;
            }

        } // Open an RW session..
        else
        {
            if (gSessionHandleCache->hasSOLoggedInSession(slotID))
            {
                sessionState = SessionState::RW_SO_STATE;
            }
            else if (gSessionHandleCache->hasUserLoggedInRWSession(slotID))
            {
                sessionState = SessionState::RW_USER_STATE;
            }
            else
            {
                sessionState = SessionState::RW_PUBLIC_STATE;
            }
        }

        uint32_t sessionId = 0;

        sgxStatus = generateId(enclaveHelpers.getSgxEnclaveId(),
                               reinterpret_cast<int32_t*>(&enclaveStatus),
                               &sessionId);
        if (sgx_status_t::SGX_ERROR_ENCLAVE_LOST == sgxStatus)
        {
            rv = CKR_POWER_STATE_INVALID;
        }
        else if (sgx_status_t::SGX_SUCCESS != sgxStatus)
        {
            rv = CKR_GENERAL_ERROR;
        }
        else
        {
            rv = enclaveHelpers.enclaveStatusToPkcsStatus(enclaveStatus);
        }

        if (CKR_OK != rv)
        {
            break;
        }

        *phSession = sessionId;

        SessionParameters sessionParameters{};
        sessionParameters.slotID        = slotID;
        sessionParameters.sessionState  = sessionState;

        rv = token->addSession();
        if (CKR_OK != rv)
        {
            break;
        }

        gSessionHandleCache->add(*phSession, sessionParameters);
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV clearHandles(CK_SESSION_HANDLE& hSession)
{
    CK_RV    rv             = CKR_FUNCTION_FAILED;
    uint32_t keyHandleCount = 0;
    std::vector<uint32_t> keyHandles{};

    do
    {
        if (!gSymmetricCrypto           ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricCrypto          ||
            !gAsymmetricKeyHandleCache  ||
            !gCryptoHash                ||
            !gHashHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        // Get all symmetric key Ids in this session
        gSymmetricKeyHandleCache->getKeyHandlesInSession(hSession, keyHandles);

        // Delete all symmetric key Ids in this session
        keyHandleCount = keyHandles.size();
        for (auto i = 0; i < keyHandleCount; i++)
        {
            gSymmetricCrypto->destroyKey(keyHandles[i], gSymmetricKeyHandleCache);
        }

        // Get all asymmetric key Ids in this session
        keyHandles.clear();
        gAsymmetricKeyHandleCache->getKeyHandlesInSession(hSession, keyHandles);

        // Delete all asymmetric key Ids in this session
        keyHandleCount = keyHandles.size();
        for (auto i = 0; i < keyHandleCount; i++)
        {
            gAsymmetricCrypto->destroyKey(keyHandles[i], gAsymmetricKeyHandleCache);
        }

        // Get all hash key Ids in this session
        keyHandles.clear();
        gHashHandleCache->getHashHandlesInSession(hSession, keyHandles);

        // Delete all hash key Ids in this session
        keyHandleCount = keyHandles.size();
        for (auto i = 0; i < keyHandleCount; i++)
        {
            gCryptoHash->destroyHash(keyHandles[i], gHashHandleCache);
        }

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
bool logOutRequired(const CK_SESSION_HANDLE& hSession)
{
    if (!gSessionHandleCache)
    {
        return false;
    }

    CK_SLOT_ID slotID = gSessionHandleCache->getSlotID(hSession);

    return gSessionHandleCache->isLastSessionInSlot(slotID);
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CloseSession(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(closeSessionMutex)> ulock(closeSessionMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);

        Slot slot(sessionParameters.slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (SessionState::RW_SO_STATE   == sessionParameters.sessionState ||
            SessionState::RW_USER_STATE == sessionParameters.sessionState ||
            SessionState::RO_USER_STATE == sessionParameters.sessionState)
        {
            if (logOutRequired(hSession))
            {
                rv = C_Logout(hSession);
                if (CKR_OK != rv)
                {
                    break;
                }
            }
        }

        rv = token->removeSession();
        if (CKR_OK != rv)
        {
            break;
        }

        rv = clearHandles(hSession);
        if (CKR_OK != rv)
        {
            rv = token->addSession();
            break;
        }

        // Remove current session from session handle cache
        if (!gSessionHandleCache->remove(hSession))
        {
            rv = CKR_SESSION_CLOSED;
            break;
        }

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CloseAllSessions(CK_SLOT_ID slotID)
{
    CK_RV                   rv                  = CKR_FUNCTION_FAILED;
    uint32_t                sessionHandleCount  = 0;
    std::vector<uint32_t>   sessionHandles;

    std::unique_lock<decltype(closeAllSessionsMutex)> ulock(closeAllSessionsMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized    ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        sessionHandleCount = gSessionHandleCache->count();
        if (sessionHandleCount)
        {
            // Get all session handles in slotID from the cache
            gSessionHandleCache->getSessionHandlesInSlot(slotID, sessionHandles);
            uint32_t handleCount = sessionHandles.size();
            for (auto i = 0; i < handleCount; i++)   // Closing all the sessions in slotID
            {
                C_CloseSession(sessionHandles[i]);
            }
        }

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GenerateKey(CK_SESSION_HANDLE       hSession,
                                                           CK_MECHANISM_PTR        pMechanism,
                                                           CK_ATTRIBUTE_PTR        pTemplate,
                                                           CK_ULONG                ulCount,
                                                           CK_OBJECT_HANDLE_PTR    phKey)
{
    CK_RV      rv = CKR_FUNCTION_FAILED;
    Attributes keyAttributes;

    std::unique_lock<decltype(generateKeyMutex)> ulock(generateKeyMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized            ||
            !gSymmetricCrypto         ||
            !gSymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!phKey      ||
            !pMechanism ||
            !pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = checkWriteAccess(hSession, pTemplate, ulCount);
        if (CKR_OK != rv)
        {
            break;
        }

        if (CKM_AES_KEY_GEN != pMechanism->mechanism)
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        if (NULL_PTR != pMechanism->pParameter   ||
            0        != pMechanism->ulParameterLen)
        {
            rv = CKR_MECHANISM_PARAM_INVALID;
            break;
        }

        if (gSymmetricCrypto)
        {
            rv = gSymmetricCrypto->generateKey(hSession, pTemplate, ulCount, phKey, keyAttributes);
            if (CKR_OK != rv)
            {
                break;
            }

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

            SymmetricKey symKey{ sessionId };
            gSymmetricKeyHandleCache->add(*phKey, symKey);

            gAttributeCache->add(*phKey, keyAttributes);
        }
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static bool isSymmetricMechanism(const CK_MECHANISM_PTR pMechanism)
{
    bool result = false;

    if (!pMechanism)
    {
        return false;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_CTR:
        case CKM_AES_GCM:
            result = true;
            break;
        default:
            result = false;
            break;
    }

    return result;
}

//---------------------------------------------------------------------------------------------
static bool isAsymmetricMechanism(const CK_MECHANISM_PTR pMechanism)
{
    bool result = false;

    if (!pMechanism)
    {
        return false;
    }

    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS: // with implicit OAEP padding
        result = true;
        break;
    default:
        result = false;
        break;
    }
    return result;
}

//---------------------------------------------------------------------------------------------
static bool isSupportedSignVerifyMechanism(const CK_MECHANISM_PTR pMechanism)
{
    bool result = false;

    if (!pMechanism)
    {
        return false;
    }

    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        result = true;
        break;
    default:
        result = false;
        break;
    }
    return result;
}

//---------------------------------------------------------------------------------------------
auto __attribute__((visibility("hidden"))) isSupportedCounterBitsSize = [](const uint32_t& counterBits) -> bool
{
    return (counterBits >= minCounterBitsSupported) &&
           (counterBits <= maxCounterBitsSupported);
};

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) populateSymmetricMechanismParameters(const CK_MECHANISM_PTR pMechanism,
                                                                                 std::vector<uint8_t>&  iv,
                                                                                 std::vector<uint8_t>&  aad,
                                                                                 int&                   counterBits,
                                                                                 uint32_t&              tagBits,
                                                                                 uint32_t&              tagBytes,
                                                                                 bool&                  padding,
                                                                                 BlockCipherMode&       cipherMode)
{
    CK_RV    rv      = CKR_OK;
    CK_ULONG ctrBits = 0;

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    do
    {
        if (!pMechanism->pParameter)
        {
            rv = CKR_MECHANISM_PARAM_INVALID;
            break;
        }

        switch (pMechanism->mechanism)
        {
            case CKM_AES_CTR:
                if (sizeof(CK_AES_CTR_PARAMS) != pMechanism->ulParameterLen)
                {
                    rv = CKR_MECHANISM_PARAM_INVALID;
                    break;
                }

                ctrBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
                if (!isSupportedCounterBitsSize(ctrBits))
                {
                    rv = CKR_MECHANISM_PARAM_INVALID;
                    break;
                }

                counterBits = ctrBits;

                cipherMode = BlockCipherMode::ctr;
                iv.resize(16);
                memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
                break;
            case CKM_AES_GCM:
                if (pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
                {
                    rv = CKR_MECHANISM_PARAM_INVALID;
                    break;
                }

                iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
                memcpy(&iv[0],
                       CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv,
                       CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);

                aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
                memcpy(&aad[0],
                       CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                       CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);

                tagBits  = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
                tagBytes = tagBits >> 3;
                if (tagBytes < minTagSize ||
                    tagBytes > maxTagSize)
                {
                    rv = CKR_MECHANISM_PARAM_INVALID;
                    break;
                }

                cipherMode = BlockCipherMode::gcm;
                break;
            case CKM_AES_CBC:
                if (0 == pMechanism->ulParameterLen)
                {
                    rv = CKR_MECHANISM_PARAM_INVALID;
                    break;
                }

                iv.resize(pMechanism->ulParameterLen);
                memcpy(&iv[0],
                       pMechanism->pParameter,
                       pMechanism->ulParameterLen);

                cipherMode = BlockCipherMode::cbc;
                break;
            case CKM_AES_CBC_PAD:
                if (0 == pMechanism->ulParameterLen)
                {
                    rv = CKR_MECHANISM_PARAM_INVALID;
                    break;
                }

                iv.resize(pMechanism->ulParameterLen);
                memcpy(&iv[0],
                       pMechanism->pParameter,
                       pMechanism->ulParameterLen);

                padding = true;
                cipherMode = BlockCipherMode::cbc;
                break;
            default:
                rv = CKR_MECHANISM_INVALID;
                break;
        }
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesEncryptInit(const CK_SESSION_HANDLE& hSession,
                                                           const CK_MECHANISM_PTR   pMechanism,
                                                           const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV                   rv           = CKR_FUNCTION_FAILED;
    int                     counterBits  = 0;
    uint32_t                tagBits      = 0;
    uint32_t                tagBytes     = 0;
    bool                    padding      = false;
    std::vector<uint8_t>    iv;
    std::vector<uint8_t>    aad;
    BlockCipherMode         cipherMode{ BlockCipherMode::unknown };

    do
    {
        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSymmetricKeyHandleCache ||
            !gSymmetricCrypto         ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hKey) ||
            !gAttributeCache->isAttributeSet(hKey, KeyAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_ENCRYPT_NONE != sessionParameters.encryptOperation)
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        rv = populateSymmetricMechanismParameters(pMechanism,
                                                  iv,
                                                  aad,
                                                  counterBits,
                                                  tagBits,
                                                  tagBytes,
                                                  padding,
                                                  cipherMode);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = gSymmetricCrypto->encryptInit(hKey,
                                           iv.data(),
                                           iv.size(),
                                           aad.data(),
                                           aad.size(),
                                           static_cast<uint8_t>(cipherMode),
                                           padding,
                                           tagBits,
                                           counterBits);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.encryptOperation                = SessionOperation::SESSION_OP_SYMMETRIC_ENCRYPT_INIT;
        sessionParameters.encryptParams.keyHandle         = hKey;
        sessionParameters.encryptParams.currentBufferSize = 0;
        sessionParameters.encryptParams.blockCipherMode   = cipherMode;
        sessionParameters.encryptParams.padding           = padding;
        sessionParameters.encryptParams.tagBytes          = tagBytes;

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaEncryptInit(const CK_SESSION_HANDLE&   hSession,
                                                           const CK_OBJECT_HANDLE&    hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!gAsymmetricKeyHandleCache ||
            !gAsymmetricCrypto         ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey) ||
            !gAttributeCache->isAttributeSet(hKey, KeyAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_ENCRYPT_NONE != sessionParameters.encryptOperation)
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        sessionParameters.encryptOperation         = SessionOperation::SESSION_OP_ASYMMETRIC_ENCRYPT_INIT;
        sessionParameters.encryptParams.keyHandle  = hKey;

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_EncryptInit(CK_SESSION_HANDLE   hSession,
                                                           CK_MECHANISM_PTR    pMechanism,
                                                           CK_OBJECT_HANDLE    hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(encryptInitMutex)> ulock(encryptInitMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (isSymmetricMechanism(pMechanism))
        {
            if (!gSymmetricKeyHandleCache->find(hKey))
            {
                rv = CKR_KEY_HANDLE_INVALID;
                break;
            }

            rv = aesEncryptInit(hSession,
                                pMechanism,
                                hKey);

            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isAsymmetricMechanism(pMechanism))
        {
            if (!gAsymmetricKeyHandleCache->find(hKey))
            {
                rv = CKR_KEY_HANDLE_INVALID;
                break;
            }

            rv = rsaEncryptInit(hSession,
                                hKey);

            if (CKR_OK != rv)
            {
                break;
            }
        }
        else    // Unsupported mechanism passed
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesEncryptUpdate(const CK_SESSION_HANDLE&   hSession,
                                                             const CK_BYTE_PTR          pData,
                                                             const CK_ULONG&            ulDataLen,
                                                             CK_BYTE_PTR                pEncryptedData,
                                                             CK_ULONG_PTR               pulEncryptedDataLen,
                                                             SessionParameters&         sessionParameters)
{
    CK_RV       rv                  = CKR_FUNCTION_FAILED;
    uint32_t    keyHandle           = sessionParameters.encryptParams.keyHandle;
    uint32_t    destBufferRequired  = 0;
    uint32_t    destBufferLength    = 0;
    uint32_t    remainingSize       = sessionParameters.encryptParams.currentBufferSize;
    CK_ULONG    maxSize             = ulDataLen + remainingSize;

    do
    {
        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == sessionParameters.encryptParams.blockCipherMode)
        {
            int nrOfBlocks = (ulDataLen + remainingSize) / aesBlockSize;
            maxSize = nrOfBlocks * aesBlockSize;
        }
        else
        {
            maxSize = ulDataLen;
        }

        if (!pEncryptedData)
        {
            *pulEncryptedDataLen = maxSize;
            rv = CKR_OK;
            break;
        }

        if (*pulEncryptedDataLen < maxSize)
        {
            *pulEncryptedDataLen = maxSize;
            rv                   =  CKR_BUFFER_TOO_SMALL;
            break;
        }

        destBufferLength = *pulEncryptedDataLen;
        rv = gSymmetricCrypto->encryptUpdate(keyHandle,
                                             pData,
                                             ulDataLen,
                                             pEncryptedData,
                                             destBufferLength,
                                             destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.encryptParams.currentBufferSize += (ulDataLen - destBufferRequired);
        sessionParameters.encryptOperation                 = SESSION_OP_SYMMETRIC_ENCRYPT;

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        *pulEncryptedDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                                                             CK_BYTE_PTR       pData,
                                                             CK_ULONG          ulDataLen,
                                                             CK_BYTE_PTR       pEncryptedData,
                                                             CK_ULONG_PTR      pulEncryptedDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(encryptUpdateMutex)> ulock(encryptUpdateMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SYMMETRIC_ENCRYPT_INIT == sessionParameters.encryptOperation ||
            SessionOperation::SESSION_OP_SYMMETRIC_ENCRYPT      == sessionParameters.encryptOperation)
        {
            rv = aesEncryptUpdate(hSession,
                                  pData,
                                  ulDataLen,
                                  pEncryptedData,
                                  pulEncryptedDataLen,
                                  sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if(SessionOperation::SESSION_OP_ENCRYPT_NONE == sessionParameters.encryptOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.encryptParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::ENCRYPT);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesEncrypt(const CK_SESSION_HANDLE& hSession,
                                                       const CK_BYTE_PTR        pData,
                                                       const CK_ULONG&          ulDataLen,
                                                       CK_BYTE_PTR              pEncryptedData,
                                                       CK_ULONG_PTR             pulEncryptedDataLen,
                                                       SessionParameters&       sessionParameters)
{
    CK_RV       rv                  = CKR_FUNCTION_FAILED;
    uint32_t    keyHandle           = sessionParameters.encryptParams.keyHandle;;
    uint32_t    destBufferRequired  = 0;
    uint32_t    destBufferLength    = 0;
    uint32_t    encryptedBytes      = 0;
    CK_ULONG    maxSize             = ulDataLen;
    CK_ULONG    remainder           = ulDataLen % aesBlockSize;

    do
    {
        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == sessionParameters.encryptParams.blockCipherMode)
        {
            if (!sessionParameters.encryptParams.padding && remainder != 0)
            {
                rv = CKR_DATA_LEN_RANGE;
                break;
            }

            if (0 != remainder)
            {
                maxSize = ulDataLen + aesBlockSize - remainder;
            }
            else if (sessionParameters.encryptParams.padding)
            {
                maxSize = ulDataLen + aesBlockSize;
            }
        }
        else if (BlockCipherMode::ctr == sessionParameters.encryptParams.blockCipherMode)
        {
            maxSize = ulDataLen;
        }
        else if (BlockCipherMode::gcm == sessionParameters.encryptParams.blockCipherMode)
        {
            maxSize = ulDataLen + sessionParameters.encryptParams.tagBytes;
        }

        if (!pEncryptedData)
        {
            *pulEncryptedDataLen = maxSize;
            rv = CKR_OK;
            break;
        }

        if (*pulEncryptedDataLen < maxSize)
        {
            *pulEncryptedDataLen = maxSize;
            rv                   =  CKR_BUFFER_TOO_SMALL;
            break;
        }

        destBufferLength = *pulEncryptedDataLen;
        rv = gSymmetricCrypto->encryptUpdate(keyHandle,
                                             pData,
                                             ulDataLen,
                                             pEncryptedData,
                                             destBufferLength,
                                             destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        encryptedBytes      = destBufferRequired;
        destBufferRequired  = 0;

        rv = gSymmetricCrypto->encryptFinal(keyHandle,
                                            pEncryptedData + encryptedBytes,
                                            destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        encryptedBytes += destBufferRequired;

        resetSessionParameters(sessionParameters, ActiveOperation::ENCRYPT);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        *pulEncryptedDataLen = encryptedBytes;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaEncrypt(const CK_SESSION_HANDLE& hSession,
                                                       const CK_BYTE_PTR        pData,
                                                       const CK_ULONG&          ulDataLen,
                                                       CK_BYTE_PTR              pEncryptedData,
                                                       CK_ULONG_PTR             pulEncryptedDataLen,
                                                       SessionParameters&       sessionParameters)
{
    CK_RV       rv                  = CKR_FUNCTION_FAILED;
    uint32_t    keyHandle           = sessionParameters.encryptParams.keyHandle;
    uint32_t    destBufferRequired  = 0;
    uint32_t    destBufferLength    = 0;

    do
    {
        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLength = *pulEncryptedDataLen;
        rv = gAsymmetricCrypto->encrypt(keyHandle,
                                        pData,
                                        ulDataLen,
                                        pEncryptedData,
                                        destBufferLength,
                                        destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        if (!pEncryptedData)
        {
            *pulEncryptedDataLen = destBufferRequired;
            rv = CKR_OK;
            break;
        }

        resetSessionParameters(sessionParameters, ActiveOperation::ENCRYPT);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Encrypt(CK_SESSION_HANDLE   hSession,
                                                       CK_BYTE_PTR         pData,
                                                       CK_ULONG            ulDataLen,
                                                       CK_BYTE_PTR         pEncryptedData,
                                                       CK_ULONG_PTR        pulEncryptedDataLen)
{
    CK_RV             rv      = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(encryptMutex)> ulock(encryptMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSymmetricCrypto           ||
            !gAsymmetricCrypto          ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SYMMETRIC_ENCRYPT_INIT == sessionParameters.encryptOperation)
        {
            rv = aesEncrypt(hSession,
                            pData,
                            ulDataLen,
                            pEncryptedData,
                            pulEncryptedDataLen,
                            sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (SessionOperation::SESSION_OP_ASYMMETRIC_ENCRYPT_INIT == sessionParameters.encryptOperation)
        {
            rv = rsaEncrypt(hSession,
                            pData,
                            ulDataLen,
                            pEncryptedData,
                            pulEncryptedDataLen,
                            sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.encryptParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::ENCRYPT);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesEncryptFinal(const CK_SESSION_HANDLE&    hSession,
                                                            CK_BYTE_PTR                 pEncryptedData,
                                                            CK_ULONG_PTR                pulEncryptedDataLen,
                                                            SessionParameters&          sessionParameters)
{
    CK_RV           rv                  = CKR_FUNCTION_FAILED;
    uint32_t        remainingSize       = sessionParameters.encryptParams.currentBufferSize + sessionParameters.encryptParams.tagBytes;
    CK_ULONG        size                = remainingSize;
    uint32_t        keyHandle           = sessionParameters.encryptParams.keyHandle;
    BlockCipherMode cipherMode          = sessionParameters.encryptParams.blockCipherMode;
    uint32_t        destBufferRequired  = 0;

    do
    {
        if (!pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == cipherMode)
        {
            bool isPadding = sessionParameters.encryptParams.padding;
            if ((remainingSize % aesBlockSize) != 0 &&
                 !isPadding)
            {
                rv = CKR_DATA_LEN_RANGE;
                break;
            }
            size = isPadding ? ((remainingSize + aesBlockSize) / aesBlockSize) * aesBlockSize : remainingSize;
        }
        else if (BlockCipherMode::ctr == cipherMode)
        {
            size = 0;
        }
        else if (BlockCipherMode::gcm == cipherMode)
        {
            size = sessionParameters.encryptParams.tagBytes;
        }

        if (!pEncryptedData)
        {
            *pulEncryptedDataLen = size;
            rv = CKR_OK;
            break;
        }

        if (*pulEncryptedDataLen < size)
        {
            *pulEncryptedDataLen = size;
            rv                   = CKR_BUFFER_TOO_SMALL;
            break;
        }

        rv = gSymmetricCrypto->encryptFinal(keyHandle,
                                            pEncryptedData,
                                            destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        resetSessionParameters(sessionParameters, ActiveOperation::ENCRYPT);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        *pulEncryptedDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_EncryptFinal(CK_SESSION_HANDLE  hSession,
                                                            CK_BYTE_PTR        pEncryptedData,
                                                            CK_ULONG_PTR       pulEncryptedDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(encryptFinalMutex)> ulock(encryptFinalMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache    ||
            !gSymmetricCrypto       ||
            !gSymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SYMMETRIC_ENCRYPT == sessionParameters.encryptOperation)
        {
            rv = aesEncryptFinal(hSession,
                                 pEncryptedData,
                                 pulEncryptedDataLen,
                                 sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.encryptParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::ENCRYPT);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesDecryptInit(const CK_SESSION_HANDLE&  hSession,
                                                           const CK_MECHANISM_PTR    pMechanism,
                                                           const CK_OBJECT_HANDLE&   hKey)
{
    CK_RV                   rv              = CKR_FUNCTION_FAILED;
    int                     counterBits     = 0;
    uint32_t                tagBits         = 0;
    uint32_t                tagBytes        = 0;
    bool                    padding         = false;
    BlockCipherMode         cipherMode{ BlockCipherMode::unknown };
    std::vector<uint8_t>    iv;
    std::vector<uint8_t>    aad;

    do
    {
        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSymmetricKeyHandleCache ||
            !gSessionHandleCache      ||
            !gSymmetricCrypto         ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hKey) ||
            !gAttributeCache->isAttributeSet(hKey, KeyAttribute::DECRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_DECRYPT_NONE != sessionParameters.decryptOperation)
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        rv = populateSymmetricMechanismParameters(pMechanism,
                                                  iv,
                                                  aad,
                                                  counterBits,
                                                  tagBits,
                                                  tagBytes,
                                                  padding,
                                                  cipherMode);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = gSymmetricCrypto->decryptInit(hKey,
                                           iv.data(),
                                           iv.size(),
                                           aad.data(),
                                           aad.size(),
                                           static_cast<uint8_t>(cipherMode),
                                           padding,
                                           tagBits,
                                           counterBits);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.decryptOperation                = SessionOperation::SESSION_OP_SYMMETRIC_DECRYPT_INIT;
        sessionParameters.decryptParams.keyHandle         = hKey;
        sessionParameters.decryptParams.currentBufferSize = 0;
        sessionParameters.decryptParams.blockCipherMode   = cipherMode;
        sessionParameters.decryptParams.padding           = padding;
        sessionParameters.decryptParams.tagBytes          = tagBytes;

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaDecryptInit(const CK_SESSION_HANDLE&   hSession,
                                                           const CK_OBJECT_HANDLE&    hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!gAsymmetricKeyHandleCache ||
            !gSessionHandleCache       ||
            !gAsymmetricCrypto         ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey) ||
            !gAttributeCache->isAttributeSet(hKey, KeyAttribute::DECRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_DECRYPT_NONE != sessionParameters.decryptOperation)
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        sessionParameters.decryptOperation         = SessionOperation::SESSION_OP_ASYMMETRIC_DECRYPT_INIT;
        sessionParameters.decryptParams.keyHandle  = hKey;

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptInit(CK_SESSION_HANDLE   hSession,
                                                           CK_MECHANISM_PTR    pMechanism,
                                                           CK_OBJECT_HANDLE    hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(decryptInitMutex)> ulock(decryptInitMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (isSymmetricMechanism(pMechanism))
        {
            if (!gSymmetricKeyHandleCache->find(hKey))
            {
                rv = CKR_KEY_HANDLE_INVALID;
                break;
            }

            rv = aesDecryptInit(hSession,
                                pMechanism,
                                hKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isAsymmetricMechanism(pMechanism))
        {
            if (!gAsymmetricKeyHandleCache->find(hKey))
            {
                rv = CKR_KEY_HANDLE_INVALID;
                break;
            }

            rv = rsaDecryptInit(hSession,
                                hKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesDecrypt(const CK_SESSION_HANDLE&  hSession,
                                                       const CK_BYTE_PTR         pEncryptedData,
                                                       const CK_ULONG&           ulEncryptedDataLen,
                                                       CK_BYTE_PTR               pData,
                                                       CK_ULONG_PTR              pulDataLen,
                                                       SessionParameters&        sessionParameters)
{
    CK_RV           rv                 = CKR_FUNCTION_FAILED;
    uint32_t        keyHandle          = sessionParameters.decryptParams.keyHandle;
    uint32_t        destBufferLength   = 0;
    uint32_t        destBufferRequired = 0;
    uint32_t        decryptedBytes     = 0;
    uint32_t        tagBytes           = sessionParameters.decryptParams.tagBytes;
    BlockCipherMode cipherMode         = sessionParameters.decryptParams.blockCipherMode;

    do
    {
        if (!pEncryptedData || !pulDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc              == cipherMode &&
            ulEncryptedDataLen % aesBlockSize != 0)
        {
            rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
            break;
        }

        destBufferLength = *pulDataLen;

        if (!pData)
        {
            if (BlockCipherMode::gcm == cipherMode)
            {
                *pulDataLen = ulEncryptedDataLen - tagBytes;
            }
            else
            {
                *pulDataLen = ulEncryptedDataLen;
            }
            rv = CKR_OK;
            break;
        }

        if (BlockCipherMode::gcm != cipherMode &&
            *pulDataLen < ulEncryptedDataLen)
        {
            *pulDataLen = ulEncryptedDataLen;
            rv          = CKR_BUFFER_TOO_SMALL;
            break;
        }

        rv = gSymmetricCrypto->decryptUpdate(keyHandle,
                                             pEncryptedData,
                                             ulEncryptedDataLen,
                                             pData,
                                             destBufferLength,
                                             destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        decryptedBytes      = destBufferRequired;
        destBufferRequired  = 0;

        rv = gSymmetricCrypto->decryptFinal(keyHandle,
                                            pData + decryptedBytes,
                                            destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        decryptedBytes += destBufferRequired;

        resetSessionParameters(sessionParameters, ActiveOperation::DECRYPT);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        *pulDataLen = decryptedBytes;

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaDecrypt(const CK_SESSION_HANDLE&  hSession,
                                                       const CK_BYTE_PTR         pEncryptedData,
                                                       const CK_ULONG&           ulEncryptedDataLen,
                                                       CK_BYTE_PTR               pData,
                                                       CK_ULONG_PTR              pulDataLen,
                                                       SessionParameters&        sessionParameters)
{
    CK_RV    rv                 = CKR_FUNCTION_FAILED;
    uint32_t keyHandle          = sessionParameters.decryptParams.keyHandle;
    uint32_t destBufferLength   = 0;
    uint32_t destBufferRequired = 0;

    do
    {
        if (!pEncryptedData || !pulDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLength = *pulDataLen;

        rv = gAsymmetricCrypto->decrypt(keyHandle,
                                        pEncryptedData,
                                        ulEncryptedDataLen,
                                        pData,
                                        destBufferLength,
                                        destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulDataLen = destBufferRequired;
        if (!pData)
        {
            rv = CKR_OK;
            break;
        }

        resetSessionParameters(sessionParameters, ActiveOperation::DECRYPT);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Decrypt(CK_SESSION_HANDLE   hSession,
                                                       CK_BYTE_PTR         pEncryptedData,
                                                       CK_ULONG            ulEncryptedDataLen,
                                                       CK_BYTE_PTR         pData,
                                                       CK_ULONG_PTR        pulDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(decryptMutex)> ulock(decryptMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricCrypto           ||
            !gAsymmetricCrypto          ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pEncryptedData || !pulDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SYMMETRIC_DECRYPT_INIT == sessionParameters.decryptOperation)
        {
            rv = aesDecrypt(hSession,
                            pEncryptedData,
                            ulEncryptedDataLen,
                            pData,
                            pulDataLen,
                            sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (SessionOperation::SESSION_OP_ASYMMETRIC_DECRYPT_INIT == sessionParameters.decryptOperation)
        {
            rv = rsaDecrypt(hSession,
                            pEncryptedData,
                            ulEncryptedDataLen,
                            pData,
                            pulDataLen,
                            sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.decryptParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::DECRYPT);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesDecryptUpdate(const CK_SESSION_HANDLE&   hSession,
                                                             const CK_BYTE_PTR          pEncryptedData,
                                                             const CK_ULONG&            ulEncryptedDataLen,
                                                             CK_BYTE_PTR                pData,
                                                             CK_ULONG_PTR               pDataLen,
                                                             SessionParameters&         sessionParameters)
{
    CK_RV           rv                  = CKR_FUNCTION_FAILED;
    uint32_t        remainingSize       = sessionParameters.decryptParams.currentBufferSize;
    CK_ULONG        maxSize             = ulEncryptedDataLen + remainingSize;
    uint32_t        keyHandle           = sessionParameters.decryptParams.keyHandle;
    uint32_t        destBufferLength    = 0;
    BlockCipherMode cipherMode          = sessionParameters.decryptParams.blockCipherMode;
    uint32_t        destBufferRequired  = 0;

    do
    {
        if (!pEncryptedData || !pDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLength = *pDataLen;

        if (BlockCipherMode::cbc == cipherMode)
        {
            uint32_t paddingAdjustByte = sessionParameters.decryptParams.padding;
            int nrOfBlocks = (ulEncryptedDataLen + remainingSize - paddingAdjustByte) / aesBlockSize;
            maxSize = nrOfBlocks * aesBlockSize;
        }
        else if (BlockCipherMode::gcm == cipherMode)
        {
            maxSize = 0;
        }
        else
        {
            maxSize = ulEncryptedDataLen;
        }

        if (!pData)
        {
            *pDataLen = maxSize;
            rv = CKR_OK;
            break;
        }

        if (*pDataLen < maxSize)
        {
            *pDataLen = maxSize;
            rv        = CKR_BUFFER_TOO_SMALL;
            break;
        }

        rv = gSymmetricCrypto->decryptUpdate(keyHandle,
                                             pEncryptedData,
                                             ulEncryptedDataLen,
                                             pData,
                                             destBufferLength,
                                             destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.decryptParams.currentBufferSize += (ulEncryptedDataLen - destBufferRequired);
        sessionParameters.decryptOperation                 = SESSION_OP_SYMMETRIC_DECRYPT;

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        *pDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptUpdate(CK_SESSION_HANDLE     hSession,
                                                             CK_BYTE_PTR           pEncryptedData,
                                                             CK_ULONG              ulEncryptedDataLen,
                                                             CK_BYTE_PTR           pData,
                                                             CK_ULONG_PTR          pDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(decryptUpdateMutex)> ulock(decryptUpdateMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSymmetricCrypto       ||
            !gSymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pEncryptedData || !pDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SYMMETRIC_DECRYPT_INIT == sessionParameters.decryptOperation ||
            SessionOperation::SESSION_OP_SYMMETRIC_DECRYPT      == sessionParameters.decryptOperation)
        {
            rv = aesDecryptUpdate(hSession,
                                  pEncryptedData,
                                  ulEncryptedDataLen,
                                  pData,
                                  pDataLen,
                                  sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if(SessionOperation::SESSION_OP_DECRYPT_NONE == sessionParameters.decryptOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.decryptParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::DECRYPT);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesDecryptFinal(const CK_SESSION_HANDLE&    hSession,
                                                            CK_BYTE_PTR                 pData,
                                                            CK_ULONG_PTR                pDataLen,
                                                            SessionParameters&          sessionParameters)
{
    CK_RV           rv                  = CKR_FUNCTION_FAILED;
    uint32_t        tagBytes            = sessionParameters.decryptParams.tagBytes;
    uint32_t        remainingSize       = sessionParameters.decryptParams.currentBufferSize + tagBytes;
    CK_ULONG        sizeRequired        = remainingSize;
    uint32_t        keyHandle           = sessionParameters.decryptParams.keyHandle;
    BlockCipherMode cipherMode          = sessionParameters.decryptParams.blockCipherMode;
    uint32_t        destBufferRequired  = 0;

    do
    {
        if (!pDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(keyHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == cipherMode)
        {
            bool isPadding = sessionParameters.decryptParams.padding;
            if ((remainingSize % aesBlockSize) != 0 &&
                 !isPadding)
            {
                rv = CKR_DATA_LEN_RANGE;
                break;
            }
            sizeRequired = isPadding ? ((remainingSize + aesBlockSize) / aesBlockSize) * aesBlockSize : remainingSize;
        }
        else if (BlockCipherMode::ctr == cipherMode)
        {
            sizeRequired = 0;
        }
        else if (BlockCipherMode::gcm == cipherMode)
        {
            sizeRequired = sessionParameters.decryptParams.currentBufferSize - tagBytes;
        }

        if (!pData)
        {
            *pDataLen = sizeRequired;
            rv        = CKR_OK;
            break;
        }

        if (*pDataLen < sizeRequired)
        {
            *pDataLen = sizeRequired;
            rv        = CKR_BUFFER_TOO_SMALL;
            break;
        }
        destBufferRequired = *pDataLen;
        rv = gSymmetricCrypto->decryptFinal(keyHandle,
                                            pData,
                                            destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        resetSessionParameters(sessionParameters, ActiveOperation::DECRYPT);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
        *pDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptFinal(CK_SESSION_HANDLE  hSession,
                                                            CK_BYTE_PTR        pData,
                                                            CK_ULONG_PTR       pDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(decryptFinalMutex)> ulock(decryptFinalMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache    ||
            !gSymmetricCrypto       ||
            !gSymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SYMMETRIC_DECRYPT == sessionParameters.decryptOperation)
        {
            rv = aesDecryptFinal(hSession,
                                 pData,
                                 pDataLen,
                                 sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if(SessionOperation::SESSION_OP_DECRYPT_NONE == sessionParameters.decryptOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.decryptParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::DECRYPT);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) populateHashMechanismParameters(const CK_MECHANISM_PTR pMechanism,
                                                                            HashMode&              hashMode,
                                                                            bool&                  hmac,
                                                                            uint32_t&              keyHandleForHmac)
{
    CK_RV rv = CKR_OK;

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_SHA256:
            hashMode = HashMode::sha256;
            break;
        case CKM_SHA512:
            hashMode = HashMode::sha512;
            break;
        case CKM_SHA256_HMAC_AES_KEYID:
            hashMode    = HashMode::sha256;
            hmac        = true;
            if ((sizeof(CK_HMAC_AES_KEYID_PARAMS) != pMechanism->ulParameterLen) || !pMechanism->pParameter)
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
            }
            else
            {
                keyHandleForHmac = CK_HMAC_AES_KEYID_PARAMS_PTR(pMechanism->pParameter)->ulKeyID;
            }
            break;
        case CKM_SHA512_HMAC_AES_KEYID:
            hashMode    = HashMode::sha512;
            hmac        = true;
            if ((sizeof(CK_HMAC_AES_KEYID_PARAMS) != pMechanism->ulParameterLen) || !pMechanism->pParameter)
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
            }
            else
            {
                keyHandleForHmac = CK_HMAC_AES_KEYID_PARAMS_PTR(pMechanism->pParameter)->ulKeyID;
            }
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestInit(CK_SESSION_HANDLE    hSession,
                                                          CK_MECHANISM_PTR     pMechanism)
{
    CK_RV       rv                  = CKR_FUNCTION_FAILED;
    HashMode    hashMode            = HashMode::invalid;
    bool        hmac                = false;
    uint32_t    keyHandleForHmac    = 0;
    uint32_t    hashHandle          = 0;

    std::unique_lock<decltype(digestInitMutex)> ulock(digestInitMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache    ||
            !gHashHandleCache       ||
            !gCryptoHash)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_HASH_OP_NONE != sessionParameters.hashOperation)
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        rv = populateHashMechanismParameters(pMechanism,
                                             hashMode,
                                             hmac,
                                             keyHandleForHmac);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = gCryptoHash->hashInit(&hashHandle,
                                   keyHandleForHmac,
                                   hashMode,
                                   hmac);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        // Update hash handle cache
        HashState hashState{ sessionId };
        gHashHandleCache->add(hashHandle, hashState);

        // Update session handle cache
        sessionParameters.hashOperation            = SessionOperation::SESSION_HASH_OP_INIT;
        sessionParameters.hashParams.hashHandle    = hashHandle;
        sessionParameters.hashParams.hashMode      = hashMode;
        gSessionHandleCache->add(hSession, sessionParameters);

    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Digest(CK_SESSION_HANDLE    hSession,
                                                      CK_BYTE_PTR          pData,
                                                      CK_ULONG             ulDataLen,
                                                      CK_BYTE_PTR          pDigest,
                                                      CK_ULONG_PTR         pulDigestLen)

{
    CK_RV             rv          = CKR_FUNCTION_FAILED;
    uint32_t          hashHandle  = 0;
    bool              result      = false;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(digestMutex)> ulock(digestMutex, std::defer_lock);
    ulock.lock();
    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache    ||
            !gHashHandleCache       ||
            !gCryptoHash)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);
        hashHandle        = sessionParameters.hashParams.hashHandle;

        if (!pData || !pulDigestLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        switch(sessionParameters.hashOperation)
        {
            case SessionOperation::SESSION_HASH_OP_NONE:
                 rv     = CKR_OPERATION_NOT_INITIALIZED;
                 result = false;
                 break;

            case SessionOperation::SESSION_HASH_OP_DIGEST:
                 rv     = CKR_OPERATION_ACTIVE;
                 result = false;
                 break;

            case SessionOperation::SESSION_HASH_OP_INIT:
                 result = true;
                 break;
        }

        if (!result)
        {
            break;
        }

        if (!gHashHandleCache->find(hashHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (!pDigest)
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]);
            rv = CKR_OK;
            break;
        }

        if (static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]) > *pulDigestLen)
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]);
            rv            = CKR_BUFFER_TOO_SMALL;
            break;
        }

        rv = C_DigestUpdate(hSession,
                            pData,
                            ulDataLen);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = C_DigestFinal(hSession,
                           pDigest,
                           pulDigestLen);
        if (CKR_OK != rv)
        {
            break;
        }
    } while (false);

    if (cleanUpRequired(rv))
    {
        CK_RV returnValue = gCryptoHash->destroyHash(hashHandle, gHashHandleCache);

        resetSessionParameters(sessionParameters, ActiveOperation::HASH);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestUpdate(CK_SESSION_HANDLE  hSession,
                                                            CK_BYTE_PTR        pPart,
                                                            CK_ULONG           ulPartLen)
{
    CK_RV             rv          = CKR_FUNCTION_FAILED;
    uint32_t          hashHandle  = 0;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(digestUpdateMutex)> ulock(digestUpdateMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache    ||
            !gHashHandleCache       ||
            !gCryptoHash)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!pPart)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);
        if (!(SessionOperation::SESSION_HASH_OP_INIT   == sessionParameters.hashOperation ||
              SessionOperation::SESSION_HASH_OP_DIGEST == sessionParameters.hashOperation) )
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        hashHandle = sessionParameters.hashParams.hashHandle;
        if (!gHashHandleCache->find(hashHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = gCryptoHash->hashUpdate(hashHandle,
                                     reinterpret_cast<uint8_t*>(pPart),
                                     static_cast<uint32_t>(ulPartLen));
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.hashOperation = SessionOperation::SESSION_HASH_OP_DIGEST;
        gSessionHandleCache->add(hSession, sessionParameters);
    } while (false);

    if (cleanUpRequired(rv))
    {
        CK_RV returnValue = gCryptoHash->destroyHash(hashHandle, gHashHandleCache);

        resetSessionParameters(sessionParameters, ActiveOperation::HASH);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestFinal(CK_SESSION_HANDLE   hSession,
                                                           CK_BYTE_PTR         pDigest,
                                                           CK_ULONG_PTR        pulDigestLen)
{
    CK_RV               rv          = CKR_FUNCTION_FAILED;
    uint32_t            hashHandle  = 0;
    bool                result      = false;
    SessionParameters   sessionParameters{};

    std::unique_lock<decltype(digestFinalMutex)> ulock(digestFinalMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized          ||
            !gSessionHandleCache    ||
            !gHashHandleCache       ||
            !gCryptoHash)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!pulDigestLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        switch(sessionParameters.hashOperation)
        {
            case SessionOperation::SESSION_HASH_OP_NONE:
                 rv     = CKR_OPERATION_NOT_INITIALIZED;
                 result = false;
                 break;

            case SessionOperation::SESSION_HASH_OP_INIT:
                 rv     = CKR_OPERATION_ACTIVE;
                 result = false;
                 break;

            case SessionOperation::SESSION_HASH_OP_DIGEST:
                 result = true;
                 break;
        }

        if (!result)
        {
            break;
        }

        hashHandle = sessionParameters.hashParams.hashHandle;
        if (!gHashHandleCache->find(hashHandle))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (!pDigest)
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]);
            rv = CKR_OK;
            break;
        }

        if (static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]) > *pulDigestLen)
        {
            *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]);
            rv            = CKR_BUFFER_TOO_SMALL;
            break;
        }

        rv = gCryptoHash->hashFinal(hashHandle,
                                    reinterpret_cast<uint8_t*>(pDigest),
                                    static_cast<uint32_t>(*pulDigestLen));
        if (CKR_OK != rv)
        {
            break;
        }

        *pulDigestLen = static_cast<CK_ULONG>(hashDigestLengthMap[sessionParameters.hashParams.hashMode]);

        resetSessionParameters(sessionParameters, ActiveOperation::HASH);

        gSessionHandleCache->add(hSession, sessionParameters);
        gHashHandleCache->remove(hashHandle);
    } while (false);

    if (cleanUpRequired(rv))
    {
        CK_RV returnValue = gCryptoHash->destroyHash(hashHandle, gHashHandleCache);

        resetSessionParameters(sessionParameters, ActiveOperation::HASH);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignInit(CK_SESSION_HANDLE  hSession,
                                                        CK_MECHANISM_PTR   pMechanism,
                                                        CK_OBJECT_HANDLE   hKey)
{
    CK_RV      rv         = CKR_FUNCTION_FAILED;
    RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
    HashMode   hashMode   = HashMode::invalid;

    std::unique_lock<decltype(signInitMutex)> ulock(signInitMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto          ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey) ||
            !gAttributeCache->isAttributeSet(hKey, KeyAttribute::SIGN))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        if (isSupportedSignVerifyMechanism(pMechanism))
        {
            SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
            if (SessionOperation::SESSION_OP_SIGN_NONE != sessionParameters.signOperation)
            {
                rv = CKR_OPERATION_ACTIVE;
                break;
            }

            switch(pMechanism->mechanism)
            {
                case CKM_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    break;
                case CKM_SHA256_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha256;
                    break;
                case CKM_SHA512_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha512;
                    break;
                case CKM_RSA_PKCS_PSS:
                case CKM_SHA256_RSA_PKCS_PSS:
                case CKM_SHA512_RSA_PKCS_PSS:
                    if (!pMechanism->pParameter                                                                                                      ||
                        sizeof(CK_RSA_PKCS_PSS_PARAMS)                               != pMechanism->ulParameterLen                                   ||
                        CKM_SHA256                                                   != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg  ||
                        static_cast<CK_ULONG>(hashDigestLengthMap[HashMode::sha256]) != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen)
                        {
                            rv = CKR_ARGUMENTS_BAD;
                            break;
                        }
                        rsaPadding = RsaPadding::rsaPkcs1Pss;
                        if (CKM_SHA256_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha256;
                        }
                        else if (CKM_SHA512_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha512;
                        }
                    break;
                default:
                    rv = CKR_MECHANISM_INVALID;
                    break;
            }

            if (CKR_OK != rv)
            {
                break;
            }

            sessionParameters.signOperation         = SessionOperation::SESSION_OP_SIGN_INIT;
            sessionParameters.signParams.keyHandle  = hKey;
            sessionParameters.signParams.hashMode   = hashMode;
            sessionParameters.signParams.rsaPadding = rsaPadding;

            gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Sign(CK_SESSION_HANDLE  hSession,
                                                    CK_BYTE_PTR        pData,
                                                    CK_ULONG           ulDataLen,
                                                    CK_BYTE_PTR        pSignature,
                                                    CK_ULONG_PTR       pulSignatureLen)
{
    CK_RV             rv                        = CKR_FUNCTION_FAILED;
    RsaPadding        rsaPadding                = RsaPadding::rsaNoPadding;
    uint32_t          keyHandle                 = 0;
    uint32_t          destBufferLen             = 0;
    uint32_t          destBufferRequiredLength  = 0;
    HashMode          hashMode                  = HashMode::invalid;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(signMutex)> ulock(signMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pData || !pulSignatureLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_SIGN_INIT != sessionParameters.signOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        rsaPadding = sessionParameters.signParams.rsaPadding;
        keyHandle  = sessionParameters.signParams.keyHandle;
        hashMode   = sessionParameters.signParams.hashMode;

        destBufferLen = *pulSignatureLen;
        rv = gAsymmetricCrypto->sign(keyHandle,
                                     pData,
                                     ulDataLen,
                                     pSignature,
                                     destBufferLen,
                                     destBufferRequiredLength,
                                     rsaPadding,
                                     hashMode);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulSignatureLen = destBufferRequiredLength;
        if (!pSignature)
        {
            rv = CKR_OK;
            break;
        }

        resetSessionParameters(sessionParameters, ActiveOperation::SIGN);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.signParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::SIGN);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyInit(CK_SESSION_HANDLE    hSession,
                                                          CK_MECHANISM_PTR     pMechanism,
                                                          CK_OBJECT_HANDLE     hKey)
{
    CK_RV      rv         = CKR_FUNCTION_FAILED;
    RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
    HashMode   hashMode   = HashMode::invalid;

    std::unique_lock<decltype(verifyInitMutex)> ulock(verifyInitMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto          ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey) ||
            !gAttributeCache->isAttributeSet(hKey, KeyAttribute::VERIFY))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        if (isSupportedSignVerifyMechanism(pMechanism))
        {
            SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
            if (SessionOperation::SESSION_OP_VERIFY_NONE != sessionParameters.verifyOperation)
            {
                rv = CKR_OPERATION_ACTIVE;
                break;
            }

            switch(pMechanism->mechanism)
            {
                case CKM_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    break;
                case CKM_SHA256_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha256;
                    break;
                case CKM_SHA512_RSA_PKCS:
                    rsaPadding = RsaPadding::rsaPkcs1;
                    hashMode   = HashMode::sha512;
                    break;
                case CKM_RSA_PKCS_PSS:
                case CKM_SHA256_RSA_PKCS_PSS:
                case CKM_SHA512_RSA_PKCS_PSS:
                    if (!pMechanism->pParameter                                                                                                      ||
                        sizeof(CK_RSA_PKCS_PSS_PARAMS)                               != pMechanism->ulParameterLen                                   ||
                        CKM_SHA256                                                   != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg  ||
                        static_cast<CK_ULONG>(hashDigestLengthMap[HashMode::sha256]) != CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen)
                        {
                            rv = CKR_ARGUMENTS_BAD;
                            break;
                        }
                        rsaPadding = RsaPadding::rsaPkcs1Pss;
                        if (CKM_SHA256_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha256;
                        }
                        else if (CKM_SHA512_RSA_PKCS_PSS == pMechanism->mechanism)
                        {
                            hashMode = HashMode::sha512;
                        }
                    break;
                default:
                    rv = CKR_MECHANISM_INVALID;
                    break;
            }

            if (CKR_OK != rv)
            {
                break;
            }

            sessionParameters.verifyOperation         = SessionOperation::SESSION_OP_VERIFY_INIT;
            sessionParameters.verifyParams.keyHandle  = hKey;
            sessionParameters.verifyParams.hashMode   = hashMode;
            sessionParameters.verifyParams.rsaPadding = rsaPadding;

            gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_Verify(CK_SESSION_HANDLE    hSession,
                                                      CK_BYTE_PTR          pData,
                                                      CK_ULONG             ulDataLen,
                                                      CK_BYTE_PTR          pSignature,
                                                      CK_ULONG             ulSignatureLen)
{
    CK_RV             rv          = CKR_FUNCTION_FAILED;
    RsaPadding        rsaPadding  = RsaPadding::rsaNoPadding;
    uint32_t          keyHandle   = 0;
    HashMode          hashMode    = HashMode::invalid;
    SessionParameters sessionParameters{};

    std::unique_lock<decltype(verifyMutex)> ulock(verifyMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionHandleCache->get(hSession);

        if (!pData || !pSignature)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (SessionOperation::SESSION_OP_VERIFY_INIT != sessionParameters.verifyOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        rsaPadding = sessionParameters.verifyParams.rsaPadding;
        keyHandle  = sessionParameters.verifyParams.keyHandle;
        hashMode   = sessionParameters.verifyParams.hashMode;

        rv = gAsymmetricCrypto->verify(keyHandle,
                                       pData,
                                       ulDataLen,
                                       pSignature,
                                       ulSignatureLen,
                                       rsaPadding,
                                       hashMode);
        if (CKR_OK != rv)
        {
            break;
        }

        resetSessionParameters(sessionParameters, ActiveOperation::VERIFY);

        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

    } while (false);

    if (cleanUpRequired(rv))
    {
        cleanUpState(sessionParameters.verifyParams.keyHandle);

        resetSessionParameters(sessionParameters, ActiveOperation::VERIFY);
        gSessionHandleCache->add(hSession, sessionParameters);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaImportPlatformBoundKey(const CK_SESSION_HANDLE&  hSession,
                                                                      const CK_MECHANISM_PTR    pMechanism,
                                                                      const CK_ATTRIBUTE_PTR    pPublicKeyTemplate,
                                                                      const CK_ULONG&           ulPublicKeyAttributeCount,
                                                                      const CK_ATTRIBUTE_PTR    pPrivateKeyTemplate,
                                                                      const CK_ULONG&           ulPrivateKeyAttributeCount,
                                                                      CK_OBJECT_HANDLE_PTR      phPublicKey,
                                                                      CK_OBJECT_HANDLE_PTR      phPrivateKey)
{
    CK_RV                rv = CKR_FUNCTION_FAILED;
    std::vector<uint8_t> platformBoundKey;
    Attributes           publicKeyAttributes, privateKeyAttributes;

    do
    {
        if (!isInitialized             ||
            !gAsymmetricCrypto          ||
            !gSymmetricKeyHandleCache  ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }
        if (!pMechanism          ||
            !pPublicKeyTemplate  ||
            !pPrivateKeyTemplate ||
            !phPublicKey         ||
            !phPrivateKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (pMechanism->pParameter      == NULL_PTR ||
            pMechanism->ulParameterLen  != sizeof(CK_RSA_PBIND_IMPORT_PARAMS))
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }
        platformBoundKey.resize(CK_RSA_PBIND_IMPORT_PARAMS_PTR(pMechanism->pParameter)->ulPlatformBoundKeyLen);
        memcpy(&platformBoundKey[0],
               CK_RSA_PBIND_IMPORT_PARAMS_PTR(pMechanism->pParameter)->pPlatformBoundKey,
               CK_RSA_PBIND_IMPORT_PARAMS_PTR(pMechanism->pParameter)->ulPlatformBoundKeyLen);

        rv = gAsymmetricCrypto->importPlatformBoundKey(pPublicKeyTemplate,
                                                       ulPublicKeyAttributeCount,
                                                       pPrivateKeyTemplate,
                                                       ulPrivateKeyAttributeCount,
                                                       phPublicKey,
                                                       phPrivateKey,
                                                       platformBoundKey,
                                                       publicKeyAttributes,
                                                       privateKeyAttributes);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        AsymmetricKey aSymmetricKey{ sessionId };
        gAsymmetricKeyHandleCache->add(*phPublicKey, aSymmetricKey);

        gAttributeCache->add(*phPublicKey, publicKeyAttributes);

        if (*phPrivateKey)
        {
            gAsymmetricKeyHandleCache->add(*phPrivateKey, aSymmetricKey);

            gAttributeCache->add(*phPrivateKey, privateKeyAttributes);
        }

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GenerateKeyPair(CK_SESSION_HANDLE       hSession,
                                                               CK_MECHANISM_PTR        pMechanism,
                                                               CK_ATTRIBUTE_PTR        pPublicKeyTemplate,
                                                               CK_ULONG                ulPublicKeyAttributeCount,
                                                               CK_ATTRIBUTE_PTR        pPrivateKeyTemplate,
                                                               CK_ULONG                ulPrivateKeyAttributeCount,
                                                               CK_OBJECT_HANDLE_PTR    phPublicKey,
                                                               CK_OBJECT_HANDLE_PTR    phPrivateKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;
    Attributes publicKeyAttributes, privateKeyAttributes;

    std::unique_lock<decltype(generateKeyPairMutex)> ulock(generateKeyPairMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized             ||
            !gSessionHandleCache       ||
            !gAsymmetricCrypto         ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism             ||
            !pPublicKeyTemplate     ||
            !pPrivateKeyTemplate    ||
            !phPublicKey            ||
            !phPrivateKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = checkWriteAccess(hSession, pPublicKeyTemplate, ulPublicKeyAttributeCount);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = checkWriteAccess(hSession, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
        if (CKR_OK != rv)
        {
            break;
        }

        if (CKM_RSA_PKCS_KEY_PAIR_GEN == pMechanism->mechanism)
        {
            rv = gAsymmetricCrypto->generateKeyPair(hSession,
                                                    pPublicKeyTemplate,
                                                    ulPublicKeyAttributeCount,
                                                    pPrivateKeyTemplate,
                                                    ulPrivateKeyAttributeCount,
                                                    phPublicKey,
                                                    phPrivateKey,
                                                    publicKeyAttributes,
                                                    privateKeyAttributes);
            if (CKR_OK != rv)
            {
                break;
            }

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            AsymmetricKey asymmetricPublicKey{ sessionId };
            gAsymmetricKeyHandleCache->add(*phPublicKey, asymmetricPublicKey);

            AsymmetricKey asymmetricPrivateKey{ sessionId };
            gAsymmetricKeyHandleCache->add(*phPrivateKey, asymmetricPrivateKey);

            gAttributeCache->add(*phPublicKey,  publicKeyAttributes);
            gAttributeCache->add(*phPrivateKey, privateKeyAttributes);
        }
        else if (CKM_RSA_PBIND_IMPORT == pMechanism->mechanism)
        {
            rv = rsaImportPlatformBoundKey(hSession,
                                           pMechanism,
                                           pPublicKeyTemplate,
                                           ulPublicKeyAttributeCount,
                                           pPrivateKeyTemplate,
                                           ulPrivateKeyAttributeCount,
                                           phPublicKey,
                                           phPrivateKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) populateWrapParameters(const CK_MECHANISM_PTR   pMechanism,
                                                                   std::vector<uint8_t>&    iv,
                                                                   std::vector<uint8_t>&    aad,
                                                                   int&                     counterBits,
                                                                   uint32_t&                tagBits,
                                                                   uint32_t&                tagBytes,
                                                                   bool&                    padding,
                                                                   BlockCipherMode&         cipherMode,
                                                                   RsaPadding&              rsaPadding,
                                                                   std::vector<uint8_t>&    sigRL,
                                                                   std::vector<uint8_t>&    spid,
                                                                   uint32_t&                signatureType,
                                                                   bool&                    isSymmetricWrap,
                                                                   bool&                    isRSAWrap,
                                                                   bool&                    isRSAExportPublicKey,
                                                                   bool&                    isRSAExportQuotePublicKey,
                                                                   bool&                    isAESPbind,
                                                                   bool&                    isRSAPbind)
{
    CK_RV    rv      = CKR_OK;
    CK_ULONG ctrBits = 0;

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_AES_CTR:
            if (NULL_PTR                    ==  pMechanism->pParameter ||
                sizeof(CK_AES_CTR_PARAMS)   !=  pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            ctrBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
            if (!isSupportedCounterBitsSize(ctrBits))
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }

            counterBits = ctrBits;

            iv.resize(16);
            memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
            cipherMode = BlockCipherMode::ctr;

            isSymmetricWrap = true;
            break;
        case CKM_AES_GCM:
            if (NULL_PTR                ==  pMechanism->pParameter ||
                sizeof(CK_GCM_PARAMS)   !=  pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
            memcpy(&iv[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);

            aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
            memcpy(&aad[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);

            tagBits = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
            tagBytes = tagBits >> 3;
            if (tagBytes < minTagSize ||
                tagBytes > maxTagSize)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            cipherMode = BlockCipherMode::gcm;
            isSymmetricWrap = true;
            break;
        case CKM_AES_CBC:
            if (NULL_PTR == pMechanism->pParameter  ||
                0        == pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            iv.resize(pMechanism->ulParameterLen);
            memcpy(&iv[0],
                   pMechanism->pParameter,
                   pMechanism->ulParameterLen);

            cipherMode       = BlockCipherMode::cbc;
            isSymmetricWrap  = true;
            break;
        case CKM_AES_CBC_PAD:
            if (NULL_PTR == pMechanism->pParameter  ||
                0        == pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            iv.resize(pMechanism->ulParameterLen);
            memcpy(&iv[0],
                   pMechanism->pParameter,
                   pMechanism->ulParameterLen);

            cipherMode       = BlockCipherMode::cbc;
            padding          = true;
            isSymmetricWrap  = true;
            break;
        case CKM_RSA_PKCS:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isRSAWrap  = true;
            rsaPadding = RsaPadding::rsaPkcs1Oaep;
            break;
        case CKM_EXPORT_RSA_PUBLIC_KEY:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isRSAExportPublicKey = true;
            break;
        case CKM_EXPORT_QUOTE_RSA_PUBLIC_KEY:
            if (NULL_PTR                                 ==  pMechanism->pParameter ||
                sizeof(CK_QUOTE_RSA_PUBLIC_KEY_PARAMS)   !=  pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            sigRL.resize(CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSigRLLen);
            memcpy(&sigRL[0],
                   CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->pSigRL,
                   CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSigRLLen);

            spid.resize(CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSpidLen);
            memcpy(&spid[0],
                   CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->pSpid,
                   CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSpidLen);

            signatureType = CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulQuoteSignatureType;
            if (!(UNLINKABLE_SIGNATURE == signatureType ||
                  LINKABLE_SIGNATURE   == signatureType))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isRSAExportQuotePublicKey = true;
            break;
        case CKM_AES_PBIND:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isAESPbind = true;
            break;
        case CKM_RSA_PBIND_EXPORT:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isRSAPbind = true;
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesWrapKey(const CK_SESSION_HANDLE&     hSession,
                                                       const CK_OBJECT_HANDLE&      hWrappingKey,
                                                       const CK_OBJECT_HANDLE&      hKey,
                                                       CK_BYTE_PTR                  pWrappedKey,
                                                       CK_ULONG_PTR                 pulWrappedKeyLen,
                                                       const std::vector<uint8_t>&  iv,
                                                       const std::vector<uint8_t>&  aad,
                                                       const BlockCipherMode&       cipherMode,
                                                       const bool&                  padding,
                                                       const uint32_t&              tagBits,
                                                       const int&                   counterBits)
{
    CK_RV    rv                     = CKR_FUNCTION_FAILED;
    uint32_t destBufferLen          = 0;
    uint32_t destBufferLenRequired  = 0;

    do
    {
        if (!pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto           ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hKey)) // Key to be wrapped has to be symmetric
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hWrappingKey) || // Wrapping key Id has to be symmetric
            !gAttributeCache->isAttributeSet(hWrappingKey, KeyAttribute::WRAP))
        {
            rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLen = *pulWrappedKeyLen;
        rv = gSymmetricCrypto->wrapKey(hWrappingKey,
                                       hKey,
                                       iv.data(),
                                       iv.size(),
                                       aad.data(),
                                       aad.size(),
                                       static_cast<uint8_t>(cipherMode),
                                       padding,
                                       tagBits,
                                       counterBits,
                                       pWrappedKey,
                                       destBufferLen,
                                       destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaWrapKey(const CK_SESSION_HANDLE& hSession,
                                                       const CK_OBJECT_HANDLE&  hWrappingKey,
                                                       const CK_OBJECT_HANDLE&  hKey,
                                                       CK_BYTE_PTR              pWrappedKey,
                                                       CK_ULONG_PTR             pulWrappedKeyLen,
                                                       const RsaPadding&        rsaPadding)
{
    CK_RV    rv                     = CKR_FUNCTION_FAILED;
    uint32_t destBufferLen          = 0;
    uint32_t destBufferLenRequired  = 0;

    do
    {
        if (!hWrappingKey || !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized             ||
            !gSessionHandleCache       ||
            !gSymmetricKeyHandleCache  ||
            !gAsymmetricCrypto         ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hKey)) // Key to be wrapped has to be symmetric
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hWrappingKey) || // Wrapping key Id has to be asymmetric
            !gAttributeCache->isAttributeSet(hWrappingKey, KeyAttribute::WRAP))
        {
            rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLen = *pulWrappedKeyLen;
        rv = gAsymmetricCrypto->wrapKey(hWrappingKey,
                                        hKey,
                                        pWrappedKey,
                                        destBufferLen,
                                        destBufferLenRequired,
                                        rsaPadding);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesPlatformBindKey(const CK_SESSION_HANDLE& hSession,
                                                               const CK_OBJECT_HANDLE&  hWrappingKey,
                                                               const CK_OBJECT_HANDLE&  hKey,
                                                               CK_BYTE_PTR              pWrappedKey,
                                                               CK_ULONG_PTR             pulWrappedKeyLen)
{
    CK_RV    rv                     = CKR_FUNCTION_FAILED;
    uint32_t destBufferLen          = 0;
    uint32_t destBufferLenRequired  = 0;

    do
    {
        if (hWrappingKey ||     // Wrapping key Id should be null for pbind operations
            !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricKeyHandleCache   ||
            !gSymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hKey))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLen = *pulWrappedKeyLen;
        rv = gSymmetricCrypto->platformbindKey(hKey,
                                               pWrappedKey,
                                               destBufferLen,
                                               destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

CK_RV __attribute__((visibility("hidden"))) rsaPlatformBindKey(const CK_SESSION_HANDLE& hSession,
                                                               const CK_OBJECT_HANDLE&  hWrappingKey,
                                                               const CK_OBJECT_HANDLE&  hKey,
                                                               CK_BYTE_PTR              pWrappedKey,
                                                               CK_ULONG_PTR             pulWrappedKeyLen)
{
    CK_RV    rv                     = CKR_FUNCTION_FAILED;
    uint32_t destBufferLen          = 0;
    uint32_t destBufferLenRequired  = 0;

    do
    {
        if (hWrappingKey ||   // Wrapping key Id should be null for pbind operations
            !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLen = *pulWrappedKeyLen;
        rv = gAsymmetricCrypto->platformbindKey(hKey,
                                                pWrappedKey,
                                                destBufferLen,
                                                destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaExportPublicKey(const CK_SESSION_HANDLE& hSession,
                                                               const CK_OBJECT_HANDLE&  hWrappingKey,
                                                               const CK_OBJECT_HANDLE&  hKey,
                                                               CK_BYTE_PTR              pWrappedKey,
                                                               CK_ULONG_PTR             pulWrappedKeyLen)
{
    CK_RV    rv                     = CKR_FUNCTION_FAILED;
    uint32_t destBufferLen          = 0;
    uint32_t destBufferLenRequired  = 0;

    do
    {
        if (hWrappingKey   ||   // Wrapping key Id should be null for RSA export
            !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLen = *pulWrappedKeyLen;
        rv = gAsymmetricCrypto->exportKey(hKey,
                                          pWrappedKey,
                                          destBufferLen,
                                          destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaExportQuotePublicKey(const CK_SESSION_HANDLE&    hSession,
                                                                    const CK_OBJECT_HANDLE&     hWrappingKey,
                                                                    const CK_OBJECT_HANDLE&     hKey,
                                                                    CK_BYTE_PTR                 pWrappedKey,
                                                                    CK_ULONG_PTR                pulWrappedKeyLen,
                                                                    const std::vector<uint8_t>& spid,
                                                                    const std::vector<uint8_t>& sigRL,
                                                                    const uint32_t&             signatureType)
{
    CK_RV    rv                     = CKR_FUNCTION_FAILED;
    uint32_t destBufferLen          = 0;
    uint32_t destBufferLenRequired  = 0;

    do
    {
        if (hWrappingKey ||   // Wrapping key Id should be null for RSA quote + public key export
            !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gAsymmetricKeyHandleCache  ||
            !gAsymmetricCrypto)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hKey))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        destBufferLen = *pulWrappedKeyLen;
        rv = gAsymmetricCrypto->exportQuotePublicKey(hKey,
                                                     spid.data(),
                                                     spid.size(),
                                                     sigRL.data(),
                                                     sigRL.size(),
                                                     signatureType,
                                                     pWrappedKey,
                                                     destBufferLen,
                                                     destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_WrapKey(CK_SESSION_HANDLE   hSession,
                                                       CK_MECHANISM_PTR    pMechanism,
                                                       CK_OBJECT_HANDLE    hWrappingKey,
                                                       CK_OBJECT_HANDLE    hKey,
                                                       CK_BYTE_PTR         pWrappedKey,
                                                       CK_ULONG_PTR        pulWrappedKeyLen)
{
    CK_RV       rv                         = CKR_FUNCTION_FAILED;
    bool        isSymmetricWrap            = false;
    bool        isRSAWrap                  = false;
    bool        isAESPbind                 = false;
    bool        isRSAPbind                 = false;
    bool        isRSAExportPublicKey       = false;
    bool        isRSAExportQuotePublicKey  = false;
    RsaPadding  rsaPadding                 = RsaPadding::rsaNoPadding;

    std::unique_lock<decltype(wrapKeyMutex)> ulock(wrapKeyMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricCrypto           ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricCrypto          ||
            !gAsymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism || !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hKey) &&
            !gAsymmetricKeyHandleCache->find(hKey))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (hWrappingKey) // hWrappingKey can be nullptr for platform binding scenarios.
        {
            rv = checkReadAccess(hSession, hWrappingKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }

        rv = checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        std::vector<uint8_t> iv;
        std::vector<uint8_t> aad;
        std::vector<uint8_t> sigRL;
        std::vector<uint8_t> spid;
        uint32_t             signatureType;
        int                  counterBits = 0;
        uint32_t             tagBits     = 0;
        uint32_t             tagBytes    = 0;
        bool                 padding     = false;
        BlockCipherMode      cipherMode{ BlockCipherMode::unknown };

        rv = populateWrapParameters(pMechanism,
                                    iv,
                                    aad,
                                    counterBits,
                                    tagBits,
                                    tagBytes,
                                    padding,
                                    cipherMode,
                                    rsaPadding,
                                    sigRL,
                                    spid,
                                    signatureType,
                                    isSymmetricWrap,
                                    isRSAWrap,
                                    isRSAExportPublicKey,
                                    isRSAExportQuotePublicKey,
                                    isAESPbind,
                                    isRSAPbind);
        if (CKR_OK != rv)
        {
            break;
        }

        if (isSymmetricWrap)
        {
            rv = aesWrapKey(hSession,
                            hWrappingKey,
                            hKey,
                            pWrappedKey,
                            pulWrappedKeyLen,
                            iv,
                            aad,
                            cipherMode,
                            padding,
                            tagBits,
                            counterBits);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isRSAWrap)
        {
            rv = rsaWrapKey(hSession,
                            hWrappingKey,
                            hKey,
                            pWrappedKey,
                            pulWrappedKeyLen,
                            rsaPadding);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isAESPbind)
        {
            rv = aesPlatformBindKey(hSession,
                                    hWrappingKey,
                                    hKey,
                                    pWrappedKey,
                                    pulWrappedKeyLen);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isRSAPbind)
        {
            rv = rsaPlatformBindKey(hSession,
                                    hWrappingKey,
                                    hKey,
                                    pWrappedKey,
                                    pulWrappedKeyLen);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isRSAExportPublicKey)
        {
            rv = rsaExportPublicKey(hSession,
                                    hWrappingKey,
                                    hKey,
                                    pWrappedKey,
                                    pulWrappedKeyLen);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isRSAExportQuotePublicKey)
        {
            rv = rsaExportQuotePublicKey(hSession,
                                         hWrappingKey,
                                         hKey,
                                         pWrappedKey,
                                         pulWrappedKeyLen,
                                         spid,
                                         sigRL,
                                         signatureType);
            if (CKR_OK != rv)
            {
                break;
            }
        }
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) populateUnwrapParameters(const CK_MECHANISM_PTR pMechanism,
                                                                     std::vector<uint8_t>&  iv,
                                                                     std::vector<uint8_t>&  aad,
                                                                     int&                   counterBits,
                                                                     uint32_t&              tagBits,
                                                                     uint32_t&              tagBytes,
                                                                     bool&                  padding,
                                                                     BlockCipherMode&       cipherMode,
                                                                     RsaPadding&            rsaPadding,
                                                                     bool&                  isSymmetricUnwrap,
                                                                     bool&                  isRSAUnwrap,
                                                                     bool&                  isRSAImportPublicKey,
                                                                     bool&                  isAESPbind)
{
    CK_RV    rv      = CKR_OK;
    CK_ULONG ctrBits = 0;

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_AES_CTR:
            if (NULL_PTR                    == pMechanism->pParameter  ||
                sizeof(CK_AES_CTR_PARAMS)   != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            ctrBits  = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
            if (!isSupportedCounterBitsSize(ctrBits))
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }

            counterBits = ctrBits;

            iv.resize(16);
            memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);

            cipherMode         = BlockCipherMode::ctr;
            isSymmetricUnwrap  = true;
            break;
        case CKM_AES_GCM:
            if (NULL_PTR                == pMechanism->pParameter  ||
                sizeof(CK_GCM_PARAMS)   != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
            memcpy(&iv[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);

            aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
            memcpy(&aad[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);

            tagBits = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
            tagBytes = tagBits >> 3;
            if (tagBytes < minTagSize ||
                tagBytes > maxTagSize)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            cipherMode        = BlockCipherMode::gcm;
            isSymmetricUnwrap = true;
            break;
        case CKM_AES_CBC:
            if (NULL_PTR == pMechanism->pParameter  ||
                0        == pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            iv.resize(pMechanism->ulParameterLen);
            memcpy(&iv[0],
                   pMechanism->pParameter,
                   pMechanism->ulParameterLen);

            cipherMode         = BlockCipherMode::cbc;
            isSymmetricUnwrap  = true;
            break;
        case CKM_AES_CBC_PAD:
            if (NULL_PTR == pMechanism->pParameter  ||
                0        == pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            iv.resize(pMechanism->ulParameterLen);
            memcpy(&iv[0],
                   pMechanism->pParameter,
                   pMechanism->ulParameterLen);

            cipherMode         = BlockCipherMode::cbc;
            padding            = true;
            isSymmetricUnwrap  = true;
            break;
        case CKM_RSA_PKCS:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            rsaPadding  = RsaPadding::rsaPkcs1Oaep;
            isRSAUnwrap = true;
            break;
        case CKM_IMPORT_RSA_PUBLIC_KEY:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isRSAImportPublicKey = true;
            break;
        case CKM_AES_PBIND:
            if (NULL_PTR != pMechanism->pParameter  ||
                0        != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            isAESPbind = true;
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesUnwrapKey(const CK_SESSION_HANDLE&    hSession,
                                                         const CK_OBJECT_HANDLE&     hUnwrappingKey,
                                                         CK_OBJECT_HANDLE_PTR        hKey,
                                                         const CK_BYTE_PTR           pWrappedKey,
                                                         const CK_ULONG&             ulWrappedKeyLen,
                                                         const std::vector<uint8_t>& iv,
                                                         const std::vector<uint8_t>& aad,
                                                         const BlockCipherMode&      cipherMode,
                                                         const bool&                 padding,
                                                         const uint32_t&             tagBits,
                                                         const int&                  counterBits,
                                                         const Attributes&           keyAttributes)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized            ||
            !gSessionHandleCache      ||
            !gSymmetricKeyHandleCache ||
            !gSymmetricCrypto         ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pWrappedKey || !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hUnwrappingKey) || // Key to unwrap has to be symmetric
            !gAttributeCache->isAttributeSet(hUnwrappingKey, KeyAttribute::UNWRAP))
        {
            rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        rv = gSymmetricCrypto->unwrapKey(hUnwrappingKey,
                                         reinterpret_cast<uint32_t*>(hKey),
                                         pWrappedKey,
                                         ulWrappedKeyLen,
                                         iv.data(),
                                         iv.size(),
                                         aad.data(),
                                         aad.size(),
                                         static_cast<uint8_t>(cipherMode),
                                         padding,
                                         tagBits,
                                         counterBits);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        SymmetricKey symKey{ sessionId };
        gSymmetricKeyHandleCache->add(*hKey, symKey);

        gAttributeCache->add(*hKey, keyAttributes);

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaUnwrapKey(const CK_SESSION_HANDLE&   hSession,
                                                         const CK_OBJECT_HANDLE&    hUnwrappingKey,
                                                         CK_OBJECT_HANDLE_PTR       hKey,
                                                         const CK_BYTE_PTR          pWrappedKey,
                                                         const CK_ULONG&            ulWrappedKeyLen,
                                                         const RsaPadding&          rsaPadding,
                                                         const Attributes&          keyAttributes)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized             ||
            !gSessionHandleCache       ||
            !gAsymmetricKeyHandleCache ||
            !gAsymmetricCrypto         ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pWrappedKey || !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gAsymmetricKeyHandleCache->find(hUnwrappingKey) || // Key to unwrap has to be asymmetric
            !gAttributeCache->isAttributeSet(hUnwrappingKey, KeyAttribute::UNWRAP))
        {
            rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        rv = gAsymmetricCrypto->unwrapKey(hUnwrappingKey,
                                          reinterpret_cast<uint32_t*>(hKey),
                                          pWrappedKey,
                                          ulWrappedKeyLen,
                                          rsaPadding);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        SymmetricKey symKey{ sessionId };
        gSymmetricKeyHandleCache->add(*hKey, symKey);

        gAttributeCache->add(*hKey, keyAttributes);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) aesImportPlatformBoundKey(const CK_SESSION_HANDLE&  hSession,
                                                                      const CK_OBJECT_HANDLE&   hUnwrappingKey,
                                                                      CK_OBJECT_HANDLE_PTR      hKey,
                                                                      const CK_BYTE_PTR         pWrappedKey,
                                                                      const CK_ULONG&           ulWrappedKeyLen,
                                                                      const Attributes&         keyAttributes)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized            ||
            !gSymmetricCrypto         ||
            !gSymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (hUnwrappingKey ||   // Unwrapping key Id should be null for pbind operations
            !pWrappedKey   ||
            !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        rv = gSymmetricCrypto->importPlatformBoundKey(reinterpret_cast<uint32_t*>(hKey),
                                                      pWrappedKey,
                                                      ulWrappedKeyLen);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        SymmetricKey symmetricKey{ sessionId };
        gSymmetricKeyHandleCache->add(*hKey, symmetricKey);

        gAttributeCache->add(*hKey, keyAttributes);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("hidden"))) rsaImportPublicKey(const CK_SESSION_HANDLE& hSession,
                                                               const CK_OBJECT_HANDLE&  hUnwrappingKey,
                                                               CK_OBJECT_HANDLE_PTR     hKey,
                                                               const CK_BYTE_PTR        pWrappedKey,
                                                               const CK_ULONG&          ulWrappedKeyLen,
                                                               const Attributes&        keyAttributes)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized             ||
            !gAsymmetricCrypto         ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (hUnwrappingKey ||     // Unwrapping key Id should be null for RSA import
            !pWrappedKey   ||
            !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        rv = gAsymmetricCrypto->importKey(reinterpret_cast<uint32_t*>(hKey),
                                          pWrappedKey,
                                          ulWrappedKeyLen);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        AsymmetricKey aSymmetricKey{ sessionId };
        gAsymmetricKeyHandleCache->add(*hKey, aSymmetricKey);

        gAttributeCache->add(*hKey, keyAttributes);

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_UnwrapKey(CK_SESSION_HANDLE      hSession,
                                                         CK_MECHANISM_PTR       pMechanism,
                                                         CK_OBJECT_HANDLE       hUnwrappingKey,
                                                         CK_BYTE_PTR            pWrappedKey,
                                                         CK_ULONG               ulWrappedKeyLen,
                                                         CK_ATTRIBUTE_PTR       pTemplate,
                                                         CK_ULONG               ulCount,
                                                         CK_OBJECT_HANDLE_PTR   hKey)
{
    CK_RV            rv                     = CKR_FUNCTION_FAILED;
    bool             isSymmetricUnwrap      = false;
    bool             isRSAUnwrap            = false;
    bool             isAESPbind             = false;
    bool             isRSAImportPublicKey   = false;
    RsaPadding       rsaPadding             = RsaPadding::rsaNoPadding;
    AttributeHelpers attributeHelpers;

    std::unique_lock<decltype(unwrapKeyMutex)> ulock(unwrapKeyMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricCrypto           ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricCrypto          ||
            !gAsymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism         ||
            !pWrappedKey        ||
            !ulWrappedKeyLen    ||
            !pTemplate          ||
            !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (hUnwrappingKey) // hUnwrappingKey can be nullptr for platform binding scenarios.
        {
            rv = checkReadAccess(hSession, hUnwrappingKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }

        rv = checkWriteAccess(hSession, pTemplate, ulCount);
        if (CKR_OK != rv)
        {
            break;
        }

        std::vector<uint8_t>   iv;
        std::vector<uint8_t>   aad;
        int                    counterBits      = 0;
        uint32_t               tagBits          = 0;
        uint32_t               tagBytes         = 0;
        uint32_t               attributeBitmask = 0;
        bool                   padding          = false;
        bool                   result           = false;
        KeyGenerationMechanism keyGenMechanism;
        std::string            label, id;
        CK_OBJECT_CLASS        keyClass;
        CK_KEY_TYPE            keyType;
        Attributes             keyAttributes;
        BlockCipherMode        cipherMode{ BlockCipherMode::unknown };

        rv = populateUnwrapParameters(pMechanism,
                                      iv,
                                      aad,
                                      counterBits,
                                      tagBits,
                                      tagBytes,
                                      padding,
                                      cipherMode,
                                      rsaPadding,
                                      isSymmetricUnwrap,
                                      isRSAUnwrap,
                                      isRSAImportPublicKey,
                                      isAESPbind);
        if (CKR_OK != rv)
        {
            break;
        }

        if (isSymmetricUnwrap)
        {
            result = attributeHelpers.getKeyGenMechanismFromP11SymmetricUnwrapMechanism(pMechanism->mechanism, keyGenMechanism);
            if(!result)
            {
                rv = CKR_MECHANISM_INVALID;
                break;
            }
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pTemplate,
                                                                ulCount,
                                                                attributeBitmask,
                                                                label,
                                                                id,
                                                                keyClass,
                                                                keyType);
            if (CKR_OK != rv)
            {
                break;
            }

            attributeHelpers.populateAttributes(attributeBitmask,
                                                label,
                                                id,
                                                keyGenMechanism,
                                                keyClass,
                                                keyType,
                                                keyAttributes);

            rv = aesUnwrapKey(hSession,
                              hUnwrappingKey,
                              hKey,
                              pWrappedKey,
                              ulWrappedKeyLen,
                              iv,
                              aad,
                              cipherMode,
                              padding,
                              tagBits,
                              counterBits,
                              keyAttributes);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isRSAUnwrap)
        {
            keyGenMechanism = KeyGenerationMechanism::rsaUnwrapKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pTemplate,
                                                                ulCount,
                                                                attributeBitmask,
                                                                label,
                                                                id,
                                                                keyClass,
                                                                keyType);
            if (CKR_OK != rv)
            {
                break;
            }

            attributeHelpers.populateAttributes(attributeBitmask,
                                                label,
                                                id,
                                                keyGenMechanism,
                                                keyClass,
                                                keyType,
                                                keyAttributes);

            rv = rsaUnwrapKey(hSession,
                              hUnwrappingKey,
                              hKey,
                              pWrappedKey,
                              ulWrappedKeyLen,
                              rsaPadding,
                              keyAttributes);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isAESPbind)
        {
            keyGenMechanism = KeyGenerationMechanism::aesImportPbindKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pTemplate,
                                                                ulCount,
                                                                attributeBitmask,
                                                                label,
                                                                id,
                                                                keyClass,
                                                                keyType);
            if (CKR_OK != rv)
            {
                break;
            }

            attributeHelpers.populateAttributes(attributeBitmask,
                                                label,
                                                id,
                                                keyGenMechanism,
                                                keyClass,
                                                keyType,
                                                keyAttributes);

            rv = aesImportPlatformBoundKey(hSession,
                                           hUnwrappingKey,
                                           hKey,
                                           pWrappedKey,
                                           ulWrappedKeyLen,
                                           keyAttributes);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (isRSAImportPublicKey)
        {
            keyGenMechanism = KeyGenerationMechanism::rsaImportPublicKey;
            rv = attributeHelpers.extractAttributesFromTemplate(keyGenMechanism,
                                                                pTemplate,
                                                                ulCount,
                                                                attributeBitmask,
                                                                label,
                                                                id,
                                                                keyClass,
                                                                keyType);
            if (CKR_OK != rv)
            {
                break;
            }

            attributeHelpers.populateAttributes(attributeBitmask,
                                                label,
                                                id,
                                                keyGenMechanism,
                                                keyClass,
                                                keyType,
                                                keyAttributes);

            if (!(KeyAttribute::ENCRYPT & attributeBitmask) ||
                !(KeyAttribute::VERIFY  & attributeBitmask) ||
                !(KeyAttribute::WRAP    & attributeBitmask))
            {
                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
            }
            rv = rsaImportPublicKey(hSession,
                                    hUnwrappingKey,
                                    hKey,
                                    pWrappedKey,
                                    ulWrappedKeyLen,
                                    keyAttributes);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        rv = CKR_OK;
    } while (false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DestroyObject(CK_SESSION_HANDLE hSession,
                                                             CK_OBJECT_HANDLE  hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(destroyObjectMutex)> ulock(destroyObjectMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricCrypto           ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricCrypto          ||
            !gAsymmetricKeyHandleCache  ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = checkWriteAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        if (gSymmetricKeyHandleCache->find(hKey))   // hKey is symmetric key Id
        {
            rv = gSymmetricCrypto->destroyKey(hKey, gSymmetricKeyHandleCache);
            if (CKR_OK != rv)
            {
                break;
            }
        }

        else if (gAsymmetricKeyHandleCache->find(hKey))  // hKey is asymmetric key Id
        {
            rv = gAsymmetricCrypto->destroyKey(hKey, gAsymmetricKeyHandleCache);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else    // key Id not found in any of symmetric or asymmetric handle caches.
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
            break;
        }

    } while (false);

    if (CKR_OK == rv)
    {
        gAttributeCache->remove(hKey);
    }

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetInfo(CK_INFO_PTR pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(getInfoMutex)> ulock(getInfoMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
        pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;

        memset(pInfo->manufacturerID, ' ', 32);
        memcpy(pInfo->manufacturerID, "Crypto API Toolkit", 18);

        pInfo->flags = 0;

        memset(pInfo->libraryDescription, ' ', 32);
        memcpy(pInfo->libraryDescription, "Implementation of PKCS11", 24);

        // (Todo) What library versions should we use?
        pInfo->libraryVersion.major = CRYPTOKI_VERSION_MAJOR;
        pInfo->libraryVersion.minor = CRYPTOKI_VERSION_MINOR;

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetSlotList(CK_BBOOL         tokenPresent,
                                                           CK_SLOT_ID_PTR   pSlotList,
                                                           CK_ULONG_PTR     pulCount)
{
    CK_RV    rv         = CKR_FUNCTION_FAILED;
    CK_ULONG numOfSlots = 0;

    std::unique_lock<decltype(getSlotListMutex)> ulock(getSlotListMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pulCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        DIR* dir = opendir(tokenPath.c_str());

        if (dir == NULL)
        {
            rv = CKR_GENERAL_ERROR;
            break;
        }

        // Enumerate the directory
        struct dirent* entry = NULL;

        while (entry = readdir(dir))
        {
            if (!strcmp(entry->d_name, ".") ||
                !strcmp(entry->d_name, ".."))
            {
                continue;
            }
            numOfSlots++;
        }

        int retValue = closedir(dir);

        if (numOfSlots >= maxSlotsSupported)
        {
            numOfSlots = maxSlotsSupported;
        }
        else
        {
            numOfSlots++; // To ensure atleast one slot is uninitialized.
        }

        if (!pSlotList)
        {
            *pulCount = numOfSlots;
            rv        = CKR_OK;
            break;
        }

        if (*pulCount < numOfSlots)
        {
            *pulCount = numOfSlots;
            rv        = CKR_BUFFER_TOO_SMALL;
            break;
        }

        for (auto i = 0; i < numOfSlots; i++)
        {
            pSlotList[i] = i;
        }

        *pulCount = numOfSlots;

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetSlotInfo(CK_SLOT_ID slotID,
                                                           CK_SLOT_INFO_PTR pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(getSlotInfoMutex)> ulock(getSlotInfoMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        rv = slot.getSlotInfo(pInfo);
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetTokenInfo(CK_SLOT_ID          slotID,
                                                            CK_TOKEN_INFO_PTR   pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(getTokenInfoMutex)> ulock(getTokenInfoMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        rv = token->getTokenInfo(pInfo);
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetMechanismList(CK_SLOT_ID              slotID,
                                                                CK_MECHANISM_TYPE_PTR   pMechanismList,
                                                                CK_ULONG_PTR            pulCount)
{
    CK_RV   rv                       = CKR_FUNCTION_FAILED;
    uint8_t mechanismsSupportedCount = sizeof(supportedMechanisms) / sizeof(CK_MECHANISM_TYPE);

    std::unique_lock<decltype(getMechanismListMutex)> ulock(getMechanismListMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        if (!pulCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!pMechanismList)
        {
            *pulCount = mechanismsSupportedCount;
            rv        = CKR_OK;
            break;
        }

        if (*pulCount < mechanismsSupportedCount)
        {
            *pulCount = mechanismsSupportedCount;
            rv        = CKR_BUFFER_TOO_SMALL;
            break;
        }

        *pulCount = mechanismsSupportedCount;

        for (CK_ULONG i = 0; i < mechanismsSupportedCount; i++)
        {
            pMechanismList[i] = supportedMechanisms[i];
        }

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetMechanismInfo(CK_SLOT_ID              slotID,
                                                                CK_MECHANISM_TYPE       type,
                                                                CK_MECHANISM_INFO_PTR   pInfo)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    std::unique_lock<decltype(getMechanismInfoMutex)> ulock(getMechanismInfoMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SLOT_ID_INVALID;
            break;
        }

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        switch(type)
        {
            case CKM_AES_KEY_GEN:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength128);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength256);
                pInfo->flags        = CKF_HW | CKF_GENERATE;
                break;
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_GENERATE_KEY_PAIR;
                break;
            case CKM_AES_CTR:
            case CKM_AES_GCM:
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength128);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength256);
                pInfo->flags        = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
                break;
            case CKM_RSA_PKCS:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP;
                break;
            case CKM_RSA_PKCS_PSS:
            case CKM_SHA256_RSA_PKCS:
            case CKM_SHA512_RSA_PKCS:
            case CKM_SHA256_RSA_PKCS_PSS:
            case CKM_SHA512_RSA_PKCS_PSS:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_SIGN | CKF_VERIFY;
                break;
            case CKM_SHA256:
            case CKM_SHA512:
                pInfo->ulMinKeySize = 0;
                pInfo->ulMaxKeySize = 0;
                pInfo->flags        = CKF_HW | CKF_DIGEST;
                break;
            case CKM_SHA256_HMAC_AES_KEYID:
            case CKM_SHA512_HMAC_AES_KEYID:
                pInfo->ulMinKeySize = 0;
                pInfo->ulMaxKeySize = maxAesKeySizeForHmacImport;
                pInfo->flags        = CKF_HW | CKF_DIGEST;
                break;
            case CKM_AES_PBIND:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength128);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(SymmetricKeySize::keyLength256);
                pInfo->flags        = CKF_HW | CKF_WRAP | CKF_UNWRAP;
                break;
            case CKM_RSA_PBIND_EXPORT:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_WRAP;
                break;
            case CKM_RSA_PBIND_IMPORT:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_GENERATE_KEY_PAIR;
                break;
            case CKM_EXPORT_RSA_PUBLIC_KEY:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_WRAP;
                break;
            case CKM_IMPORT_RSA_PUBLIC_KEY:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_UNWRAP;
                break;
            case CKM_EXPORT_QUOTE_RSA_PUBLIC_KEY:
                pInfo->ulMinKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength1024);
                pInfo->ulMaxKeySize = static_cast<CK_ULONG>(AsymmetricKeySize::keyLength4096);
                pInfo->flags        = CKF_HW | CKF_WRAP | CKF_UNWRAP;
                break;
            default:
                return CKR_MECHANISM_INVALID;
                break;
        }

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_InitPIN(CK_SESSION_HANDLE    hSession,
                                                       CK_UTF8CHAR_PTR      pPin,
                                                       CK_ULONG             ulPinLen)
{
    CK_RV        rv           = CKR_FUNCTION_FAILED;
    SessionState sessionState = SessionState::STATE_NONE;
    CK_SLOT_ID   slotID;

    std::unique_lock<decltype(initPinMutex)> ulock(initPinMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pPin)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (ulPinLen < minPinLength ||
            ulPinLen > maxPinLength)
        {
            rv = CKR_PIN_LEN_RANGE;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionState = gSessionHandleCache->getSessionState(hSession);
        if (SessionState::RW_SO_STATE != sessionState)
        {
            rv = CKR_USER_NOT_LOGGED_IN;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        rv = token->initUserPin(pPin, ulPinLen);
        if (CKR_OK != rv)
        {
            break;
        }
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_SetPIN(CK_SESSION_HANDLE     hSession,
                                                      CK_UTF8CHAR_PTR       pOldPin,
                                                      CK_ULONG              ulOldLen,
                                                      CK_UTF8CHAR_PTR       pNewPin,
                                                      CK_ULONG              ulNewLen)
{
    CK_RV        rv           = CKR_FUNCTION_FAILED;
    SessionState sessionState = SessionState::STATE_NONE;
    CK_SLOT_ID   slotID;

    std::unique_lock<decltype(setPinMutex)> ulock(setPinMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pOldPin || !pNewPin)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (ulOldLen < minPinLength ||
            ulOldLen > maxPinLength ||
            ulNewLen < minPinLength ||
            ulNewLen > maxPinLength)
        {
            rv = CKR_PIN_LEN_RANGE;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        sessionState = gSessionHandleCache->getSessionState(hSession);
        switch(sessionState)
        {
            case SessionState::RW_SO_STATE:
                rv = token->setSOPin(pOldPin,
                                     ulOldLen,
                                     pNewPin,
                                     ulNewLen);
                break;
            case SessionState::RW_USER_STATE:
            case SessionState::RW_PUBLIC_STATE:
                rv = token->setUserPin(pOldPin,
                                       ulOldLen,
                                       pNewPin,
                                       ulNewLen);
                break;
            default:
                rv = CKR_SESSION_READ_ONLY;
                break;
        }

        if (CKR_OK != rv)
        {
            break;
        }


        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetSessionInfo(CK_SESSION_HANDLE     hSession,
                                                              CK_SESSION_INFO_PTR   pInfo)
{
    CK_RV    rv     = CKR_FUNCTION_FAILED;
    CK_FLAGS flags  = CKF_SERIAL_SESSION;
    bool     result = false;

    std::unique_lock<decltype(getSessionInfoMutex)> ulock(getSessionInfoMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pInfo)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        pInfo->slotID = gSessionHandleCache->getSlotID(hSession);

        result = gSessionHandleCache->isRWSession(hSession);

        if (result)
        {
            flags = flags | CKF_RW_SESSION;
        }

        SessionState sessionState = gSessionHandleCache->getSessionState(hSession);
        switch(sessionState)
        {
            case SessionState::RW_PUBLIC_STATE :
                pInfo->state = CKS_RW_PUBLIC_SESSION;
                break;
            case SessionState::RO_PUBLIC_STATE :
                pInfo->state = CKS_RO_PUBLIC_SESSION;
                break;
            case SessionState::RW_SO_STATE :
                pInfo->state = CKS_RW_SO_FUNCTIONS;
                break;
            case SessionState::RW_USER_STATE :
                pInfo->state = CKS_RW_USER_FUNCTIONS;
                break;
            case SessionState::RO_USER_STATE :
                pInfo->state = CKS_RO_USER_FUNCTIONS;
                break;
        }

        pInfo->flags         = flags;
        pInfo->ulDeviceError = 0;

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_GetOperationState(CK_SESSION_HANDLE  hSession,
                                                                 CK_BYTE_PTR        pOperationState,
                                                                 CK_ULONG_PTR       pulOperationStateLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SetOperationState(CK_SESSION_HANDLE  hSession,
                                                                 CK_BYTE_PTR        pOperationState,
                                                                 CK_ULONG           ulOperationStateLen,
                                                                 CK_OBJECT_HANDLE   hEncryptionKey,
                                                                 CK_OBJECT_HANDLE   hAuthenticationKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV __attribute__((visibility("default"))) C_Login(CK_SESSION_HANDLE  hSession,
                                                     CK_USER_TYPE       userType,
                                                     CK_UTF8CHAR_PTR    pPin,
                                                     CK_ULONG           ulPinLen)
{
    CK_RV                   rv              = CKR_FUNCTION_FAILED;
    SessionState            sessionState    = SessionState::STATE_NONE;
    SessionState            newSessionState = SessionState::STATE_NONE;
    uint32_t                sessionCount    = 0;
    std::vector<uint32_t>   sessionHandlesInSlot;
    CK_SLOT_ID              slotID;

    std::unique_lock<decltype(loginMutex)> ulock(loginMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pPin)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (ulPinLen < minPinLength ||
            ulPinLen > maxPinLength)
        {
            rv = CKR_PIN_LEN_RANGE;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if(CKU_SO == userType)
        {
            if (gSessionHandleCache->hasROSessionInSlot(slotID))
            {
                rv = CKR_SESSION_READ_ONLY_EXISTS;
                break;
            }

            rv = token->loginSO(pPin, ulPinLen);
            if (CKR_OK != rv)
            {
                break;
            }

            newSessionState = SessionState::RW_SO_STATE;

            gSessionHandleCache->getSessionHandlesInSlot(slotID, sessionHandlesInSlot);

            sessionCount = sessionHandlesInSlot.size();

            for (auto i = 0; i < sessionCount; i++)
            {
                gSessionHandleCache->updateSessionState(sessionHandlesInSlot[i], newSessionState);
            }
        }
        else if (CKU_USER == userType)
        {
            rv = token->loginUser(pPin, ulPinLen);
            if (CKR_OK != rv)
            {
                break;
            }

            gSessionHandleCache->getSessionHandlesInSlot(slotID, sessionHandlesInSlot);

            sessionCount = sessionHandlesInSlot.size();

            for (auto i = 0; i < sessionCount; i++)
            {
                sessionState = gSessionHandleCache->getSessionState(sessionHandlesInSlot[i]);

                if (SessionState::RW_PUBLIC_STATE == sessionState)
                {
                    newSessionState = SessionState::RW_USER_STATE;
                }
                else if (SessionState::RO_PUBLIC_STATE == sessionState)
                {
                    newSessionState = SessionState::RO_USER_STATE;
                }

                gSessionHandleCache->updateSessionState(sessionHandlesInSlot[i], newSessionState);
            }
        }
        else // User type of CKU_CONTEXT_SPECIFIC is not supported.
        {
            rv = CKR_USER_TYPE_INVALID;
            break;
        }

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_Logout(CK_SESSION_HANDLE hSession)
{
    CK_RV                   rv              = CKR_FUNCTION_FAILED;
    SessionState            sessionState    = SessionState::STATE_NONE;
    SessionState            newSessionState = SessionState::STATE_NONE;
    uint32_t                sessionCount    = 0;
    std::vector<uint32_t>   sessionHandlesInSlot;
    CK_SLOT_ID              slotID;

    std::unique_lock<decltype(logoutMutex)> ulock(logoutMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized   ||
            !gAttributeCache ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        rv = token->logOut();
        if (CKR_OK != rv)
        {
            break;
        }

        gSessionHandleCache->getSessionHandlesInSlot(slotID, sessionHandlesInSlot);

        sessionCount = sessionHandlesInSlot.size();

        for (auto i = 0; i < sessionCount; i++)
        {
            sessionState = gSessionHandleCache->getSessionState(sessionHandlesInSlot[i]);

            if (SessionState::RW_SO_STATE == sessionState)
            {
                newSessionState = SessionState::RW_PUBLIC_STATE;
            }
            else if (SessionState::RO_USER_STATE == sessionState)
            {
                newSessionState = SessionState::RO_PUBLIC_STATE;
            }
            else if (SessionState::RW_USER_STATE == sessionState)
            {
                newSessionState = SessionState::RW_PUBLIC_STATE;
            }

            gSessionHandleCache->updateSessionState(sessionHandlesInSlot[i], newSessionState);
        }

        // Destroy all private key objets.
        std::vector<uint32_t> keyHandles;

        gAttributeCache->getAllKeyHandles(keyHandles);
        auto keyHandleCount = keyHandles.size();

        for (auto i = 0; i < keyHandleCount; i++)
        {
            if (gAttributeCache->isPrivateObject(keyHandles[i]))
            {
                rv = C_DestroyObject(hSession, keyHandles[i]);
            }
        }

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_CreateObject(CK_SESSION_HANDLE    hSession,
                                                            CK_ATTRIBUTE_PTR     pTemplate,
                                                            CK_ULONG             ulCount,
                                                            CK_OBJECT_HANDLE_PTR phObject)
{
    CK_RV             rv                = CKR_FUNCTION_FAILED;
    bool              isKeyClassPresent = false;
    CK_MECHANISM_TYPE mechanismType     = CKM_AES_KEY_GEN;

    std::unique_lock<decltype(createObejctMutex)> ulock(createObejctMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        for (auto i = 0; i < ulCount; i++)
        {
            if (isKeyClassPresent)
            {
                break;
            }

            switch(pTemplate[i].type)
            {
                case CKA_CLASS:
                    if (!pTemplate[i].pValue)
                    {
                        break;
                    }

                    isKeyClassPresent = true;
                    if (CKO_SECRET_KEY == *reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue))
                    {
                        mechanismType = CKM_AES_KEY_GEN;
                    }
                    else if (CKO_PUBLIC_KEY == *reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue))
                    {
                        mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;
                    }
                    break;
                default:
                    break;
            }
        }

        if (!isKeyClassPresent)
        {
            rv = CKR_TEMPLATE_INCOMPLETE;
            break;
        }

        CK_MECHANISM mechanism { mechanismType, nullptr, 0 };
        if (CKM_AES_KEY_GEN == mechanismType)
        {
            rv = C_GenerateKey(hSession,
                               &mechanism,
                               pTemplate,
                               ulCount,
                               phObject);
        }
        else if (CKM_RSA_PKCS_KEY_PAIR_GEN == mechanismType)
        {
            CK_OBJECT_CLASS  rsaPrivateKeyClass = CKO_PRIVATE_KEY;
            CK_KEY_TYPE      rsaKeyType         = CKK_RSA;
            CK_OBJECT_HANDLE privateKeyHandle   = CK_INVALID_HANDLE;

            CK_ATTRIBUTE privateKeyAttributes[] = {{ CKA_CLASS,     &rsaPrivateKeyClass, sizeof(rsaPrivateKeyClass) },
                                                   { CKA_KEY_TYPE,  &rsaKeyType,         sizeof(rsaKeyType) } };

            rv = C_GenerateKeyPair(hSession,
                                   &mechanism,
                                   pTemplate,
                                   ulCount,
                                   privateKeyAttributes,
                                   sizeof(privateKeyAttributes) / sizeof(CK_ATTRIBUTE),
                                   phObject,
                                   &privateKeyHandle);
            if (CKR_OK == rv)
            {
                // Destroy the private key handle since C_CreateObject API gives out only one key(public) handle
                rv = C_DestroyObject(hSession, privateKeyHandle);
            }
        }
        else
        {
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
            break;
        }
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                                                 CK_OBJECT_HANDLE  hObject,
                                                                 CK_ATTRIBUTE_PTR  pTemplate,
                                                                 CK_ULONG          ulCount)
{
    CK_RV            rv = CKR_FUNCTION_FAILED;
    CK_SLOT_ID       slotID;
    Attributes       attributes;
    AttributeHelpers attributeHelpers;

    std::unique_lock<decltype(getAttributeValueMutex)> ulock(getAttributeValueMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized             ||
            !gSessionHandleCache       ||
            !gSymmetricKeyHandleCache  ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid() ||
            !gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hObject) &&
            !gAsymmetricKeyHandleCache->find(hObject))
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
            break;
        }

        rv = checkReadAccess(hSession, hObject);
        if (CKR_OK != rv)
        {
            break;
        }

        gAttributeCache->getAttributes(hObject, attributes);

        rv = attributeHelpers.populateTemplateFromAttributes(pTemplate, ulCount, attributes);
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                                                 CK_OBJECT_HANDLE  hObject,
                                                                 CK_ATTRIBUTE_PTR  pTemplate,
                                                                 CK_ULONG          ulCount)
{
    CK_RV            rv = CKR_FUNCTION_FAILED;
    CK_SLOT_ID       slotID;
    Attributes       attributes;
    SessionState     sessionState;
    AttributeHelpers attributeHelpers;

    std::unique_lock<decltype(setAttributeValueMutex)> ulock(setAttributeValueMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized             ||
            !gSessionHandleCache       ||
            !gSymmetricKeyHandleCache  ||
            !gAsymmetricKeyHandleCache ||
            !gAttributeCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid() ||
            !gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (!gSymmetricKeyHandleCache->find(hObject) &&
            !gAsymmetricKeyHandleCache->find(hObject))
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
            break;
        }

        rv = checkWriteAccess(hSession, hObject);
        if (CKR_OK != rv)
        {
            break;
        }

        gAttributeCache->getAttributes(hObject, attributes);

        if (!(KeyAttribute::MODIFIABLE & attributes.attributeBitmask))  // Rejecting if CKA_MODIFIABLE is NOT SET.
        {
            rv = CKR_ACTION_PROHIBITED;
            break;
        }

        rv = attributeHelpers.updateAttributes(hObject, pTemplate, ulCount, attributes);
        if (CKR_OK != rv)
        {
            break;
        }

        // If a session that's NOT logged in has tried to set CKA_PRIVATE as CK_TRUE, reject it.
        if (KeyAttribute::PRIVATE & attributes.attributeBitmask)
        {
            sessionState = gSessionHandleCache->getSessionState(hSession);
            if (SessionState::RW_SO_STATE     == sessionState ||
                SessionState::RW_PUBLIC_STATE == sessionState ||
                SessionState::RO_PUBLIC_STATE == sessionState)
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }
        }

        gAttributeCache->add(hObject, attributes);

    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                                               CK_ATTRIBUTE_PTR  pTemplate,
                                                               CK_ULONG          ulCount)
{
    CK_RV                  rv                  = CKR_FUNCTION_FAILED;
    bool                   result              = false;
    bool                   templateMatched     = true;
    CK_BBOOL               isAttributeSet      = CK_FALSE;
    SessionState           sessionState        = SessionState::STATE_NONE;
    bool                   isPublicSession     = true;
    uint32_t               bitMaskedAttributes = 0;
    std::vector<uint32_t>  keyHandles, matchedKeyHandles;
    CK_SLOT_ID             slotID;
    Attributes             attributes;
    KeyAttribute           keyAttribute;
    std::string            label, id;
    AttributeHelpers       attributeHelpers;

    std::unique_lock<decltype(findObjectsInitMutex)> ulock(findObjectsInitMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricCrypto           ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricCrypto          ||
            !gAsymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_FIND_OBJECTS_NONE != sessionParameters.findObjectsOperation)
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        sessionState = gSessionHandleCache->getSessionState(hSession);

        if (SessionState::RW_USER_STATE == sessionState ||
            SessionState::RO_USER_STATE == sessionState)
        {
            isPublicSession = false;
        }

        gAttributeCache->getAllKeyHandles(keyHandles);
        auto keyHandleCount = keyHandles.size();

        for (auto j = 0; j < keyHandleCount; j++)
        {
            label.clear();
            id.clear();

            gAttributeCache->getAttributes(keyHandles[j], attributes);

            bitMaskedAttributes = attributes.attributeBitmask;

            // If session is public, skip all private keys.
            if (isPublicSession &&
               (KeyAttribute::PRIVATE & bitMaskedAttributes))
            {
                continue;
            }

            for (auto i = 0; i < ulCount; i++)
            {
                if (!pTemplate)
                {
                    break;
                }

                templateMatched = false;

                result = attributeHelpers.isValidAttributeType(pTemplate[i].type);
                if (!result)
                {
                    break;
                }

                if (attributeHelpers.isBoolAttribute(pTemplate[i].type))
                {
                    rv = attributeHelpers.validateBoolAttribute(pTemplate[i].pValue,
                                                                pTemplate[i].ulValueLen,
                                                                isAttributeSet);
                    if (CKR_OK != rv)
                    {
                        break;
                    }

                    result = attributeHelpers.getKeyAttributeFromP11Attribute(pTemplate[i].type, keyAttribute);
                    if (!result)
                    {
                        break;
                    }

                    result = keyAttribute & bitMaskedAttributes;

                    if ((isAttributeSet  && !result) ||
                        (!isAttributeSet && result))
                    {
                        break;
                    }
                }
                else
                {
                    if (CKA_CLASS == pTemplate[i].type)
                    {
                        if (!pTemplate[i].pValue                               ||
                            sizeof(CK_OBJECT_CLASS) != pTemplate[i].ulValueLen ||
                            *reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue) != attributes.keyClass)
                        {
                            break;
                        }
                    }
                    else if (CKA_KEY_TYPE == pTemplate[i].type)
                    {
                        if (!pTemplate[i].pValue                           ||
                            sizeof(CK_KEY_TYPE) != pTemplate[i].ulValueLen ||
                            *reinterpret_cast<CK_KEY_TYPE*>(pTemplate[i].pValue) != attributes.keyType)
                        {
                            break;
                        }
                    }
                    else if (CKA_LABEL == pTemplate[i].type)
                    {
                        if (!pTemplate[i].pValue)
                        {
                            break;
                        }

                        label.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);

                        if (label != attributes.label)
                        {
                            break;
                        }
                    }
                    else if (CKA_ID == pTemplate[i].type)
                    {
                        if (!pTemplate[i].pValue)
                        {
                            break;
                        }

                        id.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);

                        if (id != attributes.id)
                        {
                            break;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                templateMatched = true;
            }

            if (templateMatched)
            {
                matchedKeyHandles.push_back(keyHandles[j]);
            }
        }

        sessionParameters.findObjectsOperation = SessionOperation::SESSION_OP_FIND_OBJECTS_INIT;
        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        gSessionHandleCache->updateMatchedKeyHandles(hSession, matchedKeyHandles);

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_FindObjects(CK_SESSION_HANDLE    hSession,
                                                           CK_OBJECT_HANDLE_PTR phObject,
                                                           CK_ULONG             ulMaxObjectCount,
                                                           CK_ULONG_PTR         pulObjectCount)
{
    CK_RV      rv = CKR_FUNCTION_FAILED;
    CK_SLOT_ID slotID;

    std::unique_lock<decltype(findObjectsMutex)> ulock(findObjectsMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized              ||
            !gSessionHandleCache        ||
            !gSymmetricCrypto           ||
            !gSymmetricKeyHandleCache   ||
            !gAsymmetricCrypto          ||
            !gAsymmetricKeyHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!phObject  ||
            !pulObjectCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid())
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_FIND_OBJECTS_NONE == sessionParameters.findObjectsOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        *pulObjectCount = gSessionHandleCache->getMatchedKeyHandles(hSession, phObject, ulMaxObjectCount);

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    CK_RV      rv = CKR_FUNCTION_FAILED;
    CK_SLOT_ID slotID;

    std::unique_lock<decltype(findObjectsFinalMutex)> ulock(findObjectsFinalMutex, std::defer_lock);
    ulock.lock();

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        slotID = gSessionHandleCache->getSlotID(hSession);

        Slot slot(slotID);
        if (!slot.valid() ||
            !gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        SessionParameters sessionParameters = gSessionHandleCache->get(hSession);
        if (SessionOperation::SESSION_OP_FIND_OBJECTS_NONE == sessionParameters.findObjectsOperation)
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        sessionParameters.findObjectsOperation = SessionOperation::SESSION_OP_FIND_OBJECTS_NONE;
        gSessionHandleCache->add(static_cast<uint32_t>(hSession), sessionParameters);

        gSessionHandleCache->clearMatchedKeyHandles(hSession);

        rv = CKR_OK;
    } while(false);

    if (ulock.owns_lock())
    {
        ulock.unlock();
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,  CK_OBJECT_HANDLE_PTR phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    return CKR_RANDOM_NO_RNG;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    return CKR_RANDOM_NO_RNG;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = CKR_FUNCTION_NOT_PARALLEL;
    } while(false);

    return rv;
}

CK_RV __attribute__((visibility("default"))) C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized ||
            !gSessionHandleCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionHandleCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = CKR_FUNCTION_NOT_PARALLEL;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV __attribute__((visibility("default"))) C_WaitForSlotEvent(CK_FLAGS        flags,
                                                                CK_SLOT_ID_PTR  pSlot,
                                                                CK_VOID_PTR     pReserved)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}
