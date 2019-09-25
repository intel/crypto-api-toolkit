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

#include "Encryption.h"

//---------------------------------------------------------------------------------------------
static CK_RV aesEncryptInit(const CK_SESSION_HANDLE& hSession,
                            const CK_MECHANISM_PTR   pMechanism,
                            const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->checkKeyType(hKey, CKK_AES) ||
            !gSessionCache->attributeSet(hKey, BoolAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
        if (!sessionParameters.activeOperation.test(ActiveOp::Encrypt_None))
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        AesCryptParams aesCryptParams;
        rv = Utils::AttributeUtils::getAesParameters(pMechanism, &aesCryptParams);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = P11Crypto::SymmetricProvider::encryptInit(hKey, aesCryptParams);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.activeOperation.reset(ActiveOp::Encrypt_None);
        sessionParameters.activeOperation.set(ActiveOp::AesEncrypt_Init);
        sessionParameters.data.encryptParams.keyHandle         = hKey;
        sessionParameters.data.encryptParams.currentBufferSize = 0;
        sessionParameters.data.encryptParams.blockCipherMode   = aesCryptParams.cipherMode;
        sessionParameters.data.encryptParams.padding           = aesCryptParams.padding;
        sessionParameters.data.encryptParams.tagBytes          = aesCryptParams.tagBits >> 3;

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaEncryptInit(const CK_SESSION_HANDLE& hSession, const CK_MECHANISM_PTR pMechanism, const CK_OBJECT_HANDLE& hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache || !pMechanism)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->checkKeyType(hKey, CKK_RSA) ||
            !gSessionCache->attributeSet(hKey, BoolAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
        if (!sessionParameters.activeOperation.test(ActiveOp::Encrypt_None))
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        RsaPadding rsaPadding = RsaPadding::rsaNoPadding;

        if (CKM_RSA_PKCS == pMechanism->mechanism)
        {
            rsaPadding = RsaPadding::rsaPkcs1;
        }
        else if (CKM_RSA_PKCS_OAEP == pMechanism->mechanism)
        {
            rsaPadding = RsaPadding::rsaPkcs1Oaep;
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        sessionParameters.activeOperation.reset(ActiveOp::Encrypt_None);
        sessionParameters.activeOperation.set(ActiveOp::RsaEncrypt_Init);
        sessionParameters.data.encryptParams.keyHandle  = hKey;
        sessionParameters.data.encryptParams.rsaPadding = rsaPadding;

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV encryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (gSessionCache->checkWrappingStatus(hKey))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        if (Utils::AttributeUtils::isSymmetricMechanism(pMechanism))
        {
            rv = aesEncryptInit(hSession, pMechanism, hKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (Utils::AttributeUtils::isAsymmetricMechanism(pMechanism))
        {
            rv = rsaEncryptInit(hSession, pMechanism, hKey);
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

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesEncryptUpdate(const CK_SESSION_HANDLE& hSession,
                              const CK_BYTE_PTR        pData,
                              const CK_ULONG&          ulDataLen,
                              CK_BYTE_PTR              pEncryptedData,
                              CK_ULONG_PTR             pulEncryptedDataLen,
                              SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pData || !pulEncryptedDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t keyHandle     = sessionParameters->data.encryptParams.keyHandle;
        uint32_t remainingSize = sessionParameters->data.encryptParams.currentBufferSize;
        CK_ULONG maxSize       = ulDataLen + remainingSize;

        if (gSessionCache->checkWrappingStatus(keyHandle))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        if (!gSessionCache->checkKeyType(keyHandle, CKK_AES) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == sessionParameters->data.encryptParams.blockCipherMode)
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

        uint32_t destBufferRequired = 0;
        uint32_t destBufferLength   = *pulEncryptedDataLen;
        rv = P11Crypto::SymmetricProvider::encryptUpdate(keyHandle,
                                                         pData, ulDataLen,
                                                         pEncryptedData, destBufferLength,
                                                         &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters->data.encryptParams.currentBufferSize += (ulDataLen - destBufferRequired);
        sessionParameters->activeOperation.set(ActiveOp::AesEncrypt);
        sessionParameters->activeOperation.reset(ActiveOp::AesEncrypt_Init);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);

        *pulEncryptedDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV encryptUpdate(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR       pData,
                    CK_ULONG          ulDataLen,
                    CK_BYTE_PTR       pEncryptedData,
                    CK_ULONG_PTR      pulEncryptedDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(hSession);

        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::AesEncrypt_Init) ||
            sessionParameters.activeOperation.test(ActiveOp::AesEncrypt))
        {
            rv = aesEncryptUpdate(hSession,
                                  pData, ulDataLen,
                                  pEncryptedData, pulEncryptedDataLen,
                                  &sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (sessionParameters.activeOperation.test(ActiveOp::Encrypt_None))
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

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache && gSessionCache->checkKeyType(sessionParameters.data.encryptParams.keyHandle, CKK_AES))
        {
            Utils::EnclaveUtils::cleanUpState(sessionParameters.data.encryptParams.keyHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Encrypt);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesEncrypt(const CK_SESSION_HANDLE& hSession,
                        const CK_BYTE_PTR        pData,
                        const CK_ULONG&          ulDataLen,
                        CK_BYTE_PTR              pEncryptedData,
                        CK_ULONG_PTR             pulEncryptedDataLen,
                        SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pData || !pulEncryptedDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t keyHandle = sessionParameters->data.encryptParams.keyHandle;

        if (gSessionCache->checkWrappingStatus(keyHandle))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        if (!gSessionCache->checkKeyType(keyHandle, CKK_AES) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        CK_ULONG maxSize = ulDataLen;
        if (BlockCipherMode::cbc == sessionParameters->data.encryptParams.blockCipherMode)
        {
            CK_ULONG remainingLength = ulDataLen % aesBlockSize;
            if (!sessionParameters->data.encryptParams.padding && remainingLength != 0)
            {
                rv = CKR_DATA_LEN_RANGE;
                break;
            }

            if (0 != remainingLength)
            {
                maxSize = ulDataLen + aesBlockSize - remainingLength;
            }
            else if (sessionParameters->data.encryptParams.padding)
            {
                maxSize = ulDataLen + aesBlockSize;
            }
        }
        else if (BlockCipherMode::ctr == sessionParameters->data.encryptParams.blockCipherMode)
        {
            maxSize = ulDataLen;
        }
        else if (BlockCipherMode::gcm == sessionParameters->data.encryptParams.blockCipherMode)
        {
            maxSize = ulDataLen + sessionParameters->data.encryptParams.tagBytes;
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

        uint32_t destBufferRequired = 0;
        uint32_t destBufferLength   = *pulEncryptedDataLen;
        rv = P11Crypto::SymmetricProvider::encryptUpdate(keyHandle,
                                                         pData, ulDataLen,
                                                         pEncryptedData, destBufferLength,
                                                         &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t encryptedBytes = destBufferRequired;
        destBufferRequired = 0;

        rv = P11Crypto::SymmetricProvider::encryptFinal(keyHandle,
                                                        pEncryptedData + encryptedBytes,
                                                        &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        encryptedBytes += destBufferRequired;

        P11Crypto::resetSessionParameters(sessionParameters, CurrentOperation::Encrypt);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);

        *pulEncryptedDataLen = encryptedBytes;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaEncrypt(const CK_SESSION_HANDLE& hSession,
                        const CK_BYTE_PTR        pData,
                        const CK_ULONG&          ulDataLen,
                        CK_BYTE_PTR              pEncryptedData,
                        CK_ULONG_PTR             pulEncryptedDataLen,
                        SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pData || !pulEncryptedDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t keyHandle = sessionParameters->data.encryptParams.keyHandle;

        if (gSessionCache->checkWrappingStatus(keyHandle))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        if (!gSessionCache->checkKeyType(keyHandle, CKK_RSA) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        uint32_t   destBufferRequired = 0;
        uint32_t   destBufferLength   = *pulEncryptedDataLen;
        RsaPadding rsaPadding         = sessionParameters->data.encryptParams.rsaPadding;

        rv = P11Crypto::AsymmetricProvider::encrypt(keyHandle,
                                                    pData, ulDataLen,
                                                    pEncryptedData, destBufferLength,
                                                    &destBufferRequired,
                                                    rsaPadding);
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

        P11Crypto::resetSessionParameters(sessionParameters, CurrentOperation::Encrypt);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV encrypt(CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR       pData,
              CK_ULONG          ulDataLen,
              CK_BYTE_PTR       pEncryptedData,
              CK_ULONG_PTR      pulEncryptedDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(hSession);

        if (!pData || !pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::AesEncrypt_Init))
        {
            rv = aesEncrypt(hSession,
                            pData, ulDataLen,
                            pEncryptedData, pulEncryptedDataLen,
                            &sessionParameters);
        }
        else if (sessionParameters.activeOperation.test(ActiveOp::RsaEncrypt_Init))
        {
            rv = rsaEncrypt(hSession,
                            pData, ulDataLen,
                            pEncryptedData, pulEncryptedDataLen,
                            &sessionParameters);
        }
        else
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
        }
    } while (false);

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache && gSessionCache->checkKeyType(sessionParameters.data.encryptParams.keyHandle, CKK_AES))
        {
            Utils::EnclaveUtils::cleanUpState(sessionParameters.data.encryptParams.keyHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Encrypt);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesEncryptFinal(const CK_SESSION_HANDLE& hSession,
                             CK_BYTE_PTR              pEncryptedData,
                             CK_ULONG_PTR             pulEncryptedDataLen,
                             SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pulEncryptedDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t        remainingSize = sessionParameters->data.encryptParams.currentBufferSize + sessionParameters->data.encryptParams.tagBytes;
        CK_ULONG        size          = remainingSize;
        uint32_t        keyHandle     = sessionParameters->data.encryptParams.keyHandle;
        BlockCipherMode cipherMode    = sessionParameters->data.encryptParams.blockCipherMode;

        if (!gSessionCache->checkKeyType(keyHandle, CKK_AES) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::ENCRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == cipherMode)
        {
            bool isPadding = sessionParameters->data.encryptParams.padding;
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
            size = sessionParameters->data.encryptParams.tagBytes;
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

        uint32_t destBufferRequired = 0;
        rv = P11Crypto::SymmetricProvider::encryptFinal(keyHandle, pEncryptedData, &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        P11Crypto::resetSessionParameters(sessionParameters, CurrentOperation::Encrypt);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);

        *pulEncryptedDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV encryptFinal(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pEncryptedData,
                   CK_ULONG_PTR      pulEncryptedDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        sessionParameters = gSessionCache->getSessionParameters(hSession);

        if (!pulEncryptedDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::AesEncrypt))
        {
            rv = aesEncryptFinal(hSession,
                                 pEncryptedData, pulEncryptedDataLen,
                                 &sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if(sessionParameters.activeOperation.test(ActiveOp::Encrypt_None))
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

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache && gSessionCache->checkKeyType(sessionParameters.data.encryptParams.keyHandle, CKK_AES))
        {
            Utils::EnclaveUtils::cleanUpState(sessionParameters.data.encryptParams.keyHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Encrypt);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}