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

#include "Decryption.h"

//---------------------------------------------------------------------------------------------
static CK_RV aesDecryptInit(const CK_SESSION_HANDLE& hSession,
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
            !gSessionCache->attributeSet(hKey, BoolAttribute::DECRYPT))
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
        if (!sessionParameters.activeOperation.test(ActiveOp::Decrypt_None))
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

        rv = P11Crypto::SymmetricProvider::decryptInit(hKey, aesCryptParams);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters.activeOperation.reset(ActiveOp::Decrypt_None);
        sessionParameters.activeOperation.set(ActiveOp::AesDecrypt_Init);
        sessionParameters.data.decryptParams.keyHandle         = hKey;
        sessionParameters.data.decryptParams.currentBufferSize = 0;
        sessionParameters.data.decryptParams.blockCipherMode   = aesCryptParams.cipherMode;
        sessionParameters.data.decryptParams.padding           = aesCryptParams.padding;
        sessionParameters.data.decryptParams.tagBytes          = aesCryptParams.tagBits >> 3;

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaDecryptInit(const CK_SESSION_HANDLE& hSession, const CK_MECHANISM_PTR pMechanism, const CK_OBJECT_HANDLE& hKey)
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
            !gSessionCache->attributeSet(hKey, BoolAttribute::DECRYPT))
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
        if (!sessionParameters.activeOperation.test(ActiveOp::Decrypt_None))
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

        sessionParameters.activeOperation.reset(ActiveOp::Decrypt_None);
        sessionParameters.activeOperation.set(ActiveOp::RsaDecrypt_Init);
        sessionParameters.data.decryptParams.keyHandle  = hKey;
        sessionParameters.data.decryptParams.rsaPadding = rsaPadding;

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, sessionParameters);

        rv = CKR_OK;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV decryptInit(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR  pMechanism,
                  CK_OBJECT_HANDLE  hKey)
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
            rv = aesDecryptInit(hSession, pMechanism, hKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (Utils::AttributeUtils::isAsymmetricMechanism(pMechanism))
        {
            rv = rsaDecryptInit(hSession, pMechanism, hKey);
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

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesDecrypt(const CK_SESSION_HANDLE& hSession,
                        const CK_BYTE_PTR        pEncryptedData,
                        const CK_ULONG&          ulEncryptedDataLen,
                        CK_BYTE_PTR              pData,
                        CK_ULONG_PTR             pulDataLen,
                        SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pEncryptedData || !pulDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t        keyHandle  = sessionParameters->data.decryptParams.keyHandle;
        BlockCipherMode cipherMode = sessionParameters->data.decryptParams.blockCipherMode;

        if (!gSessionCache->checkKeyType(keyHandle, CKK_AES) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::DECRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (gSessionCache->checkWrappingStatus(keyHandle))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        if (BlockCipherMode::cbc == cipherMode &&
            ulEncryptedDataLen % aesBlockSize != 0)
        {
            rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
            break;
        }

        uint32_t destBufferRequired = 0;
        uint32_t destBufferLength = *pulDataLen;

        if (!pData)
        {
            if (BlockCipherMode::gcm == cipherMode)
            {
                *pulDataLen = ulEncryptedDataLen - sessionParameters->data.decryptParams.tagBytes;
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

        rv = P11Crypto::SymmetricProvider::decryptUpdate(keyHandle,
                                                         pEncryptedData, ulEncryptedDataLen,
                                                         pData, destBufferLength,
                                                         &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        uint32_t decryptedBytes = destBufferRequired;
        destBufferRequired  = 0;

        rv = P11Crypto::SymmetricProvider::decryptFinal(keyHandle,
                                                        pData + decryptedBytes,
                                                        &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        decryptedBytes += destBufferRequired;

        P11Crypto::resetSessionParameters(sessionParameters, CurrentOperation::Decrypt);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);

        *pulDataLen = decryptedBytes;

    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaDecrypt(const CK_SESSION_HANDLE& hSession,
                        const CK_BYTE_PTR        pEncryptedData,
                        const CK_ULONG&          ulEncryptedDataLen,
                        CK_BYTE_PTR              pData,
                        CK_ULONG_PTR             pulDataLen,
                        SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pEncryptedData || !pulDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t keyHandle = sessionParameters->data.decryptParams.keyHandle;

        if (!gSessionCache->checkKeyType(keyHandle, CKK_RSA) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::DECRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (gSessionCache->checkWrappingStatus(keyHandle))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        uint32_t   destBufferRequired = 0;
        uint32_t   destBufferLength   = *pulDataLen;
        RsaPadding rsaPadding         = sessionParameters->data.decryptParams.rsaPadding;

        rv = P11Crypto::AsymmetricProvider::decrypt(keyHandle,
                                                    pEncryptedData, ulEncryptedDataLen,
                                                    pData, destBufferLength,
                                                    &destBufferRequired,
                                                    rsaPadding);
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

        P11Crypto::resetSessionParameters(sessionParameters, CurrentOperation::Decrypt);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV decrypt(CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR       pEncryptedData,
              CK_ULONG          ulEncryptedDataLen,
              CK_BYTE_PTR       pData,
              CK_ULONG_PTR      pulDataLen)
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

        if (!pEncryptedData || !pulDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::AesDecrypt_Init))
        {
            rv = aesDecrypt(hSession,
                            pEncryptedData, ulEncryptedDataLen,
                            pData, pulDataLen,
                            &sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (sessionParameters.activeOperation.test(ActiveOp::RsaDecrypt_Init))
        {
            rv = rsaDecrypt(hSession,
                            pEncryptedData, ulEncryptedDataLen,
                            pData, pulDataLen,
                            &sessionParameters);
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

    if (P11Crypto::cleanUpRequired(rv))
    {
        if (gSessionCache && gSessionCache->checkKeyType(sessionParameters.data.decryptParams.keyHandle, CKK_AES))
        {
            Utils::EnclaveUtils::cleanUpState(sessionParameters.data.decryptParams.keyHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Decrypt);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesDecryptUpdate(const CK_SESSION_HANDLE& hSession,
                              const CK_BYTE_PTR        pEncryptedData,
                              const CK_ULONG&          ulEncryptedDataLen,
                              CK_BYTE_PTR              pData,
                              CK_ULONG_PTR             pDataLen,
                              SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pEncryptedData || !pDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t        remainingSize = sessionParameters->data.decryptParams.currentBufferSize;
        CK_ULONG        maxSize       = ulEncryptedDataLen + remainingSize;
        uint32_t        keyHandle     = sessionParameters->data.decryptParams.keyHandle;
        BlockCipherMode cipherMode    = sessionParameters->data.decryptParams.blockCipherMode;

        if (gSessionCache->checkWrappingStatus(keyHandle))
        {
            rv = CKR_OPERATION_NOT_PERMITTED;
            break;
        }

        if (!gSessionCache->checkKeyType(keyHandle, CKK_AES) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::DECRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        uint32_t destBufferLength = *pDataLen;

        if (BlockCipherMode::cbc == cipherMode)
        {
            uint32_t paddingAdjustByte = sessionParameters->data.decryptParams.padding;
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

        uint32_t destBufferRequired  = 0;
        rv = P11Crypto::SymmetricProvider::decryptUpdate(keyHandle,
                                                         pEncryptedData, ulEncryptedDataLen,
                                                         pData, destBufferLength,
                                                         &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        sessionParameters->data.decryptParams.currentBufferSize += (ulEncryptedDataLen - destBufferRequired);
        sessionParameters->activeOperation.set(ActiveOp::AesDecrypt);
        sessionParameters->activeOperation.reset(ActiveOp::AesDecrypt_Init);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);

        *pDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV decryptUpdate(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR       pEncryptedData,
                    CK_ULONG          ulEncryptedDataLen,
                    CK_BYTE_PTR       pData,
                    CK_ULONG_PTR      pDataLen)
{
    CK_RV             rv = CKR_FUNCTION_FAILED;
    SessionParameters sessionParameters{};

    do
    {
        if (!isInitialized())
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

        if (!pEncryptedData || !pDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::AesDecrypt_Init) ||
            sessionParameters.activeOperation.test(ActiveOp::AesDecrypt))
        {
            rv = aesDecryptUpdate(hSession,
                                  pEncryptedData, ulEncryptedDataLen,
                                  pData, pDataLen,
                                  &sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if (sessionParameters.activeOperation.test(ActiveOp::Decrypt_None))
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
        if (gSessionCache && gSessionCache->checkKeyType(sessionParameters.data.decryptParams.keyHandle, CKK_AES))
        {
            Utils::EnclaveUtils::cleanUpState(sessionParameters.data.decryptParams.keyHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Decrypt);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesDecryptFinal(const CK_SESSION_HANDLE& hSession,
                             CK_BYTE_PTR              pData,
                             CK_ULONG_PTR             pDataLen,
                             SessionParameters*       sessionParameters)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pDataLen || !sessionParameters)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        uint32_t        tagBytes      = sessionParameters->data.decryptParams.tagBytes;
        uint32_t        remainingSize = sessionParameters->data.decryptParams.currentBufferSize + tagBytes;
        CK_ULONG        sizeRequired  = remainingSize;
        uint32_t        keyHandle     = sessionParameters->data.decryptParams.keyHandle;
        BlockCipherMode cipherMode    = sessionParameters->data.decryptParams.blockCipherMode;

        if (!gSessionCache->checkKeyType(keyHandle, CKK_AES) ||
            !gSessionCache->attributeSet(keyHandle, BoolAttribute::DECRYPT))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (BlockCipherMode::cbc == cipherMode)
        {
            bool isPadding = sessionParameters->data.decryptParams.padding;
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
            sizeRequired = sessionParameters->data.decryptParams.currentBufferSize - tagBytes;
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

        uint32_t destBufferRequired = *pDataLen;

        rv = P11Crypto::SymmetricProvider::decryptFinal(keyHandle, pData, &destBufferRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        P11Crypto::resetSessionParameters(sessionParameters, CurrentOperation::Decrypt);

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
        gSessionCache->add(sessionId, *sessionParameters);
        *pDataLen = destBufferRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV decryptFinal(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR       pData,
                   CK_ULONG_PTR      pDataLen)
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

        if (!pDataLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (sessionParameters.activeOperation.test(ActiveOp::AesDecrypt))
        {
            rv = aesDecryptFinal(hSession,
                                 pData, pDataLen,
                                 &sessionParameters);
            if (CKR_OK != rv)
            {
                break;
            }
        }
        else if(sessionParameters.activeOperation.test(ActiveOp::Decrypt_None))
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
        if (gSessionCache && gSessionCache->checkKeyType(sessionParameters.data.decryptParams.keyHandle, CKK_AES))
        {
            Utils::EnclaveUtils::cleanUpState(sessionParameters.data.decryptParams.keyHandle);

            P11Crypto::resetSessionParameters(&sessionParameters, CurrentOperation::Decrypt);

            uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();
            gSessionCache->add(sessionId, sessionParameters);
        }
    }

    return rv;
}