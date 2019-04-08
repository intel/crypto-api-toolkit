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

#include <mbusafecrt.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include "SymmetricCrypto.h"
#include "AsymmetricCrypto.h"
#include "HashCrypto.h"
#include "CryptoEnclaveDefs.h"
#include "p11Enclave_t.h"
#include "HashDefs.h"

using namespace CryptoSgx;

SymmetricCrypto  symmetricCrypto;
AsymmetricCrypto asymmetricCrypto;
CryptoHash       cryptoHash;

#ifdef _WIN32
    extern "C" void _mm_lfence(void);
#else
    extern "C" void __builtin_ia32_lfence(void);
#endif

//---------------------------------------------------------------------------------------------------------------------
static inline bool checkUserCheckPointer(const uint8_t* ptr, uint32_t& length)
{
    bool result = false;

    if (!ptr || !sgx_is_outside_enclave(ptr, length))
    {
        result = false;
    }
    else
    {
        result = true;
    }

    return result;
}

//---------------------------------------------------------------------------------------------------------------------
static inline bool isInsideEnclave(const void* ptr, size_t length)
{
    bool result = false;

    if (!ptr || !sgx_is_within_enclave(ptr, length))
    {
        result = false;
    }
    else
    {
        result = true;
    }

    return result;
}

/*
 * ECALLS
 */
// enclave init/deinit operations
//---------------------------------------------------------------------------------------------------------------------
SgxStatus initCryptoEnclave(uint8_t providerType)
{
    SgxStatus    status             = static_cast<int>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
    ProviderType cryptoProviderType = static_cast<ProviderType>(providerType);

    switch (cryptoProviderType)
    {
        case ProviderType::PKCS11:
            symmetricCrypto.clearKeys();
            asymmetricCrypto.clearKeys();
            cryptoHash.clearStates();
            break;
        default:
            status = static_cast<int>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
    }

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus deinitCryptoEnclave(uint8_t providerType)
{
    return initCryptoEnclave(providerType);
}

// symmetric operations
//---------------------------------------------------------------------------------------------------------------------
SgxStatus generateSymmetricKey(uint32_t*  keyId,
                               uint16_t   keySize)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(keyId)>::type);

    do
    {
        result = keyId                                                                 &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(keyId), ptrDataSize) &&
                 (0 == *keyId);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (!(static_cast<uint16_t>(SymmetricKeySize::keyLength128) == keySize ||
              static_cast<uint16_t>(SymmetricKeySize::keyLength192) == keySize ||
              static_cast<uint16_t>(SymmetricKeySize::keyLength256) == keySize))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = generateId(keyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            break;
        }

        status = symmetricCrypto.generateSymmetricKey(*keyId,
                                                      static_cast<SymmetricKeySize>(keySize));
    } while (false);
    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus destroySymmetricKey(uint32_t keyId)
{
    SgxStatus status{ 0 };

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = symmetricCrypto.removeSymmetricKey(keyId);
    } while (false);

    return status;
}

SgxStatus importSymmetricKey(uint32_t*       keyId,
                             const uint8_t*  keyBuffer,
                             uint16_t        keySize)
{
#ifndef IMPORT_RAW_KEY
    return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
#else
    bool        bImportKeyBuffer = true;
    bool        result           = false;
    uint32_t    ptrDataSize      = sizeof(std::remove_pointer<decltype(keyId)>::type);
    SgxStatus   status{ 0 };

    do
    {
        result = keyId                                                                 &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(keyId), ptrDataSize) &&
                 (0 == *keyId);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

#ifndef IMPORT_KEY_FOR_HMAC
        if (static_cast<uint16_t>(SymmetricKeySize::keyLength256) < keySize)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }
#else
        if (maxAesKeySizeForHmacImport < keySize)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }
#endif
        status = generateId(keyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            break;
        }
        status = symmetricCrypto.importRawKey(*keyId,
                                              keyBuffer,
                                              keySize);
    } while (false);
    return status;
#endif
}

//---------------------------------------------------------------------------------------------------------------------
void clearKeys()
{
    symmetricCrypto.clearKeys();
    asymmetricCrypto.clearKeys();
    cryptoHash.clearStates();
}

// hash operations
//---------------------------------------------------------------------------------------------------------------------
SgxStatus digestInit(uint32_t   hashId,
                     uint32_t   keyIdHmac,
                     uint8_t    hashMode,
                     uint8_t    hmac)
{
    SgxStatus                  status        = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
    bool                       result        = false;
    uint32_t                   secretLen     = 0;
    std::unique_ptr<uint8_t[]> secretBuffer{};
    SymmetricKey               symKey{};

    do
    {
        if (!hashId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = symmetricCrypto.getSymmetricKey(keyIdHmac, symKey);
        if (hmac && !result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (0 == hashDigestLengthMap.count(static_cast<HashMode>(hashMode)))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (!hmac)
        {
            secretBuffer.reset(0);
            secretLen = 0;
        }
        else
        {
            secretLen = symKey.key.size();
            secretBuffer.reset(new uint8_t[secretLen]);

            if (!secretBuffer.get())
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                break;
            }
            memcpy_s(secretBuffer.get(), secretLen, symKey.key.get(), secretLen);
        }

        status =  cryptoHash.createHashState(hashId,
                                             static_cast<HashMode>(hashMode),
                                             static_cast<bool>(hmac),
                                             secretBuffer.get(),
                                             secretLen);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus digestUpdate(uint32_t         hashId,
                       const uint8_t*   sourceBuffer,
                       uint32_t         sourceBufferLen)
{
    SgxStatus status{ 0 };
    bool      result = hashId || checkUserCheckPointer(sourceBuffer, sourceBufferLen);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }
#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif
        status = cryptoHash.hashData(hashId,
                                     sourceBuffer,
                                     sourceBufferLen);
    } while (false);

    if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
    {
        SgxStatus sgxStatus = destroyHashState(hashId);
    }

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus digestFinal(uint32_t  hashId,
                      uint8_t*  destBuffer,
                      uint32_t  destBufferLen)
{
    SgxStatus status{ 0 };

    do
    {
        if (!hashId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        status = cryptoHash.getHashDigest(hashId,
                                          destBuffer,
                                          destBufferLen);
    } while (false);

    if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
    {
        SgxStatus sgxStatus = destroyHashState(hashId);
    }

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus destroyHashState(uint32_t hashId)
{
    SgxStatus status { 0 };

    do
    {
        if (!hashId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }
        status = cryptoHash.destroyHash(hashId);
    } while (false);

    return status;
}

// asymmetric operations
//---------------------------------------------------------------------------------------------------------------------
SgxStatus generateAsymmetricKey(uint32_t*   publicKeyId,
                                uint32_t*   privateKeyId,
                                uint16_t    modulusSize)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(publicKeyId)>::type);

    do
    {
        if (!publicKeyId || !privateKeyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (!(static_cast<uint16_t>(AsymmetricKeySize::keyLength1024) == modulusSize  ||
              static_cast<uint16_t>(AsymmetricKeySize::keyLength2048) == modulusSize  ||
              static_cast<uint16_t>(AsymmetricKeySize::keyLength3072) == modulusSize  ||
              static_cast<uint16_t>(AsymmetricKeySize::keyLength4096) == modulusSize))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(publicKeyId), ptrDataSize) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(privateKeyId), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = generateId(publicKeyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            break;
        }

        status = generateId(privateKeyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            break;
        }

        status = asymmetricCrypto.generateAsymmetricKey(*publicKeyId, *privateKeyId, reinterpret_cast<AsymmetricKeySize&>(modulusSize));

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *publicKeyId  = 0;
            *privateKeyId = 0;
            break;
        }
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus destroyAsymmetricKey(uint32_t keyId)
{
    SgxStatus status{ 0 };

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = asymmetricCrypto.removeAsymmetricKey(keyId);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricEncryptInit(uint32_t         keyId,
                               const uint8_t*   iv,
                               uint32_t         ivSize,
                               const uint8_t*   aad,
                               uint32_t         aadSize,
                               uint8_t          cipherMode,
                               int              padding,
                               uint32_t         tagBits,
                               int              counterBits)
{
    SgxStatus status{ 0 };

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        bool result = symmetricCrypto.checkWrappingStatus(keyId);
        if (result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        status = symmetricCrypto.encryptInit(keyId,
                                             static_cast<BlockCipherMode>(cipherMode),
                                             iv,
                                             ivSize,
                                             aad,
                                             aadSize,
                                             padding,
                                             tagBits,
                                             counterBits);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricDecryptInit(uint32_t         keyId,
                               const uint8_t*   iv,
                               uint32_t         ivSize,
                               const uint8_t*   aad,
                               uint32_t         aadSize,
                               uint8_t          cipherMode,
                               int              padding,
                               uint32_t         tagBits,
                               int              counterBits)
{
    SgxStatus status{ 0 };

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        bool result = symmetricCrypto.checkWrappingStatus(keyId);
        if (result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        status = symmetricCrypto.decryptInit(keyId,
                                             static_cast<BlockCipherMode>(cipherMode),
                                             iv,
                                             ivSize,
                                             aad,
                                             aadSize,
                                             padding,
                                             tagBits,
                                             counterBits);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricEncryptUpdate(uint32_t       keyId,
                                 const uint8_t* sourceBuffer,
                                 uint32_t       sourceBufferLen,
                                 uint8_t*       destBuffer,
                                 uint32_t       destBufferLen,
                                 uint32_t*      destBufferWritten)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(sourceBuffer, sourceBufferLen) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::symmetric);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        status = symmetricCrypto.encryptUpdate(keyId,
                                               sourceBuffer,
                                               sourceBufferLen,
                                               destBuffer,
                                               destBufferLen,
                                               destBufferWritten);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricEncrypt(uint32_t         keyId,
                           const uint8_t*   sourceBuffer,
                           uint32_t         sourceBufferLen,
                           uint8_t*         destBuffer,
                           uint32_t         destBufferLen,
                           uint32_t*        destBufferWritten)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);
    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(sourceBuffer, sourceBufferLen) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::symmetric);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        status = symmetricCrypto.encryptUpdate(keyId,
                                               sourceBuffer,
                                               sourceBufferLen,
                                               destBuffer,
                                               destBufferLen,
                                               destBufferWritten,
                                               true);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricEncryptFinal(uint32_t    keyId,
                                uint8_t*    destBuffer,
                                uint32_t*   destBufferWritten)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, *destBufferWritten);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

        status = symmetricCrypto.encryptFinal(keyId,
                                              destBuffer,
                                              destBufferWritten);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricDecryptUpdate(uint32_t       keyId,
                                 const uint8_t* sourceBuffer,
                                 uint32_t       sourceBufferLen,
                                 uint8_t*       destBuffer,
                                 uint32_t       destBufferLen,
                                 uint32_t*      destBufferWritten)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(sourceBuffer, sourceBufferLen)  &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::symmetric);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        status = symmetricCrypto.decryptUpdate(keyId,
                                               sourceBuffer,
                                               sourceBufferLen,
                                               destBuffer,
                                               destBufferLen,
                                               destBufferWritten);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricDecrypt(uint32_t         keyId,
                           const uint8_t*   sourceBuffer,
                           uint32_t         sourceBufferLen,
                           uint8_t*         destBuffer,
                           uint32_t         destBufferLen,
                           uint32_t*        destBufferWritten)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(sourceBuffer, sourceBufferLen) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::symmetric);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        status = symmetricCrypto.decryptUpdate(keyId,
                                               sourceBuffer,
                                               sourceBufferLen,
                                               destBuffer,
                                               destBufferLen,
                                               destBufferWritten,
                                               true);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus symmetricDecryptFinal(uint32_t    keyId,
                                uint8_t*    destBuffer,
                                uint32_t*   destBufferWritten)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, *destBufferWritten);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

        status = symmetricCrypto.decryptFinal(keyId,
                                              destBuffer,
                                              destBufferWritten);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus asymmetricEncrypt(uint32_t        keyId,
                            const uint8_t*  sourceBuffer,
                            uint32_t        sourceBufferLen,
                            uint8_t*        destBuffer,
                            uint32_t        destBufferLen,
                            uint32_t*       destBufferRequiredLength,
                            uint8_t         rsaPadding)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferRequiredLength)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(sourceBuffer, sourceBufferLen) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferRequiredLength), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = destBufferRequiredLength &&
                 sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::asymmetric);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        if (destBuffer)
        {
            if (destBufferLen > static_cast<uint32_t>(SgxMaxDataLimitsInBytes::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
                break;
            }
        }

        bool result = asymmetricCrypto.checkWrappingStatus(keyId);
        if (result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        status = asymmetricCrypto.encryptBuffer(keyId,
                                                sourceBuffer,
                                                sourceBufferLen,
                                                destBuffer,
                                                destBufferLen,
                                                destBufferRequiredLength,
                                                static_cast<RsaPadding>(rsaPadding));
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus asymmetricDecrypt(uint32_t        keyId,
                            const uint8_t*  sourceBuffer,
                            uint32_t        sourceBufferLen,
                            uint8_t*        destBuffer,
                            uint32_t        destBufferLen,
                            uint32_t*       destBufferRequiredLength,
                            uint8_t         rsaPadding)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferRequiredLength)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }
        result = checkUserCheckPointer(sourceBuffer, sourceBufferLen) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferRequiredLength), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }
#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = destBufferRequiredLength &&
                 sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::asymmetric);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        if (destBuffer)
        {
            if (destBufferLen > static_cast<uint32_t>(SgxMaxDataLimitsInBytes::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
                break;
            }
        }

        bool result = asymmetricCrypto.checkWrappingStatus(keyId);
        if (result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        status = asymmetricCrypto.decryptBuffer(keyId,
                                                sourceBuffer,
                                                sourceBufferLen,
                                                destBuffer,
                                                destBufferLen,
                                                destBufferRequiredLength,
                                                static_cast<RsaPadding>(rsaPadding));
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus asymmetricSign(uint32_t       keyId,
                         const uint8_t* sourceBuffer,
                         uint32_t       sourceBufferLen,
                         uint8_t*       destBuffer,
                         uint32_t       destBufferLen,
                         uint32_t*      destBufferRequiredLength,
                         uint32_t       hashAlgorithm,
                         uint8_t        rsaPadding,
                         uint8_t        hashMode,
                         uint32_t       salt)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferRequiredLength)>::type);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferRequiredLength), ptrDataSize);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = asymmetricCrypto.sign(keyId,
                                       sourceBuffer,
                                       sourceBufferLen,
                                       destBuffer,
                                       destBufferLen,
                                       destBufferRequiredLength,
                                       hashAlgorithm,
                                       static_cast<RsaPadding>(rsaPadding),
                                       static_cast<HashMode>(hashMode),
                                       salt);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus asymmetricVerify(uint32_t       keyId,
                           const uint8_t* sourceBuffer,
                           uint32_t       sourceBufferLen,
                           const uint8_t* signatureBuffer,
                           uint32_t       signatureBufferLen,
                           uint32_t       hashAlgorithm,
                           uint8_t        rsaPadding,
                           uint8_t        hashMode,
                           uint32_t       salt)
{
    if (!keyId)
    {
        return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
    }

    return asymmetricCrypto.verifySign(keyId,
                                       sourceBuffer,
                                       sourceBufferLen,
                                       signatureBuffer,
                                       signatureBufferLen,
                                       hashAlgorithm,
                                       static_cast<RsaPadding>(rsaPadding),
                                       static_cast<HashMode>(hashMode),
                                       salt);
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus generateId(uint32_t* keyId)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(keyId)>::type);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(keyId), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = sgx_read_rand(reinterpret_cast<unsigned char*>(keyId), sizeof(uint32_t));
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus wrapSymmetricKeyWithSymmetricKey(uint32_t         keyId,
                                           uint32_t         keyIdData,
                                           const uint8_t*   iv,
                                           uint32_t         ivSize,
                                           const uint8_t*   aad,
                                           uint32_t         aadSize,
                                           uint8_t          cipherMode,
                                           int              padding,
                                           uint32_t         tagBits,
                                           int              counterBits,
                                           uint8_t*         destBuffer,
                                           uint32_t         destBufferLen,
                                           uint32_t*        destBufferWritten)
{
    bool         result = keyId && keyIdData;
    SgxStatus    status{ 0 };
    SymmetricKey symKey{};
    SymmetricKey symKeyData{};
    uint32_t     ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }
#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        result = symmetricCrypto.getSymmetricKey(keyIdData, symKeyData);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        if (!destBuffer)
        {
            if (BlockCipherMode::gcm == static_cast<BlockCipherMode>(cipherMode))
            {
                *destBufferWritten = symKeyData.key.size() + tagBits / bitsPerByte;
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                break;
            }
            else if (BlockCipherMode::ctr == static_cast<BlockCipherMode>(cipherMode))
            {
                *destBufferWritten = symKeyData.key.size();
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                break;
            }
            else if (BlockCipherMode::cbc == static_cast<BlockCipherMode>(cipherMode))
            {
                if ((BlockCipherPadding::NoPadding == static_cast<BlockCipherPadding>(padding)))
                {
                    *destBufferWritten = symKeyData.key.size();
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                    break;
                }
                else
                {
                    *destBufferWritten = symKeyData.key.size() + aesBlockSize;
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                    break;
                }
            }
        }

        status = symmetricCrypto.encryptInit(keyId,
                                             static_cast<BlockCipherMode>(cipherMode),
                                             iv,
                                             ivSize,
                                             aad,
                                             aadSize,
                                             padding,
                                             tagBits,
                                             counterBits);

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        status = symmetricCrypto.encryptUpdate(keyId,
                                               symKeyData.key.get(),
                                               symKeyData.key.size(),
                                               destBuffer,
                                               destBufferLen,
                                               destBufferWritten,
                                               true);
    } while (false);

    if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) == status)
    {
        symmetricCrypto.markAsWrappingKey(keyId);
    }

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unwrapSymmetricKeyWithSymmetricKey(uint32_t       keyId,
                                             uint32_t*      unwrappedKeyId,
                                             const uint8_t* sourceBuffer,
                                             uint32_t       sourceBufferLen,
                                             const uint8_t* iv,
                                             uint32_t       ivSize,
                                             const uint8_t* aad,
                                             uint32_t       aadSize,
                                             uint8_t        cipherMode,
                                             int            padding,
                                             uint32_t       tagBits,
                                             int            counterBits)
{
    SgxStatus status{ 0 };
    bool      result      = keyId && unwrappedKeyId;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(unwrappedKeyId)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(unwrappedKeyId), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (sourceBuffer)
        {
            result = checkUserCheckPointer(sourceBuffer, sourceBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        SymmetricKey symKey{};

        result = symmetricCrypto.getSymmetricKey(keyId, symKey);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        status = symmetricCrypto.decryptInit(keyId,
                                             static_cast<BlockCipherMode>(cipherMode),
                                             iv,
                                             ivSize,
                                             aad,
                                             aadSize,
                                             padding,
                                             tagBits,
                                             counterBits);

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        result = sourceBufferLen <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::symmetric);

        if (!result)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
        }

        // Retrieve the destination buffer size required..
        uint32_t destBufferWritten = 0;
        status = symmetricCrypto.decryptUpdate(keyId,
                                               sourceBuffer,
                                               sourceBufferLen,
                                               nullptr,
                                               0,
                                               &destBufferWritten,
                                               true);

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        uint32_t tempDestBufferLen = destBufferWritten;
        std::unique_ptr<uint8_t[]> tempDestBuffer(new uint8_t[tempDestBufferLen], std::default_delete<uint8_t[]>());
        if (!tempDestBuffer.get())
        {
            result = false;
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }
        destBufferWritten = 0;
        status = symmetricCrypto.decryptUpdate(keyId,
                                               sourceBuffer,
                                               sourceBufferLen,
                                               tempDestBuffer.get(),
                                               tempDestBufferLen,
                                               &destBufferWritten,
                                               true);

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        status = generateId(unwrappedKeyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        SymmetricKey newSymKey{};

        newSymKey.key.allocate(destBufferWritten);
        newSymKey.key.fromData(tempDestBuffer.get(), destBufferWritten);
        symmetricCrypto.addSymmetricKey(*unwrappedKeyId, newSymKey);
        memset_s(tempDestBuffer.get(), tempDestBufferLen, 0, tempDestBufferLen);
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus platformBindSymmetricKey(uint32_t     keyId,
                                   uint8_t*     destBuffer,
                                   uint32_t     destBufferLen,
                                   uint32_t*    destBufferWritten)
{
    SgxStatus   status{ 0 };
    bool        result      = keyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = symmetricCrypto.exportSymmetricKeyPbind(keyId,
                                                         destBuffer,
                                                         destBufferLen,
                                                         destBufferWritten);

    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unwrapAndImportPlatformBoundSymmetricKey(uint32_t*         keyId,
                                                   const uint8_t*    sourceBuffer,
                                                   uint32_t          sourceBufferLen)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(keyId)>::type);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(keyId), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = generateId(keyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        status = symmetricCrypto.importSymmetricKeyPbind(*keyId,
                                                         sourceBuffer,
                                                         sourceBufferLen);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus platformBindAsymmetricKey(uint32_t    keyId,
                                    uint8_t*    destBuffer,
                                    uint32_t    destBufferLen,
                                    uint32_t*   destBufferWritten)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = asymmetricCrypto.exportAsymmetricKeyPbind(keyId,
                                                           destBuffer,
                                                           destBufferLen,
                                                           destBufferWritten);

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unwrapAndImportPlatformBoundAsymmetricKey(uint32_t*       publicKeyId,
                                                    uint32_t*       privateKeyId,
                                                    const uint8_t*  sourceBuffer,
                                                    uint32_t        sourceBufferLen)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(publicKeyId)>::type);;
    do
    {
        if (!publicKeyId || !privateKeyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(publicKeyId), ptrDataSize) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(privateKeyId), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = generateId(publicKeyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        status = generateId(privateKeyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        status = asymmetricCrypto.importAsymmetricKeyPbind(publicKeyId,
                                                           privateKeyId,
                                                           sourceBuffer,
                                                           sourceBufferLen);

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *publicKeyId = 0;
            *privateKeyId = 0;
            break;
        }
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus wrapWithAsymmetricKey(uint32_t  asymmetricKeyId,
                                uint32_t  symmetricKeyId,
                                uint8_t*  destBuffer,
                                uint32_t  destBufferLen,
                                uint32_t* destBufferWritten,
                                uint8_t   rsaPadding)
{
    SgxStatus   status{ 0 };
    bool        result      = asymmetricKeyId && symmetricKeyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer)
        {
            result = checkUserCheckPointer(destBuffer, destBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        SymmetricKey symKey{};

        result = symmetricCrypto.getSymmetricKey(symmetricKeyId, symKey);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = destBufferWritten &&
                 symKey.key.size() <= static_cast<uint32_t>(SgxMaxDataLimitsInBytes::asymmetric);

        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
            break;
        }

        if (destBuffer)
        {
            if (destBufferLen > static_cast<uint32_t>(SgxMaxDataLimitsInBytes::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE);
                break;
            }
        }

        status = asymmetricCrypto.encryptBuffer(asymmetricKeyId,
                                                symKey.key.get(),
                                                symKey.key.size(),
                                                destBuffer,
                                                destBufferLen,
                                                destBufferWritten,
                                                static_cast<RsaPadding>(rsaPadding));
    } while (false);

    if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) == status)
    {
        asymmetricCrypto.markAsWrappingKey(asymmetricKeyId);
    }

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unwrapWithAsymmetricKey(uint32_t          asymmetricKeyId,
                                  uint32_t*         unwrappedKeyId,
                                  const uint8_t*    sourceBuffer,
                                  uint32_t          sourceBufferLen,
                                  uint8_t           rsaPadding)
{
    SgxStatus   status{ 0 };
    bool        result      = asymmetricKeyId;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(unwrappedKeyId)>::type);

    do
    {
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(unwrappedKeyId), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (sourceBuffer)
        {
            result = checkUserCheckPointer(sourceBuffer, sourceBufferLen);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        uint32_t destBufferRequiredLength = 0;
        uint32_t tempDestBufferSize = 0;

        status = asymmetricCrypto.decryptBuffer(asymmetricKeyId,
                                                sourceBuffer,
                                                sourceBufferLen,
                                                nullptr,
                                                0,
                                                &destBufferRequiredLength,
                                                static_cast<RsaPadding>(rsaPadding));

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        tempDestBufferSize = destBufferRequiredLength;
        std::unique_ptr<uint8_t[]> tempDestBuffer(new uint8_t[tempDestBufferSize], std::default_delete<uint8_t[]>());
        if (!tempDestBuffer.get())
        {
            result = false;
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }
        status = asymmetricCrypto.decryptBuffer(asymmetricKeyId,
                                                sourceBuffer,
                                                sourceBufferLen,
                                                tempDestBuffer.get(),
                                                tempDestBufferSize,
                                                &destBufferRequiredLength,
                                                static_cast<RsaPadding>(rsaPadding));

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        status = generateId(unwrappedKeyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        SymmetricKey newSymKey{};

        newSymKey.key.allocate(tempDestBufferSize);
        newSymKey.key.fromData(tempDestBuffer.get(), tempDestBufferSize);
        symmetricCrypto.addSymmetricKey(*unwrappedKeyId, newSymKey);

    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus asymmetricExportKey(uint32_t  keyId,
                              uint8_t*  destBuffer,
                              uint32_t  destBufferLen,
                              uint32_t* destBufferWritten,
                              uint32_t* modulusSize,
                              uint32_t* exponentSize)
{
    SgxStatus status      = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);
    bool      result  = false;

    do
    {
        if (!keyId || !destBufferWritten || !modulusSize || !exponentSize)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer && !checkUserCheckPointer(destBuffer, destBufferLen))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize) &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(modulusSize), ptrDataSize)       &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(exponentSize), ptrDataSize);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        status = asymmetricCrypto.exportPublicKey(keyId,
                                                  destBuffer,
                                                  destBufferLen,
                                                  modulusSize,
                                                  exponentSize);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) == status)
        {
            *destBufferWritten = *modulusSize + *exponentSize;
        }
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus asymmetricImportKey(uint32_t*  keyId,
                              uint8_t*   modulusBuffer,
                              uint32_t   modulusBufferLen,
                              uint8_t*   exponentBuffer,
                              uint32_t   exponentBufferLen)
 {
    SgxStatus status      = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(keyId)>::type);
    bool      result      = false;

    do
    {
        if (!keyId || !modulusBuffer || !exponentBuffer)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(keyId), ptrDataSize) &&
                 checkUserCheckPointer(modulusBuffer, modulusBufferLen)                &&
                 checkUserCheckPointer(exponentBuffer, exponentBufferLen);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        status = generateId(keyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            break;
        }

        status = asymmetricCrypto.importPublicKey(*keyId,
                                                  modulusBuffer,
                                                  modulusBufferLen,
                                                  exponentBuffer,
                                                  exponentBufferLen);
    } while (false);

    return status;
 }

 //---------------------------------------------------------------------------------------------------------------------
SgxStatus createReportForKeyHandle(uint32_t             keyId,
                                   sgx_target_info_t*   targetInfo,
                                   sgx_report_t*        sgxReport)
{
    sgx_report_data_t reportData;
    SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (!isInsideEnclave(targetInfo, sizeof(sgx_target_info_t)) ||
            !isInsideEnclave(sgxReport, sizeof(sgx_report_t)))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = asymmetricCrypto.getPublicKeyHash(keyId, reportData.d, SGX_REPORT_DATA_SIZE, HashMode::sha256);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }
        status = sgx_create_report(targetInfo, &reportData, sgxReport);
    } while (false);
    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus sealData(uint8_t*   sourceBuffer,
                   uint32_t   sourceBufferLen,
                   uint8_t*   destBuffer,
                   uint32_t   destBufferLen,
                   uint32_t*  destBufferWritten)
{
    SgxCryptStatus  status              = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
    bool            result              = false;
    uint32_t        ptrDataSize         = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);
    uint32_t        pbindInputDataSize  = 0;
    uint32_t        sealDataSize        = 0;

    do
    {
        if (!sourceBuffer || !destBufferWritten)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
            break;
        }

        pbindInputDataSize = sourceBufferLen;
        sealDataSize = sgx_calc_sealed_data_size(0, pbindInputDataSize);

        if (UINT32_MAX == sealDataSize)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
            break;
        }
        else
        {
            *destBufferWritten = sealDataSize;
            if (!destBuffer)
            {
                result = true;
                break;
            }

            if (destBufferLen < sealDataSize)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                break;
            }

            std::unique_ptr<uint8_t[]> dataToBePlatformBound(new uint8_t[pbindInputDataSize]);
            if (!dataToBePlatformBound.get())
            {
                *destBufferWritten = 0;
                result             = false;
                status             = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            memcpy_s(dataToBePlatformBound.get(), pbindInputDataSize, sourceBuffer, sourceBufferLen);

            sgx_status_t sealingStatus = sgx_seal_data(0,
                                                       nullptr,
                                                       pbindInputDataSize,
                                                       dataToBePlatformBound.get(),
                                                       sealDataSize,
                                                       reinterpret_cast<sgx_sealed_data_t*>(destBuffer));

            result = (sgx_status_t::SGX_SUCCESS == sealingStatus);

            if (!result)
            {
                *destBufferWritten = 0;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_SEALED_DATA_FAILED;
                break;
            }
        }

    } while (false);

    return static_cast<SgxStatus>(status);
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus sealPin(uint8_t*   pin,
                  uint32_t   pinLen,
                  uint8_t*   destBuffer,
                  uint32_t   destBufferLen,
                  uint32_t*  destBufferWritten)
{
    SgxCryptStatus       status        = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
    bool                 result        = false;
    uint32_t             ptrDataSize   = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);
    sgx_status_t         sgxStatus     = SGX_SUCCESS;
    HashMode             hashMode      = HashMode::sha256;
    auto                 hashSize      = static_cast<uint8_t>(hashDigestLengthMap[static_cast<HashMode>(hashMode)]);
    auto                 saltSize      = 32;
    auto                 hashInputSize = 0;
    auto                 sealInputSize = 0;
    std::vector<uint8_t> salt(saltSize, 0);
    std::vector<uint8_t> hashInput;
    std::vector<uint8_t> hashOutput;
    std::vector<uint8_t> sealInput;

    do
    {
        if (!pin || !destBufferWritten)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
            break;
        }

        result = checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize);
        if (!result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
            break;
        }

        // Generate a random salt
        sgxStatus = sgx_read_rand(reinterpret_cast<unsigned char*>(salt.data()), saltSize);
        if (SGX_SUCCESS != sgxStatus)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
            break;
        }

        // Compute HASH(Salt + Pin)
        hashInputSize = saltSize + pinLen;
        hashInput.resize(hashInputSize);

        memcpy_s(hashInput.data(), saltSize, salt.data(), saltSize);
        memcpy_s(hashInput.data() + saltSize, pinLen, pin, pinLen);

        hashOutput.resize(hashSize);
        cryptoHash.computeHash(hashMode,
                               hashInput.data(),
                               hashInput.size(),
                               hashOutput.data(),
                               hashSize);

        // Compute SEAL(Salt + HASH(Salt + Pin))
        sealInputSize = saltSize + hashSize;
        sealInput.resize(sealInputSize);

        memcpy_s(sealInput.data(), saltSize, salt.data(), saltSize);
        memcpy_s(sealInput.data() + saltSize, hashSize, hashOutput.data(), hashSize);

        status = static_cast<SgxCryptStatus>(sealData(sealInput.data(),
                                                      sealInputSize,
                                                      destBuffer,
                                                      destBufferLen,
                                                      destBufferWritten));
        if (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != status)
        {
            break;
        }

        if (!destBuffer)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            break;
        }

        status = static_cast<SgxCryptStatus>(sealData(sealInput.data(),
                                                      sealInput.size(),
                                                      destBuffer,
                                                      destBufferLen,
                                                      destBufferWritten));

    } while (false);

    return static_cast<SgxStatus>(status);
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unsealData(uint8_t*   sourceBuffer,
                     uint32_t   sourceBufferLen,
                     uint8_t*   destBuffer,
                     uint32_t   destBufferLen,
                     uint32_t*  destBufferWritten)
{
    SgxCryptStatus  status              = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
    bool            result              = false;
    uint32_t        decryptedDataSize   = 0;

    do
    {
        if (!sourceBuffer || !sourceBufferLen || !destBufferWritten)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
            break;
        }

        decryptedDataSize = sgx_get_encrypt_txt_len(reinterpret_cast<const sgx_sealed_data_t*>(sourceBuffer));
        if (UINT32_MAX == decryptedDataSize)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if (decryptedDataSize)
        {
            *destBufferWritten = decryptedDataSize;
            if (!destBuffer)
            {
                result = true;
                break;
            }
            std::unique_ptr<uint8_t[]> tempDest(new uint8_t[decryptedDataSize], std::default_delete<uint8_t[]>());

            if (!tempDest.get())
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            sgx_status_t sealingStatus = sgx_unseal_data(reinterpret_cast<const sgx_sealed_data_t*>(sourceBuffer),
                                                         nullptr,
                                                         nullptr,
                                                         tempDest.get(),
                                                         &decryptedDataSize);

            result = (sgx_status_t::SGX_SUCCESS == sealingStatus);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_SEALED_DATA_FAILED;
                break;
            }

            memcpy_s(destBuffer,
                     destBufferLen,
                     tempDest.get(),
                     decryptedDataSize);
        }
        else
        {
            result = false;
            status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
            break;
        }

    } while (false);

    return static_cast<SgxStatus>(status);
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus updateSessionCount(uint8_t*   sourceBuffer,
                             uint32_t   sourceBufferLen,
                             uint8_t*   destBuffer,
                             uint32_t   destBufferLen,
                             uint32_t*  destBufferWritten,
                             int        updateSession)
{
    SgxStatus   status           = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    uint32_t    bytesNeeded      = 0;
    uint32_t    unsealBufferSize = 0;
    std::string newSessionCount;
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);

    do
    {
        if (!destBufferWritten ||
            !checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = unsealData(sourceBuffer,
                            sourceBufferLen,
                            nullptr,
                            0,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

        unsealBufferSize = bytesNeeded;
        std::unique_ptr<uint8_t[]> unsealedBuffer(new uint8_t[unsealBufferSize], std::default_delete<uint8_t[]>());
        if (!unsealedBuffer.get())
        {
            *destBufferWritten = 0;
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }

        bytesNeeded = 0;
        status = unsealData(sourceBuffer,
                            sourceBufferLen,
                            unsealedBuffer.get(),
                            unsealBufferSize,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

        std::string sessionCount(reinterpret_cast<char *>(unsealedBuffer.get()), bytesNeeded);

        if (UpdateSession::OPEN == static_cast<UpdateSession>(updateSession))
        {
            newSessionCount = std::to_string(std::stoi(sessionCount) + 1);
        }
        else
        {
            newSessionCount = std::to_string(std::stoi(sessionCount) - 1);
        }

        *destBufferWritten = 0;
        status = sealData(reinterpret_cast<uint8_t*>(&newSessionCount.at(0)),
                          newSessionCount.size(),
                          nullptr,
                          0,
                          destBufferWritten);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

        if (!destBuffer)
        {
            break;
        }

        *destBufferWritten = 0;
        status = sealData(reinterpret_cast<uint8_t*>(&newSessionCount.at(0)),
                          newSessionCount.size(),
                          destBuffer,
                          destBufferLen,
                          destBufferWritten);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus validatePin(uint8_t*  pin,
                      uint32_t  pinLen,
                      uint8_t*  sealedPin,
                      uint32_t  sealedPinLen)
{
    SgxStatus            status                     = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    HashMode             hashMode                   = HashMode::sha256;
    uint8_t              hashSize                   = static_cast<uint8_t>(hashDigestLengthMap[static_cast<HashMode>(hashMode)]);
    uint8_t              saltSize                   = 32;
    uint32_t             bytesNeeded                = 0;
    auto                 hashInputSize              = 0;
    uint32_t             unsealedDataSize           = 0;
    auto                 hashedSaltedPasswordLength = 0;
    std::vector<uint8_t> salt(saltSize);
    std::vector<uint8_t> hashInput;
    std::vector<uint8_t> hashOutput;
    std::vector<uint8_t> hashedSaltedPassword;

    do
    {
        if (!pin ||
            !checkUserCheckPointer(reinterpret_cast<uint8_t*>(pin), pinLen))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = unsealData(sealedPin,
                            sealedPinLen,
                            nullptr,
                            0,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        unsealedDataSize = bytesNeeded;

        std::unique_ptr<uint8_t[]> unsealedPin(new uint8_t[unsealedDataSize], std::default_delete<uint8_t[]>());
        if (!unsealedPin.get())
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }

        bytesNeeded = 0;
        status = unsealData(sealedPin,
                            sealedPinLen,
                            unsealedPin.get(),
                            unsealedDataSize,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        // Extract salt
        memcpy_s(salt.data(), saltSize, unsealedPin.get(), saltSize);

        // Extract hash
        hashedSaltedPasswordLength = unsealedDataSize - saltSize;
        hashedSaltedPassword.resize(hashedSaltedPasswordLength);

        memcpy_s(hashedSaltedPassword.data(),
                 hashedSaltedPasswordLength,
                 unsealedPin.get() + saltSize,
                 hashedSaltedPasswordLength);

        // Compute HASH(Salt + Pin)
        hashInputSize = saltSize + pinLen;
        hashInput.resize(hashInputSize);

        memcpy_s(hashInput.data(), saltSize, salt.data(), saltSize);
        memcpy_s(hashInput.data() + saltSize, pinLen, pin, pinLen);

        hashOutput.resize(hashSize);
        cryptoHash.computeHash(hashMode,
                               hashInput.data(),
                               hashInputSize,
                               hashOutput.data(),
                               hashSize);

        if (hashedSaltedPassword != hashOutput)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            break;
        }

        status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus checkSessionExistence(uint8_t* sealedSessionCount,
                                uint32_t sealedSessionCountLen)
{
    SgxStatus   status           = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    uint32_t    bytesNeeded      = 0;
    uint32_t    unsealedDataSize = 0;

    do
    {
        status = unsealData(sealedSessionCount,
                            sealedSessionCountLen,
                            nullptr,
                            0,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        unsealedDataSize = bytesNeeded;

        std::unique_ptr<uint8_t[]> unsealedBuffer(new uint8_t[unsealedDataSize], std::default_delete<uint8_t[]>());
        if (!unsealedBuffer.get())
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }

        bytesNeeded = 0;
        status = unsealData(sealedSessionCount,
                            sealedSessionCountLen,
                            unsealedBuffer.get(),
                            unsealedDataSize,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        std::string sessionCount(reinterpret_cast<char *>(unsealedBuffer.get()), bytesNeeded);

        if ("0" != sessionCount)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SESSION_EXISTS);
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        }

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus checkLoginStatus(uint8_t* sealedBuffer,
                           uint32_t sealedBufferLen)
{
    SgxStatus   status           = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    uint32_t    bytesNeeded      = 0;
    uint32_t    unsealedDataSize = 0;

    do
    {
        status = unsealData(sealedBuffer,
                            sealedBufferLen,
                            nullptr,
                            0,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        unsealedDataSize = bytesNeeded;

        std::unique_ptr<uint8_t[]> unsealedBuffer(new uint8_t[unsealedDataSize], std::default_delete<uint8_t[]>());
        if (!unsealedBuffer.get())
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }

        bytesNeeded = 0;
        status = unsealData(sealedBuffer,
                            sealedBufferLen,
                            unsealedBuffer.get(),
                            unsealedDataSize,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            break;
        }

        std::string loginStatus(reinterpret_cast<char *>(unsealedBuffer.get()), bytesNeeded);

        if ("FALSE" == loginStatus)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_NOT_LOGGED);
        }
        else if ("TRUE" == loginStatus)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_LOGGED_IN);
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
        }

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus updateLoginStatus(uint8_t*   sourceBuffer,
                            uint32_t   sourceBufferLen,
                            uint8_t*   destBuffer,
                            uint32_t   destBufferLen,
                            uint32_t*  destBufferWritten)
{
    SgxStatus   status      = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    uint32_t    ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);
    uint32_t    bytesNeeded = 0;
    std::string newLoginStatus;

    do
    {
        if (!destBufferWritten ||
            !checkUserCheckPointer(reinterpret_cast<uint8_t*>(destBufferWritten), ptrDataSize))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        status = unsealData(sourceBuffer,
                            sourceBufferLen,
                            nullptr,
                            0,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

        uint32_t unsealedBufferSize = bytesNeeded;
        std::unique_ptr<uint8_t[]> unsealedBuffer(new uint8_t[unsealedBufferSize], std::default_delete<uint8_t[]>());
        if (!unsealedBuffer.get())
        {
            *destBufferWritten = 0;
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }

        bytesNeeded = 0;
        status = unsealData(sourceBuffer,
                            sourceBufferLen,
                            unsealedBuffer.get(),
                            unsealedBufferSize,
                            &bytesNeeded);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

        std::string loginStatus(reinterpret_cast<char *>(unsealedBuffer.get()), bytesNeeded);
        if ("FALSE" == loginStatus)
        {
            newLoginStatus = "TRUE";
        }
        else if ("TRUE" == loginStatus)
        {
            newLoginStatus = "FALSE";
        }
        else
        {
            *destBufferWritten = 0;
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        *destBufferWritten = 0;
        status = sealData(reinterpret_cast<uint8_t*>(&newLoginStatus.at(0)),
                          newLoginStatus.size(),
                          nullptr,
                          0,
                          destBufferWritten);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

        if (!destBuffer)
        {
            break;
        }

        *destBufferWritten = 0;
        status = sealData(reinterpret_cast<uint8_t*>(&newLoginStatus.at(0)),
                          newLoginStatus.size(),
                          destBuffer,
                          destBufferLen,
                          destBufferWritten);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            *destBufferWritten = 0;
            break;
        }

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus clearCacheState(uint32_t keyId)
{
    SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);

    symmetricCrypto.clearState(keyId);

    return status;
}