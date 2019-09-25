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
#include <openssl/x509.h>
#include "SymmetricCrypto.h"
#include "AsymmetricCrypto.h"
#include "HashCrypto.h"
#include "CryptoEnclaveDefs.h"
#include "p11Enclave_t.h"
#include "HashDefs.h"
#include "SgxFileUtils.h"
#include "SoPinCache.h"

using namespace CryptoSgx;

SymmetricCrypto  symmetricCrypto;
AsymmetricCrypto asymmetricCrypto;
CryptoHash       cryptoHash;
SoPinCache       soPinCache;

#ifdef _WIN32
    extern "C" void _mm_lfence(void);
#else
    extern "C" void __builtin_ia32_lfence(void);
#endif

//---------------------------------------------------------------------------------------------------------------------
static inline bool checkUserCheckPointer(const void* ptr, uint32_t& length)
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
SgxStatus initCryptoEnclave()
{
    symmetricCrypto.clearKeys();
    asymmetricCrypto.clearKeys();
    cryptoHash.clearStates();

    return static_cast<int>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus deinitCryptoEnclave()
{
    return initCryptoEnclave();
}

// symmetric operations
//---------------------------------------------------------------------------------------------------------------------
SgxStatus generateSymmetricKey(uint32_t*       keyId,
                               uint16_t        keySize,
                               const uint64_t* attributeBuffer,
                               uint64_t        attributeBufferLen)
{
    SgxStatus status{ 0 };
    bool      result       = false;
    uint32_t  ptrDataSize  = sizeof(std::remove_pointer<decltype(keyId)>::type);

    do
    {
        result = keyId &&
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

        uint64_t   slotId;
        ByteBuffer pinMaterial;

        if (attributeBuffer)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
            pinMaterial = soPinCache.get(slotId);
        }

        status = symmetricCrypto.generateSymmetricKey(*keyId,
                                                      static_cast<SymmetricKeySize>(keySize),
                                                      attributeBuffer,
                                                      attributeBufferLen,
                                                      pinMaterial);
    } while (false);
    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus destroyKey(uint32_t keyId, uint8_t keyType)
{
    SgxStatus status{ 0 };
    KeyType   type = static_cast<KeyType>(keyType);

    do
    {
        if (!keyId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (KeyType::Aes == type)
        {
            status = symmetricCrypto.removeSymmetricKey(keyId);
        }
        else if ((KeyType::Rsa == type) || (KeyType::Ec == type) || (KeyType::Ed == type))
        {
            status = asymmetricCrypto.removeAsymmetricKey(keyId);
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
        }

    } while (false);

    return status;
}

SgxStatus importSymmetricKey(uint32_t*       keyId,
                             const uint8_t*  keyBuffer,
                             uint16_t        keySize,
                             const uint64_t* attributeBuffer,
                             uint64_t        attributeBufferLen)
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
        result = keyId &&
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

        uint64_t   slotId;
        ByteBuffer pinMaterial;

        if (attributeBuffer)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
            pinMaterial = soPinCache.get(slotId);
        }

        status = symmetricCrypto.importRawKey(*keyId,
                                              keyBuffer,
                                              keySize,
                                              attributeBuffer,
                                              attributeBufferLen,
                                              pinMaterial);
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

        result = symmetricCrypto.getSymmetricKey(keyIdHmac, &symKey);
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
            secretBuffer.reset(new (std::nothrow) uint8_t[secretLen]);

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
SgxStatus generateAsymmetricKey(uint32_t*       publicKeyId,
                                uint32_t*       privateKeyId,
                                uint16_t        modulusSize,
                                const uint64_t* attributeBufferPublic,
                                uint64_t        attributeBufferPublicLen,
                                const uint64_t* attributeBufferPrivate,
                                uint64_t        attributeBufferPrivateLen)
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

        uint64_t   slotId;
        ByteBuffer pinMaterial;

        if (attributeBufferPublic)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBufferPublic, attributeBufferPublicLen);
            pinMaterial = soPinCache.get(slotId);
        }
        else if (attributeBufferPrivate)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBufferPrivate, attributeBufferPrivateLen);
            pinMaterial = soPinCache.get(slotId);
        }

        status = asymmetricCrypto.generateAsymmetricKey(*publicKeyId, *privateKeyId,
                                                        reinterpret_cast<AsymmetricKeySize&>(modulusSize),
                                                        attributeBufferPublic,  attributeBufferPublicLen,
                                                        attributeBufferPrivate, attributeBufferPrivateLen,
                                                        pinMaterial);

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
        if (!keyId || symmetricCrypto.checkWrappingStatus(keyId))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
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
        if (!keyId || symmetricCrypto.checkWrappingStatus(keyId))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
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
        if (!result || symmetricCrypto.checkWrappingStatus(keyId))
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
        if (!result || symmetricCrypto.checkWrappingStatus(keyId))
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
        if (!keyId || symmetricCrypto.checkWrappingStatus(keyId))
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
        if (!result || symmetricCrypto.checkWrappingStatus(keyId))
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
        if (!result || symmetricCrypto.checkWrappingStatus(keyId))
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
        if (!keyId || symmetricCrypto.checkWrappingStatus(keyId))
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
        if (!result || asymmetricCrypto.checkWrappingStatus(keyId, OperationType::Public))
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
        if (!result || asymmetricCrypto.checkWrappingStatus(keyId, OperationType::Private))
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

        result = symmetricCrypto.getSymmetricKey(keyIdData, &symKeyData) &&
                 symmetricCrypto.getSymmetricKey(keyId, &symKey);

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

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) == status)
        {
            status = symmetricCrypto.setWrappingStatus(keyId);
        }
    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unwrapWithSymmetricKey(uint32_t        keyId,
                                 uint32_t*       unwrappedKeyId,
                                 const uint8_t*  sourceBuffer,
                                 uint32_t        sourceBufferLen,
                                 const uint8_t*  iv,
                                 uint32_t        ivSize,
                                 const uint8_t*  aad,
                                 uint32_t        aadSize,
                                 uint8_t         cipherMode,
                                 int             padding,
                                 uint32_t        tagBits,
                                 int             counterBits,
                                 uint8_t         wrappedKeyType,
                                 const uint64_t* attributeBuffer,
                                 uint64_t        attributeBufferLen)
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

        result = symmetricCrypto.getSymmetricKey(keyId, &symKey);
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

        // Retrieve the destination buffer size required.
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
        std::unique_ptr<uint8_t[]> tempDestBuffer(new (std::nothrow) uint8_t[tempDestBufferLen], std::default_delete<uint8_t[]>());
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

        std::string fileName, filePath;
        ByteBuffer  pinMaterial;
        uint64_t    slotId;

        if (attributeBuffer)
        {
            fileName = Utils::SgxFileUtils::generateRandomFilename();
            if (fileName.empty())
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                break;
            }

            slotId = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
            pinMaterial = soPinCache.get(slotId);
        }

        KeyType keyType = static_cast<KeyType>(wrappedKeyType);
        if (KeyType::Aes == keyType)
        {
            SymmetricKey newSymKey{};

            newSymKey.key.allocate(destBufferWritten);
            if (!newSymKey.key.isValid())
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                break;
            }

            newSymKey.key.fromData(tempDestBuffer.get(), destBufferWritten);

            if (attributeBuffer)
            {
                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                    newSymKey.key.get(), newSymKey.key.size(), false, 0, &filePath);
                if (!result)
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                    break;
                }

                newSymKey.keyFile = filePath;
            }

            symmetricCrypto.addSymmetricKey(*unwrappedKeyId, newSymKey);
            memset_s(tempDestBuffer.get(), tempDestBufferLen, 0, tempDestBufferLen);
        }
        else if (KeyType::Rsa == keyType)
        {
            const unsigned char* temp  = tempDestBuffer.get();
            PKCS8_PRIV_KEY_INFO* pInfo = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &temp, destBufferWritten);

            EVP_PKEY* evpKey = EVP_PKCS82PKEY(pInfo);
            RSA* rsa = EVP_PKEY_get1_RSA(evpKey);

            AsymmetricKey asymKey{};
            asymKey.key = rsa;

            uint8_t* encodedKey = nullptr;
            uint64_t encodedKeySize = 0;

            if (attributeBuffer)
            {
                if (!asymmetricCrypto.encodeRsaKey(asymKey.key, &encodedKey, &encodedKeySize))
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                    encodedKey, encodedKeySize, false, 0, &filePath);
                if (!result)
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                    break;
                }

                asymKey.keyFile = filePath;
            }

            asymmetricCrypto.addRsaPrivateKey(*unwrappedKeyId, asymKey);
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

        result = symmetricCrypto.getSymmetricKey(symmetricKeyId, &symKey);
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

        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) == status)
        {
            status = asymmetricCrypto.setWrappingStatus(asymmetricKeyId);
        }

    } while (false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus unwrapWithAsymmetricKey(uint32_t        asymmetricKeyId,
                                  uint32_t*       unwrappedKeyId,
                                  const uint8_t*  sourceBuffer,
                                  uint32_t        sourceBufferLen,
                                  uint8_t         rsaPadding,
                                  const uint64_t* attributeBuffer,
                                  uint64_t        attributeBufferLen)
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
        std::unique_ptr<uint8_t[]> tempDestBuffer(new (std::nothrow) uint8_t[tempDestBufferSize], std::default_delete<uint8_t[]>());
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
        if (!newSymKey.key.isValid())
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
            break;
        }

        newSymKey.key.fromData(tempDestBuffer.get(), tempDestBufferSize);

        std::string filePath;

        if (attributeBuffer)
        {
            std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
            if (fileName.empty())
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                break;
            }

            uint64_t    slotId      = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
            ByteBuffer  pinMaterial = soPinCache.get(slotId);

            result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                newSymKey.key.get(), newSymKey.key.size(), false, 0, &filePath);
            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                break;
            }

            newSymKey.keyFile = filePath;
        }

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
SgxStatus asymmetricImportKey(uint32_t*       keyId,
                              uint8_t*        modulusBuffer,
                              uint32_t        modulusBufferLen,
                              uint8_t*        exponentBuffer,
                              uint32_t        exponentBufferLen,
                              const uint64_t* attributeBuffer,
                              uint64_t        attributeBufferLen)
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

        uint64_t   slotId;
        ByteBuffer pinMaterial;

        if (attributeBuffer)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
            pinMaterial = soPinCache.get(slotId);
        }

        status = asymmetricCrypto.importPublicKey(*keyId,
                                                  modulusBuffer,
                                                  modulusBufferLen,
                                                  exponentBuffer,
                                                  exponentBufferLen,
                                                  attributeBuffer,
                                                  attributeBufferLen,
                                                  pinMaterial);
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

            std::unique_ptr<uint8_t[]> dataToBePlatformBound(new (std::nothrow) uint8_t[pbindInputDataSize]);
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
            std::unique_ptr<uint8_t[]> tempDest(new (std::nothrow) uint8_t[decryptedDataSize], std::default_delete<uint8_t[]>());

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

        std::unique_ptr<uint8_t[]> unsealedPin(new (std::nothrow) uint8_t[unsealedDataSize], std::default_delete<uint8_t[]>());
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
SgxStatus clearCacheState(uint32_t keyId)
{
    SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);

    symmetricCrypto.clearState(keyId);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus readTokenObjectFile(const char* filePath,
                              uint32_t    filePathLen,
                              uint64_t    slotId,
                              uint64_t*   attributeBuffer,
                              uint64_t    attributeBufferLen,
                              uint64_t*   attributeBufferLenRequired,
                              uint32_t*   keyId)
{
    SgxStatus status{ 0 };
    bool      result       = false;
    uint32_t  ptrDataSize  = sizeof(std::remove_pointer<decltype(keyId)>::type);
    uint32_t  ptrDataSize1 = sizeof(std::remove_pointer<decltype(attributeBufferLenRequired)>::type);

    do
    {
        result = keyId                      &&
                 attributeBufferLenRequired &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(keyId), ptrDataSize)                       &&
                 checkUserCheckPointer(reinterpret_cast<uint8_t*>(attributeBufferLenRequired), ptrDataSize1) &&
                 (0 == *keyId);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        std::string tokenObjectFilePath(filePath, filePathLen);
        ByteBuffer  pinMaterial              = soPinCache.get(slotId);
        uint64_t    pairKeyId                = 0;
        bool        usedForWrapping          = false;
        uint64_t    keyBufferLenRequired     = 0;
        uint64_t    attributeBufferLenNeeded = 0;

        result = Utils::TokenObjectParser::readTokenObject(tokenObjectFilePath, pinMaterial,
                                                           nullptr, 0, &attributeBufferLenNeeded,
                                                           nullptr, 0, &keyBufferLenRequired,
                                                           &usedForWrapping, &pairKeyId, true);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            break;
        }

        if (!attributeBuffer)
        {
            *attributeBufferLenRequired = attributeBufferLenNeeded;
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
            break;
        }

        std::unique_ptr<uint8_t[]> keyBuffer(new (std::nothrow) uint8_t[keyBufferLenRequired], std::default_delete<uint8_t[]>());

        result = Utils::TokenObjectParser::readTokenObject(tokenObjectFilePath, pinMaterial,
                                                           attributeBuffer, attributeBufferLen, &attributeBufferLenNeeded,
                                                           keyBuffer.get(), keyBufferLenRequired, &keyBufferLenRequired,
                                                           &usedForWrapping, &pairKeyId, false);
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            break;
        }

        uint64_t slotIdInFile = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
        if (slotIdInFile != slotId)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            break;
        }

        status = generateId(keyId);
        if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            break;
        }

        uint64_t keyType = 0;
        memcpy_s(&keyType, sizeof(uint64_t), attributeBuffer + 1, sizeof(uint64_t));

        if (static_cast<uint64_t>(KeyClassType::Aes) == keyType)
        {
            status = symmetricCrypto.addSymmetricKey(*keyId, tokenObjectFilePath, keyBuffer.get(), static_cast<SymmetricKeySize>(keyBufferLenRequired), usedForWrapping);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }
        }
        else if (static_cast<uint64_t>(KeyClassType::RsaPublicKey)  == keyType ||
                 static_cast<uint64_t>(KeyClassType::RsaPrivateKey) == keyType)
        {
            status = asymmetricCrypto.addAsymmetricKey(*keyId, tokenObjectFilePath, keyBuffer.get(), keyBufferLenRequired,
                                                       static_cast<KeyClassType>(keyType),
                                                       usedForWrapping, pairKeyId);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }
        }
        else if (static_cast<uint64_t>(KeyClassType::EcPublicKey)  == keyType ||
                 static_cast<uint64_t>(KeyClassType::EcPrivateKey) == keyType)
        {
            status = asymmetricCrypto.addEcKey(*keyId, tokenObjectFilePath, keyBuffer.get(), keyBufferLenRequired,
                                               static_cast<KeyClassType>(keyType),
                                               usedForWrapping, pairKeyId);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }
        }
        else if (static_cast<uint64_t>(KeyClassType::EdPublicKey)  == keyType ||
                 static_cast<uint64_t>(KeyClassType::EdPrivateKey) == keyType)
        {
            status = asymmetricCrypto.addEdKey(*keyId, tokenObjectFilePath, keyBuffer.get(), keyBufferLenRequired,
                                               static_cast<KeyClassType>(keyType),
                                               usedForWrapping, pairKeyId);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            break;
        }

        *attributeBufferLenRequired = attributeBufferLenNeeded;

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus updateTokenObjectFile(uint32_t        keyId,
                                uint8_t         keyType,
                                const uint64_t* attributeBuffer,
                                uint64_t        attributeBufferLen)
{
    SgxStatus status{ 0 };
    bool      result = false;

    do
    {
        result = keyId && attributeBuffer && attributeBufferLen;
        if (!result)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        uint64_t    slotId      = Utils::TokenObjectParser::getSlotId(attributeBuffer, attributeBufferLen);
        ByteBuffer  pinMaterial = soPinCache.get(slotId);

        if (static_cast<uint8_t>(KeyType::Aes) == keyType)
        {
            status = symmetricCrypto.updateKeyFile(keyId, attributeBuffer, attributeBufferLen, pinMaterial);
        }
        else if ((static_cast<uint8_t>(KeyType::Rsa) == keyType) ||
                 (static_cast<uint8_t>(KeyType::Ec)  == keyType) ||
                 (static_cast<uint8_t>(KeyType::Ed)  == keyType))
        {
            status = asymmetricCrypto.updateKeyFile(keyId, keyType, attributeBuffer, attributeBufferLen, pinMaterial);
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
        }

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus updateSOPinMaterial(uint64_t    slotId,
                              const char* filePath,
                              uint32_t    filePathLen)
{
    SgxStatus status{ 0 };

    do
    {
        if (!filePath)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        std::string path;
        path.assign(reinterpret_cast<const char*>(filePath), filePathLen);

        ByteBuffer pinMaterial = soPinCache.get(slotId);

        if (!Utils::TokenObjectParser::updatePinMaterial(path, pinMaterial))
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
        }

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus savePinMaterial(uint64_t slotId,
                          uint8_t* sealedPin,
                          uint32_t sealedPinLen)
{
    SgxStatus status{ 0 };

    uint8_t  saltSize              = 32;
    uint32_t bytesNeeded           = 0;
    uint32_t unsealedDataSize      = 0;
    auto     hashedSaltedPinLength = 0;

    do
    {
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

        std::unique_ptr<uint8_t[]> unsealedPin(new (std::nothrow) uint8_t[unsealedDataSize], std::default_delete<uint8_t[]>());
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

        // Extract hash
        hashedSaltedPinLength = unsealedDataSize - saltSize;
        ByteBuffer hashedSaltedPin(hashedSaltedPinLength);

        memcpy_s(hashedSaltedPin.get(),
                 hashedSaltedPinLength,
                 unsealedPin.get() + saltSize,
                 hashedSaltedPinLength);

        soPinCache.add(slotId, hashedSaltedPin);

    } while(false);

    return status;
}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus updateKeyHandle(uint32_t keyHandle, uint32_t newKeyHandle, uint8_t keyType)
{
    SgxStatus status{ 0 };
    KeyType   type = static_cast<KeyType>(keyType);

    if (KeyType::Aes == type)
    {
        status = symmetricCrypto.updateHandle(keyHandle, newKeyHandle);
    }
    else if (KeyType::Rsa == type || KeyType::Ec == type || KeyType::Ed == type)
    {
        status = asymmetricCrypto.updateHandle(keyHandle, newKeyHandle);
    }
    else
    {
        status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
    }

    return status;

}

//---------------------------------------------------------------------------------------------------------------------
SgxStatus generateEccKeyPair(uint32_t*            publicKeyId,
                             uint32_t*            privateKeyId,
                             const unsigned char* curveOid,
                             uint32_t             curveOidLen,
                             const uint64_t*      attributeBufferPublic,
                             uint64_t             attributeBufferPublicLen,
                             const uint64_t*      attributeBufferPrivate,
                             uint64_t             attributeBufferPrivateLen)
{
    SgxStatus status{ 0 };
    bool      result      = false;
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(publicKeyId)>::type);

    do
    {
        if (!publicKeyId || !privateKeyId || !curveOid || !curveOidLen)
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

        uint64_t   slotId;
        ByteBuffer pinMaterial;

        if (attributeBufferPublic)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBufferPublic, attributeBufferPublicLen);
            pinMaterial = soPinCache.get(slotId);
        }
        else if (attributeBufferPrivate)
        {
            slotId      = Utils::TokenObjectParser::getSlotId(attributeBufferPrivate, attributeBufferPrivateLen);
            pinMaterial = soPinCache.get(slotId);
        }

        status = asymmetricCrypto.generateEccKey(*publicKeyId, *privateKeyId,
                                                 curveOid, curveOidLen,
                                                 attributeBufferPublic,  attributeBufferPublicLen,
                                                 attributeBufferPrivate, attributeBufferPrivateLen,
                                                 pinMaterial);

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
SgxStatus exportEcParams(uint32_t  keyId,
                         uint8_t*  destBuffer,
                         uint32_t  destBufferLen,
                         uint32_t* destBufferWritten)
{
    SgxStatus status      = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
    uint32_t  ptrDataSize = sizeof(std::remove_pointer<decltype(destBufferWritten)>::type);
    bool      result  = false;

    do
    {
        if (!keyId || !destBufferWritten)
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
            break;
        }

        if (destBuffer && !checkUserCheckPointer(destBuffer, destBufferLen))
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

#ifdef _WIN32
        _mm_lfence();
#else
        __builtin_ia32_lfence();
#endif

        status = asymmetricCrypto.getEcParams(keyId,
                                              destBuffer,
                                              destBufferLen,
                                              destBufferWritten);
    } while (false);

    return status;
}