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

#include "AsymmetricCrypto.h"
#include "HashCrypto.h"
#include "HashDefs.h"
#include "CryptoEnclaveDefs.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <sgx_tseal.h>
#include <sgx_trts.h>
#include <memory>
#include <mbusafecrt.h>
#include <vector>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    auto getMaxSalt = [](const uint32_t& rsaBlockSize, const uint32_t& hashLength) -> uint32_t
                        {
                            return (rsaBlockSize - hashLength - 2);
                        };

    //---------------------------------------------------------------------------------------------
    auto hasPrivateKey = [](const AsymmetricKey& asymKey) -> bool
                           {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                                if (asymKey.key && asymKey.key->p && asymKey.key->q)
                                {
                                    return true;
                                }
#else
                                /* OpenSSL 1.1.0 and above */
                                bool         result = false;
                                const BIGNUM *bn_p  = nullptr;
                                const BIGNUM *bn_q  = nullptr;

                                RSA_get0_factors(asymKey.key, &bn_p, &bn_q);

                                if (bn_p && bn_q)
                                {
                                    result = true;
                                }
#endif
                                return result;
                           };

    //---------------------------------------------------------------------------------------------
    auto getEncodedKey = [](const AsymmetricKey& asymKey, uint8_t** encodedKey, const bool& onlyPubicKeyPresent) -> int
                           {
                              int bytesWritten = 0;

                              if (!encodedKey || !*encodedKey)
                              {
                                  return bytesWritten;
                              }

                              if (onlyPubicKeyPresent)
                              {
                                  // Only public key encoded
                                  bytesWritten = i2d_RSAPublicKey(asymKey.key, encodedKey);
                              }
                              else
                              {
                                  // Both public & private keys encoded
                                  bytesWritten = i2d_RSAPrivateKey(asymKey.key, encodedKey);
                              }

                              return bytesWritten;
                           };

    //---------------------------------------------------------------------------------------------
    AsymmetricCrypto::AsymmetricCrypto()
    {
    }

    //---------------------------------------------------------------------------------------------
    AsymmetricCrypto::~AsymmetricCrypto()
    {
        clearKeys();
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricCrypto::clearKeys()
    {
        mAsymmetricPublicKeyCache.clear();
        mAsymmetricPrivateKeyCache.clear();
    }

    //---------------------------------------------------------------------------------------------
    static EC_POINT* decodeEcPublicKey(const uint8_t* encodedKey, const uint64_t& encodedKeyLen, const EC_GROUP* ecGroup)
    {
        bool      result = false;
        EC_POINT* ecPoint;

        do
        {
            // Two bytes are stuffed in while encoding to identify if EC_POINT is short/long.
            size_t extraBytes = 2;

            if (!encodedKey || !ecGroup || (encodedKeyLen <= extraBytes))
            {
                break;
            }

            // First two bytes of encodedKey are used to do integrity checks.
            uint8_t byte1  = 0;
            uint8_t byte2  = 0;
            size_t  offset = 0;

            memcpy_s(&byte1, sizeof(uint8_t), encodedKey + offset, sizeof(uint8_t));
            offset++;

            memcpy_s(&byte2, sizeof(uint8_t), encodedKey + offset, sizeof(uint8_t));

            // Integrity check
            if (V_ASN1_OCTET_STRING != byte1)
            {
                break;
            }

            // For short EC_POINT
            if (byte2 < 0x80)
            {
                if (byte2 != encodedKeyLen - extraBytes)
                {
                    break;
                }
            }
            else // For long EC_POINT
            {
                size_t bytesLen = byte2 & 0x7f;
                extraBytes += bytesLen;

                if (extraBytes >= encodedKeyLen)
                {
                    break;
                }

                unsigned long val = 0;
                size_t rawPublicKeyOffset = 2;
                size_t rawPublicKeyLen = encodedKeyLen - rawPublicKeyOffset;

                for (size_t i = 0; i < std::min(size_t{8}, rawPublicKeyLen); i++)
                {
                    val <<= 8;
                    val += *(encodedKey + rawPublicKeyOffset + i);
                }

                if (val != (encodedKeyLen - extraBytes))
                {
                    break;
                }
            }

            const size_t rawPublicKeyOffset = extraBytes;
            const size_t rawPublicKeyLen    = encodedKeyLen - extraBytes;

            if (!rawPublicKeyLen)
            {
                break;
            }

            // Extract EC_POINT from ec group
            ecPoint = EC_POINT_new(ecGroup);
            if (!ecPoint)
            {
                break;
            }

            //Decode EC_POINT from a octet string
            if (!EC_POINT_oct2point(ecGroup, ecPoint, encodedKey + rawPublicKeyOffset, rawPublicKeyLen, nullptr))
            {
                EC_POINT_free(ecPoint);
                break;
            }

            result = true;
        } while(false);

        if (!result)
        {
            return nullptr;
        }

        return ecPoint;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::addEcKey(const uint32_t&     keyId,
                                         const std::string&  tokenObjectFilePath,
                                         const uint8_t*      encodedKey,
                                         const uint64_t&     encodedKeyLen,
                                         const KeyClassType& keyClassType,
                                         const bool&         usedForWrapping,
                                         const uint64_t&     pairKeyId)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
        EC_KEY*   ecKey  = nullptr;

        do
        {
            if (!encodedKey)
            {
                break;
            }

            if (!((KeyClassType::EcPublicKey  == keyClassType) ||
                  (KeyClassType::EcPrivateKey == keyClassType)))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            if ((KeyClassType::EcPublicKey == keyClassType) &&
                (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
                break;
            }
            else if ((KeyClassType::EcPrivateKey == keyClassType) &&
                     (static_cast<SgxMaxKeyLimits>(mAsymmetricPrivateKeyCache.count()) >= SgxMaxKeyLimits::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
                break;
            }

            uint8_t privateKeyLen = 0;
            uint8_t derParamsLen  = 0;
            uint8_t publicKeyLen  = 0;

            // Ensure bound checks for encodedKey
            if (encodedKeyLen < privateKeyOffset)
            {
                break;
            }

            memcpy_s(&privateKeyLen, sizeof(uint8_t), encodedKey + privateKeyLenOffset, sizeof(uint8_t));
            memcpy_s(&derParamsLen,  sizeof(uint8_t), encodedKey + derParamsLenOffset, sizeof(uint8_t));
            memcpy_s(&publicKeyLen,  sizeof(uint8_t), encodedKey + publicKeyLenOffset, sizeof(uint8_t));

            // Ensure bound checks for encodedKey
            const size_t encodedKeyLenRequired = 3*sizeof(uint8_t) + privateKeyLen + derParamsLen + publicKeyLen;
            if (encodedKeyLen < encodedKeyLenRequired)
            {
                break;
            }

            const size_t derParamsOffset  = privateKeyOffset + privateKeyLen;
            const size_t publicKeyOffset  = derParamsOffset + derParamsLen;

            // Create an Ec Key
            ecKey = EC_KEY_new();
            if (!ecKey)
            {
                break;
            }

            // Extract Ec Group
            const unsigned char *derParamsPtr = encodedKey + derParamsOffset;
            EC_GROUP* ecGroup = d2i_ECPKParameters(nullptr, &derParamsPtr, derParamsLen);
            if (!ecGroup)
            {
                break;
            }

            // Set Ec Group
            EC_KEY_set_group(ecKey, ecGroup);

            // Extract private key
            BIGNUM* privateKey = BN_bin2bn(encodedKey + privateKeyOffset, privateKeyLen, nullptr);
            if (!privateKey)
            {
                break;
            }

            // Set private key
            EC_KEY_set_private_key(ecKey, privateKey);
            BN_clear_free(privateKey);

            // Extract public key
            EC_POINT* publicKey = decodeEcPublicKey(encodedKey + publicKeyOffset, publicKeyLen, ecGroup);
            if (!publicKey)
            {
                break;
            }

            EC_KEY_set_public_key(ecKey, publicKey);
            EC_POINT_free(publicKey);
            EC_GROUP_free(ecGroup);

            // Add in key cache
            AsymmetricKey asymKey{};

            asymKey.isUsedForWrapping = usedForWrapping;
            asymKey.pairKeyId         = pairKeyId;
            asymKey.keyFile           = tokenObjectFilePath;
            asymKey.ecKey             = ecKey;

            if (KeyClassType::EcPublicKey == keyClassType)
            {
                mAsymmetricPublicKeyCache.add(keyId, asymKey);
            }
            else if (KeyClassType::EcPrivateKey == keyClassType)
            {
                mAsymmetricPrivateKeyCache.add(keyId, asymKey);
            }
            else
            {
                break;
            }

            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        } while(false);

        if (ecKey && (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status))
        {
            EC_KEY_free(ecKey);
        }

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::addEdKey(const uint32_t&     keyId,
                                         const std::string&  tokenObjectFilePath,
                                         const uint8_t*      encodedKey,
                                         const uint64_t&     encodedKeyLen,
                                         const KeyClassType& keyClassType,
                                         const bool&         usedForWrapping,
                                         const uint64_t&     pairKeyId)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);

        do
        {
            if (!encodedKey)
            {
                break;
            }

            if (!((KeyClassType::EdPublicKey  == keyClassType) ||
                  (KeyClassType::EdPrivateKey == keyClassType)))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            if ((KeyClassType::EdPublicKey == keyClassType) &&
                (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
                break;
            }
            else if ((KeyClassType::EdPrivateKey == keyClassType) &&
                     (static_cast<SgxMaxKeyLimits>(mAsymmetricPrivateKeyCache.count()) >= SgxMaxKeyLimits::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
                break;
            }

            uint8_t privateKeyLen = 0;
            uint8_t derParamsLen  = 0;
            uint8_t publicKeyLen  = 0;

            // Ensure bound checks for encodedKey
            if (encodedKeyLen < privateKeyOffset)
            {
                break;
            }

            memcpy_s(&privateKeyLen, sizeof(uint8_t), encodedKey + privateKeyLenOffset, sizeof(uint8_t));
            memcpy_s(&derParamsLen,  sizeof(uint8_t), encodedKey + derParamsLenOffset, sizeof(uint8_t));
            memcpy_s(&publicKeyLen,  sizeof(uint8_t), encodedKey + publicKeyLenOffset, sizeof(uint8_t));

            // Ensure bound checks for encodedKey
            const size_t encodedKeyLenRequired = 3*sizeof(uint8_t) + privateKeyLen + derParamsLen + publicKeyLen;
            if (encodedKeyLen < encodedKeyLenRequired)
            {
                break;
            }

            const size_t derParamsOffset  = privateKeyOffset + privateKeyLen;
            const size_t publicKeyOffset  = derParamsOffset + derParamsLen;

            // Set private key
            if (ed25519KeyLength != privateKeyLen)
            {
                break;
            }

            EVP_PKEY* edKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, encodedKey + privateKeyOffset, privateKeyLen);
            if (!edKey)
            {
                break;
            }

            // Add in key cache
            AsymmetricKey asymKey{};

            asymKey.isUsedForWrapping = usedForWrapping;
            asymKey.pairKeyId         = pairKeyId;
            asymKey.keyFile           = tokenObjectFilePath;
            asymKey.edKey             = edKey;

            if (KeyClassType::EdPublicKey == keyClassType)
            {
                mAsymmetricPublicKeyCache.add(keyId, asymKey);
            }
            else if (KeyClassType::EdPrivateKey == keyClassType)
            {
                mAsymmetricPrivateKeyCache.add(keyId, asymKey);
            }
            else
            {
                break;
            }

            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        } while(false);

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::addAsymmetricKey(const uint32_t&     keyId,
                                                 const std::string&  tokenObjectFilePath,
                                                 const uint8_t*      encodedKey,
                                                 const uint64_t&     encodedKeyLen,
                                                 const KeyClassType& keyClassType,
                                                 const bool&         usedForWrapping,
                                                 const uint64_t&     pairKeyId)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);

        do
        {
            if (!encodedKey)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                break;
            }

            if (!((KeyClassType::RsaPublicKey  == keyClassType) ||
                  (KeyClassType::RsaPrivateKey == keyClassType)))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            if ((KeyClassType::RsaPublicKey == keyClassType) &&
                (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
                break;
            }
            else if ((KeyClassType::RsaPrivateKey == keyClassType) &&
                     (static_cast<SgxMaxKeyLimits>(mAsymmetricPrivateKeyCache.count()) >= SgxMaxKeyLimits::asymmetric))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
                break;
            }

            AsymmetricKey asymKey{};

            if (nullptr == d2i_RSAPrivateKey(&asymKey.key,
                                             const_cast<const unsigned char**>(&encodedKey),
                                             encodedKeyLen))
            {
                if (nullptr == d2i_RSAPublicKey(&asymKey.key,
                                                const_cast<const unsigned char**>(&encodedKey),
                                                encodedKeyLen))
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                    break;
                }
            }

            asymKey.keyFile = tokenObjectFilePath;
            asymKey.isUsedForWrapping = usedForWrapping;
            asymKey.pairKeyId = pairKeyId;

            if (KeyClassType::RsaPublicKey == keyClassType)
            {
                mAsymmetricPublicKeyCache.add(keyId, asymKey);
            }
            else if (KeyClassType::RsaPrivateKey == keyClassType)
            {
                mAsymmetricPrivateKeyCache.add(keyId, asymKey);
            }

        } while(false);

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::removeAsymmetricKey(const uint32_t& keyId)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        AsymmetricKey  asymmetricKey{};

        if (mAsymmetricPrivateKeyCache.find(keyId)) // Check in private key cache
        {
            asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);

            if (asymmetricKey.key)
            {
                RSA_free(asymmetricKey.key);
            }
            else if (asymmetricKey.ecKey)
            {
                EC_KEY_free(asymmetricKey.ecKey);
            }
            else if (asymmetricKey.edKey)
            {
                EVP_PKEY_free(asymmetricKey.edKey);
            }

            mAsymmetricPrivateKeyCache.remove(keyId);
        }
        else if (mAsymmetricPublicKeyCache.find(keyId)) // Check in public key cache
        {
            asymmetricKey = mAsymmetricPublicKeyCache.get(keyId);

            if (asymmetricKey.key)
            {
                RSA_free(asymmetricKey.key);
            }
            else if (asymmetricKey.ecKey)
            {
                EC_KEY_free(asymmetricKey.ecKey);
            }
            else if (asymmetricKey.edKey)
            {
                EVP_PKEY_free(asymmetricKey.edKey);
            }

            mAsymmetricPublicKeyCache.remove(keyId);
        }
        else
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::getAsymmetricKey(const uint32_t&         keyId,
                                            AsymmetricKey*          asymmetricKey,
                                            const OperationType&    opType)
    {
        bool result = false;

        if (!asymmetricKey)
        {
            return false;
        }

        if (OperationType::Public == opType)
        {
            if (mAsymmetricPublicKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPublicKeyCache.get(keyId);
                result         = asymmetricKey->key || asymmetricKey->ecKey || asymmetricKey->edKey;
            }
        }
        else if (OperationType::Private == opType)
        {
            if (mAsymmetricPrivateKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);
                result         = asymmetricKey->key || asymmetricKey->ecKey || asymmetricKey->edKey;
            }
        }
        else if (OperationType::Any == opType)
        {
            if (mAsymmetricPublicKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPublicKeyCache.get(keyId);
                result         = asymmetricKey->key || asymmetricKey->ecKey || asymmetricKey->edKey;
            }
            else if (mAsymmetricPrivateKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);
                result         = asymmetricKey->key || asymmetricKey->ecKey || asymmetricKey->edKey;
            }
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::encryptBuffer(const uint32_t&    publicKeyId,
                                              const uint8_t*     sourceBuffer,
                                              const uint32_t&    sourceBufferLen,
                                              uint8_t*           destBuffer,
                                              const uint32_t&    destBufferLen,
                                              uint32_t*          destBufferRequiredLength,
                                              const RsaPadding&  rsaPadding)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        bool            result = destBufferRequiredLength    &&
                                 (!destBuffer                ||
                                 (sourceBufferLen            &&
                                  sourceBuffer               &&
                                  destBufferRequiredLength   &&
                                  destBufferLen              &&
                                  (RsaPadding::rsaPkcs1Oaep == rsaPadding || RsaPadding::rsaPkcs1 == rsaPadding)));

        if (result)
        {
            AsymmetricKey asymmetricKey;
            result = getAsymmetricKey(publicKeyId,
                                      &asymmetricKey,
                                      OperationType::Public);
            if (result)
            {
                result = encrypt(asymmetricKey,
                                 rsaPadding,
                                 destBuffer,
                                 destBufferLen,
                                 destBufferRequiredLength,
                                 sourceBuffer,
                                 sourceBufferLen,
                                 &status);
            }
            else
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
            }
        }
        else
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::encrypt(const AsymmetricKey& asymmetricKey,
                                   const RsaPadding&    rsaPadding,
                                   uint8_t*             destBuffer,
                                   const uint32_t&      destBufferLen,
                                   uint32_t*            destBufferRequiredLength,
                                   const uint8_t*       sourceBuffer,
                                   const uint32_t&      sourceBufferLen,
                                   SgxCryptStatus*      status)
    {
        bool result{ false };
        int  rsaBlockSize{};

        if (!status)
        {
            return false;
        }

        do
        {
            if (!destBufferRequiredLength)
            {
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }
            rsaBlockSize = RSA_size(asymmetricKey.key);

            *destBufferRequiredLength = rsaBlockSize;
            if (!destBuffer)
            {
                result = true;
                break;
            }

            // Plain text size limit for RSA encryption with  OAEP padding.
            if (sourceBufferLen >= (rsaBlockSize - rsaOeapSchemeAdditionalPlaceHolder))
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if(destBufferLen < rsaBlockSize)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                break;
            }

            // All input parameters are validated & now ready for encryption
            RSA_blinding_on(asymmetricKey.key, nullptr);
            const int encryptDataSize = RSA_public_encrypt(sourceBufferLen,
                                                           sourceBuffer,
                                                           destBuffer,
                                                           asymmetricKey.key,
                                                           static_cast<int>(rsaPadding));
            RSA_blinding_off(asymmetricKey.key);
            if (encryptDataSize >= 0)
            {
                result = true;
            }
        } while (false);

        if (result)
        {
            *status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::decryptBuffer(const uint32_t&    privateKeyId,
                                              const uint8_t*     sourceBuffer,
                                              const uint32_t&    sourceBufferLen,
                                              uint8_t*           destBuffer,
                                              const uint32_t&    destBufferLen,
                                              uint32_t*          destBufferRequiredLength,
                                              const RsaPadding&  rsaPadding)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        bool            result = destBufferRequiredLength   &&
                                 (!destBuffer               ||
                                 (sourceBufferLen           &&
                                  sourceBuffer              &&
                                  destBufferRequiredLength  &&
                                  (RsaPadding::rsaPkcs1Oaep == rsaPadding || RsaPadding::rsaPkcs1 == rsaPadding)));

        if (result)
        {
            AsymmetricKey asymKey;
            result = getAsymmetricKey(privateKeyId,
                                      &asymKey,
                                      OperationType::Private);
            if (result)
            {
                result = decrypt(asymKey,
                                 rsaPadding,
                                 destBuffer,
                                 destBufferLen,
                                 destBufferRequiredLength,
                                 sourceBuffer,
                                 sourceBufferLen,
                                 &status);
            }
            else
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
            }
        }
        else
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::decrypt(const AsymmetricKey& asymmetricKey,
                                   const RsaPadding&    rsaPadding,
                                   uint8_t*             destBuffer,
                                   const uint32_t&      destBufferLen,
                                   uint32_t*            destBufferRequiredLength,
                                   const uint8_t*       sourceBuffer,
                                   const uint32_t&      sourceBufferLen,
                                   SgxCryptStatus*      status)
    {
        bool    result{ true };
        int     rsaBlockSize{};

        if (!status)
        {
            return false;
        }

        do
        {
            rsaBlockSize = RSA_size(asymmetricKey.key);

            // Plain text size limit for RSA encryption with  OAEP padding.
            if ((sourceBufferLen < rsaBlockSize) || !destBufferRequiredLength)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            std::unique_ptr<uint8_t[]> tempDestBuffer(new (std::nothrow) uint8_t[rsaBlockSize], std::default_delete<uint8_t[]>());
            if (!tempDestBuffer.get())
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }
            // All input parameters are validated & now ready for encryption
            RSA_blinding_on(asymmetricKey.key, nullptr);

            const int decryptDataSize = RSA_private_decrypt(sourceBufferLen,
                                                            sourceBuffer,
                                                            tempDestBuffer.get(),
                                                            asymmetricKey.key,
                                                            static_cast<int>(rsaPadding));
            RSA_blinding_off(asymmetricKey.key);

            if (decryptDataSize < 0)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            *destBufferRequiredLength = decryptDataSize;
            if (!destBuffer)
            {
                result = true;
                break;
            }

            if (destBufferLen < *destBufferRequiredLength)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                break;
            }

            memcpy_s(destBuffer,
                     destBufferLen,
                     tempDestBuffer.get(),
                     static_cast<size_t>(*destBufferRequiredLength));

        } while (false);

        if (result)
        {
            *status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::addRsaPrivateKey(const uint32_t& keyId, const AsymmetricKey& asymmetricKey)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;

        do
        {
            if (!keyId)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPrivateKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            //Store in asymmetric private key cache
            mAsymmetricPrivateKeyCache.add(keyId, asymmetricKey);

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::encodeRsaKey(const RSA* rsaKey, uint8_t** encodedKey, uint64_t* encodedKeySize, bool onlyPublicKey)
    {
        if (!rsaKey || !encodedKey || !encodedKeySize)
        {
            return false;
        }

        int keySizeRequired = 0;
        int bytesWritten    = 0;

        if (onlyPublicKey)
        {
            keySizeRequired = i2d_RSAPublicKey(rsaKey, nullptr);
        }
        else
        {
            keySizeRequired = i2d_RSAPrivateKey(rsaKey, nullptr);
        }

        if (keySizeRequired < 0)
        {
            return false;
        }

        *encodedKey = new (std::nothrow) uint8_t[keySizeRequired];
        if (!*encodedKey)
        {
            return false;
        }

        if (onlyPublicKey)
        {
            bytesWritten = i2d_RSAPublicKey(rsaKey, encodedKey);
        }
        else
        {
            bytesWritten = i2d_RSAPrivateKey(rsaKey, encodedKey);
        }

        if (bytesWritten < 0)
        {
            return false;
        }

        *encodedKey -= (bytesWritten);
        *encodedKeySize = keySizeRequired;

        return true;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::generateAsymmetricKey(const uint32_t&          publicKeyId,
                                                      const uint32_t&          privateKeyId,
                                                      const AsymmetricKeySize& modulusLength,
                                                      const uint64_t*          attributeBufferPublic,
                                                      const uint64_t&          attributeBufferPublicLen,
                                                      const uint64_t*          attributeBufferPrivate,
                                                      const uint64_t&          attributeBufferPrivateLen,
                                                      const ByteBuffer&        pinMaterial)
    {
        SgxCryptStatus status     = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        BIGNUM*        bigNum     = nullptr;
        RSA*           rsaKey     = nullptr;
        uint8_t*       encodedKey = nullptr;
        bool           result     = false;
        std::string    filePathPublicKey, filePathPrivateKey;

        do
        {
            uint16_t keyLength = static_cast<uint16_t>(modulusLength);
            result = publicKeyId                    &&
                     privateKeyId                   &&
                     (keyLength >= minRsaKeySize)   &&
                     (keyLength <= maxRsaKeySize)   &&
                     !(keyLength % rsaKeyFactorValue);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPrivateKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            rsaKey = RSA_new();
            bigNum = BN_new();

            if (!rsaKey || !bigNum)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            BN_set_word(bigNum, rsaF4);

            // Generate new RSA key for given modulusLength(|n|) & exponent(e)
            if (1 == RSA_generate_key_ex(rsaKey, keyLength, bigNum, nullptr))
            {
                // public key
                AsymmetricKey asymKey{};
                asymKey.key = rsaKey;

                uint64_t encodedKeySize = 0;

                if (attributeBufferPublic || attributeBufferPrivate)
                {
                    if (!encodeRsaKey(asymKey.key, &encodedKey, &encodedKeySize))
                    {
                        status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                        break;
                    }
                }

                uint64_t pairKeyId = 0;
                if (SGX_SUCCESS != sgx_read_rand(reinterpret_cast<unsigned char*>(&pairKeyId), sizeof(pairKeyId)))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                    break;
                }

                if (attributeBufferPublic)
                {
                    std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                    if (fileName.empty())
                    {
                        status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                        break;
                    }

                    result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBufferPublic, attributeBufferPublicLen,
                                                                        encodedKey, encodedKeySize, false, pairKeyId, &filePathPublicKey);
                    if (!result)
                    {
                        status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                        break;
                    }
                }

                if (attributeBufferPrivate)
                {
                    std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                    if (fileName.empty())
                    {
                        status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                        break;
                    }

                    result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBufferPrivate, attributeBufferPrivateLen,
                                                                        encodedKey, encodedKeySize, false, pairKeyId, &filePathPrivateKey);
                    if (!result)
                    {
                        status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                        break;
                    }
                }

                RSA* dupRsaKey = RSAPrivateKey_dup(asymKey.key);
                if (!dupRsaKey)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                    break;
                }

                // add public key to the cache
                asymKey.pairKeyId   = pairKeyId;
                asymKey.keyFile     = filePathPublicKey;
                mAsymmetricPublicKeyCache.add(publicKeyId, asymKey);

                asymKey.key         = dupRsaKey;
                asymKey.keyFile     = filePathPrivateKey;
                mAsymmetricPrivateKeyCache.add(privateKeyId, asymKey);

                status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            }
            else
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
            }
        } while (false);

        BN_clear_free(bigNum);

        if (encodedKey)
        {
            delete encodedKey;
            encodedKey = nullptr;
        }

        if (rsaKey && !result)
        {
            RSA_free(rsaKey);
        }

        if (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != status)
        {
            Utils::SgxFileUtils::remove(filePathPublicKey);
            Utils::SgxFileUtils::remove(filePathPrivateKey);
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::exportPublicKey(const uint32_t&  keyId,
                                                uint8_t*         destBuffer,
                                                const uint32_t&  destBufferLength,
                                                uint32_t*        modulusLength,
                                                uint32_t*        exponentLength)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        bool           result = false;

        do
        {
            result = modulusLength && exponentLength;

            if (!result)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            AsymmetricKey asymKey;
            result = getAsymmetricKey(keyId, &asymKey, OperationType::Any);
            if (!result)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L

            *modulusLength = BN_num_bytes(asymKey.key->n);
            *exponentLength  = BN_num_bytes(asymKey.key->e);
#else
            /* OpenSSL 1.1.0 and above (new code) */
            const BIGNUM *bn_n;
            const BIGNUM *bn_e;
            const BIGNUM *bn_d;

            RSA_get0_key(asymKey.key, &bn_n, &bn_e, &bn_d);

            *modulusLength   = BN_num_bytes(bn_n);
            *exponentLength  = BN_num_bytes(bn_e);
#endif

            if (!destBuffer)
            {
                result = true;
                break;
            }

            if (destBufferLength < (*modulusLength + *exponentLength))
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                break;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L

            // Below does copy in big-Endian format
            BN_bn2bin(asymKey.key->e, destBuffer);
            BN_bn2bin(asymKey.key->n, destBuffer + *exponentLength);
#else
            /* OpenSSL 1.1.0 and above (new code) */
            RSA_get0_key(asymKey.key, &bn_n, &bn_e, &bn_d);
            BN_bn2bin(bn_e, destBuffer);
            BN_bn2bin(bn_n, destBuffer + *exponentLength);
#endif
        } while (false);

        if (result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::importPublicKey(const uint32_t&   keyId,
                                                uint8_t*          modulusBuffer,
                                                const uint32_t&   modulusBufferLen,
                                                uint8_t*          exponentBuffer,
                                                const uint32_t&   exponentBufferLen,
                                                const uint64_t*   attributeBuffer,
                                                const uint64_t&   attributeBufferLen,
                                                const ByteBuffer& pinMaterial)
    {
        SgxCryptStatus status     = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        RSA*           rsaKey     = nullptr;
        uint8_t*       encodedKey = nullptr;
        bool           result     = false;

        do
        {
            result = keyId              &&
                     modulusBuffer      &&
                     modulusBufferLen   &&
                     exponentBuffer     &&
                     exponentBufferLen;

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            rsaKey = RSA_new();

            if (!rsaKey)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L

            rsaKey->n = BN_bin2bn(modulusBuffer, modulusBufferLen, nullptr);
            rsaKey->e = BN_bin2bn(exponentBuffer, exponentBufferLen, nullptr);

            // Do possible sanity checks
            if (!BN_is_odd(rsaKey->e) || BN_is_one(rsaKey->e))
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }
#else
            /* OpenSSL 1.1.0 and above (new code) */
            BIGNUM *bn_n;
            BIGNUM *bn_e;
            BIGNUM *bn_d = nullptr;

            bn_d = BN_secure_new();
            bn_n = BN_bin2bn(modulusBuffer, modulusBufferLen, nullptr);
            bn_e = BN_bin2bn(exponentBuffer, exponentBufferLen, nullptr);

            RSA_set0_key(rsaKey, bn_n, bn_e, bn_d);

            if (!BN_is_odd(bn_e) || BN_is_one(bn_e))
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

#endif
            AsymmetricKey asymKey;
            asymKey.key = rsaKey;

            uint64_t encodedKeySize = 0;

            std::string filePath;

            if (attributeBuffer)
            {
                if (!encodeRsaKey(asymKey.key, &encodedKey, &encodedKeySize, true))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                    encodedKey, encodedKeySize, false, 0, &filePath);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                asymKey.keyFile = filePath;
            }

            mAsymmetricPublicKeyCache.add(keyId, asymKey);
        } while (false);

        if (encodedKey)
        {
            delete encodedKey;
            encodedKey = nullptr;
        }

        if (rsaKey && !result)
        {
            RSA_free(rsaKey);
        }

        if (result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool getHashValue(const HashMode& hashMode,
                      const uint8_t*  sourceBuffer,
                      const uint32_t& sourceBufferLen,
                      uint8_t*        destBuffer,
                      const uint32_t& destBufferLen)
    {
        CryptoHash cryptoHash;

        return cryptoHash.computeHash(hashMode, sourceBuffer, sourceBufferLen, destBuffer, destBufferLen);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::rsaSign(const uint32_t&    keyId,
                                        const uint8_t*     sourceBuffer,
                                        const uint32_t&    sourceBufferLen,
                                        uint8_t*           destBuffer,
                                        size_t             destBufferLen,
                                        uint32_t*          destBufferRequiredLength,
                                        const uint32_t     hashAlgorithm,
                                        const RsaPadding&  rsaPadding,
                                        const HashMode&    hashMode,
                                        const uint32_t&    salt)
    {
        SgxCryptStatus       cryptStatus  = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        SgxStatus            status       = 0;
        bool                 result       = false;
        uint32_t             rsaBlockSize = 0;
        uint32_t             hashLength   = 0;
        auto                 inputLength  = 0;
        std::vector<uint8_t> bufferToSign;

        do
        {
            result = !destBuffer                ||
                     (destBufferRequiredLength  &&
                     sourceBuffer               &&
                     sourceBufferLen            &&
                     ((RsaPadding::rsaPkcs1 == rsaPadding) || (RsaPadding::rsaPkcs1Pss == rsaPadding)));

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId,
                                      &asymKey,
                                      OperationType::Private);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
                break;
            }

            rsaBlockSize = RSA_size(asymKey.key);
            *destBufferRequiredLength = rsaBlockSize;

            if (!destBuffer)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                break;
            }

            if (destBufferLen < rsaBlockSize)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT);
                break;
            }

            const EVP_MD* evpMd = EVP_get_digestbynid(hashAlgorithm);
            if (!evpMd)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
                break;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            hashLength = evpMd->md_size;
#else
            hashLength = EVP_MD_size(evpMd);
#endif
            if (HashMode::sha256 == hashMode ||
                HashMode::sha512 == hashMode)
            {
                inputLength = static_cast<uint32_t>(hashDigestLengthMap[hashMode]);

                bufferToSign.resize(inputLength);
                if (!bufferToSign.data())
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                    break;
                }

                result = getHashValue(hashMode, sourceBuffer, sourceBufferLen, bufferToSign.data(), inputLength);
                if (!result)
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
                    break;
                }
            }
            else
            {
                inputLength = sourceBufferLen;
                bufferToSign.resize(inputLength);
                if (!bufferToSign.data())
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                    break;
                }

                memcpy_s(bufferToSign.data(), inputLength, sourceBuffer, inputLength);
            }

            if (inputLength < hashLength ||
                inputLength >= (rsaBlockSize - rsaPkcs1SchemeAdditionalPlaceholder))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT);
                break;
            }

            RSA_blinding_on(asymKey.key, nullptr);

            if (RsaPadding::rsaPkcs1 == rsaPadding)
            {
                int signResult = 0;
                signResult = RSA_private_encrypt(inputLength,
                                                 bufferToSign.data(),
                                                 destBuffer,
                                                 asymKey.key,
                                                 static_cast<int>(rsaPadding));

                if (signResult < 0)
                {
                    result = false;
                }
            }
            else  // PSS
            {
                result = signHashPss(asymKey,
                                     bufferToSign.data(),
                                     destBuffer,
                                     rsaBlockSize,
                                     evpMd,
                                     salt,
                                     &cryptStatus);
            }

            RSA_blinding_off(asymKey.key);
            if (!result)
            {
                if (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != cryptStatus)
                {
                    status = static_cast<SgxStatus>(cryptStatus);
                }
                else
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE);
                }
            }

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    static size_t getEcOrderLength(const EC_KEY* ecKey)
    {
        size_t len = 0;

        if (!ecKey)
        {
            return len;
        }

        const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
        if (!ecGroup)
        {
            return len;
        }

        BIGNUM* ecOrder = BN_new();
        if (!ecOrder)
        {
            return len;
        }

        if (!EC_GROUP_get_order(ecGroup, ecOrder, nullptr))
        {
            BN_clear_free(ecOrder);
            return len;
        }

        len = BN_num_bytes(ecOrder);
        BN_clear_free(ecOrder);

        return len;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::ecSign(const uint32_t& keyId,
                                       const uint8_t*  sourceBuffer,
                                       const uint32_t& sourceBufferLen,
                                       uint8_t*        destBuffer,
                                       size_t          destBufferLen,
                                       uint32_t*       destBufferRequiredLength)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
        bool      result = false;

        do
        {
            result = destBufferRequiredLength && sourceBuffer && sourceBufferLen;

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId,
                                      &asymKey,
                                      OperationType::Private);

            if (!result)
            {
                break;
            }

            EC_KEY* ecKey = asymKey.ecKey;
            if (!ecKey)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            EC_KEY_set_method(ecKey, EC_KEY_OpenSSL());

            size_t len = getEcOrderLength(ecKey);

            if (!len)
            {
                break;
            }

            if (!destBuffer)
            {
                *destBufferRequiredLength = 2 * len;

                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                break;
            }

            if (destBufferLen < (2 * len))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT);
                break;
            }

            ECDSA_SIG *ecSign = ECDSA_do_sign(sourceBuffer, sourceBufferLen, ecKey);
            if (!ecSign)
            {
                break;
            }

            const BIGNUM* bn_r = nullptr;
            const BIGNUM* bn_s = nullptr;

            ECDSA_SIG_get0(ecSign, &bn_r, &bn_s);

            BN_bn2bin(bn_r, destBuffer + (len - BN_num_bytes(bn_r)));
            BN_bn2bin(bn_s, destBuffer + (2 * len - BN_num_bytes(bn_s)));

            ECDSA_SIG_free(ecSign);

            *destBufferRequiredLength = 2 * len;

            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        } while(false);

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::edSign(const uint32_t& keyId,
                                       const uint8_t*  sourceBuffer,
                                       const uint32_t& sourceBufferLen,
                                       uint8_t*        destBuffer,
                                       size_t          destBufferLen,
                                       uint32_t*       destBufferRequiredLength)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
        bool      result = false;

        do
        {
            result = destBufferRequiredLength && sourceBuffer && sourceBufferLen;

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId,
                                      &asymKey,
                                      OperationType::Private);

            if (!result)
            {
                break;
            }

            EVP_PKEY* edKey = asymKey.edKey;
            if (!edKey)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            size_t len = 2 * ed25519KeyLength;

            if (!destBuffer)
            {
                *destBufferRequiredLength = len;

                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
                break;
            }

            if (destBufferLen < len)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT);
                break;
            }

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx)
            {
                break;
            }

            EVP_PKEY_CTX *pKeyCtx;

            int retValue = EVP_DigestSignInit(ctx, &pKeyCtx, nullptr, nullptr, edKey);
            if (1 != retValue)
            {
                EVP_MD_CTX_free(ctx);
                break;
            }

            if (1 != EVP_DigestSign(ctx, destBuffer, &len, sourceBuffer, sourceBufferLen))
            {
                EVP_MD_CTX_free(ctx);
                break;
            }

            EVP_MD_CTX_free(ctx);

            *destBufferRequiredLength = len;

            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        } while(false);

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::sign(const uint32_t&    keyId,
                                     const uint8_t*     sourceBuffer,
                                     const uint32_t&    sourceBufferLen,
                                     uint8_t*           destBuffer,
                                     size_t             destBufferLen,
                                     uint32_t*          destBufferRequiredLength,
                                     const uint32_t     hashAlgorithm,
                                     const RsaPadding&  rsaPadding,
                                     const HashMode&    hashMode,
                                     const uint32_t&    salt)
    {
        SgxStatus status = 0;

        if (mAsymmetricPrivateKeyCache.isRsaKey(keyId))
        {
            status = rsaSign(keyId,
                             sourceBuffer,
                             sourceBufferLen,
                             destBuffer,
                             destBufferLen,
                             destBufferRequiredLength,
                             hashAlgorithm,
                             rsaPadding,
                             hashMode,
                             salt);
        }
        else if (mAsymmetricPrivateKeyCache.isEcKey(keyId))
        {
            status = ecSign(keyId,
                            sourceBuffer,
                            sourceBufferLen,
                            destBuffer,
                            destBufferLen,
                            destBufferRequiredLength);
        }
        else if (mAsymmetricPrivateKeyCache.isEdKey(keyId))
        {
            status = edSign(keyId,
                            sourceBuffer,
                            sourceBufferLen,
                            destBuffer,
                            destBufferLen,
                            destBufferRequiredLength);
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
        }

        return static_cast<SgxStatus>(status);
    }

#ifdef EC_VERIFY
    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::ecVerify(const uint32_t& keyId,
                                         const uint8_t*  sourceBuffer,
                                         const uint32_t& sourceBufferLen,
                                         const uint8_t*  signatureBuffer,
                                         const uint32_t& signatureBufferLen)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
        bool      result = false;

        do
        {
            result = sourceBufferLen &&
                     sourceBuffer    &&
                     signatureBuffer;

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId, &asymKey, OperationType::Public);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            EC_KEY* ecKey = asymKey.ecKey;
            if (!ecKey)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            EC_KEY_set_method(ecKey, EC_KEY_OpenSSL());

            size_t len = getEcOrderLength(ecKey);

            if (!len)
            {
                break;
            }

            if ((2 * len) != signatureBufferLen)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE_LENGTH);
                break;
            }

            ECDSA_SIG* ecSign = ECDSA_SIG_new();
            if (!ecSign)
            {
                break;
            }

            BIGNUM* bn_r = BN_bin2bn(signatureBuffer, len, nullptr);
            BIGNUM* bn_s = BN_bin2bn(signatureBuffer + len, len, nullptr);

            if (!bn_r || !bn_s || !ECDSA_SIG_set0(ecSign, bn_r, bn_s))
            {
                ECDSA_SIG_free(ecSign);
                break;
            }

            int verifyStatus = ECDSA_do_verify(sourceBuffer, sourceBufferLen, ecSign, ecKey);

            ECDSA_SIG_free(ecSign);

            if (!verifyStatus)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE);

            }
            else if(-1 == verifyStatus)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
            }
            else
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
            }
        } while(false);

        return status;
    }
#endif

#ifdef ED_VERIFY
    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::edVerify(const uint32_t& keyId,
                                         const uint8_t*  sourceBuffer,
                                         const uint32_t& sourceBufferLen,
                                         const uint8_t*  signatureBuffer,
                                         const uint32_t& signatureBufferLen)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
        bool      result = false;

        do
        {
            result = sourceBufferLen &&
                     sourceBuffer    &&
                     signatureBuffer;

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId, &asymKey, OperationType::Public);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            EVP_PKEY* edKey = asymKey.edKey;
            if (!edKey)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            size_t len = 2 * ed25519KeyLength;

            if (len != signatureBufferLen)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE_LENGTH);
                break;
            }

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx)
            {
                break;
            }

            if (!EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, edKey))
            {
                EVP_MD_CTX_free(ctx);
                break;
            }

            if (1 != EVP_DigestVerify(ctx, signatureBuffer, signatureBufferLen, sourceBuffer, sourceBufferLen))
            {
                EVP_MD_CTX_free(ctx);
                break;
            }

            EVP_MD_CTX_free(ctx);

            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        } while(false);

        return status;
    }
#endif

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::rsaVerify(const uint32_t&   keyId,
                                          const uint8_t*    sourceBuffer,
                                          const uint32_t&   sourceBufferLen,
                                          const uint8_t*    signatureBuffer,
                                          const uint32_t&   signatureBufferLen,
                                          const uint32_t&   hashAlgorithm,
                                          const RsaPadding& rsaPadding,
                                          const HashMode&   hashMode,
                                          const uint32_t&   salt)
    {
        SgxCryptStatus       cryptStatus  = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        SgxStatus            status       = 0;
        bool                 result       = false;
        uint32_t             rsaBlockSize = 0;
        uint32_t             hashLength   = 0;
        auto                 inputLength  = 0;
        std::vector<uint8_t> bufferUsedForSign;
        std::vector<uint8_t> recoveredMessage;

        do
        {
            result = sourceBufferLen    &&
                     sourceBuffer       &&
                     signatureBuffer    &&
                     ((RsaPadding::rsaPkcs1 == rsaPadding) ||(RsaPadding::rsaPkcs1Pss == rsaPadding));

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId, &asymKey, OperationType::Public);

            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
                break;
            }

            rsaBlockSize = RSA_size(asymKey.key);

            if (signatureBufferLen != rsaBlockSize)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE_LENGTH);
                break;
            }

            const EVP_MD* evpMd = EVP_get_digestbynid(hashAlgorithm);
            if (evpMd)
            {
                // Input size MIN limit to hold the message digest
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                hashLength = evpMd->md_size;
#else
                hashLength = EVP_MD_size(evpMd);
#endif
            }

            if (HashMode::sha256 == hashMode ||
                HashMode::sha512 == hashMode)
            {
                inputLength = static_cast<uint32_t>(hashDigestLengthMap[hashMode]);

                recoveredMessage.resize(inputLength);
                if (!recoveredMessage.data())
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                    break;
                }

                bufferUsedForSign.resize(inputLength);
                if (!bufferUsedForSign.data())
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                    break;
                }

                result = getHashValue(hashMode, sourceBuffer, sourceBufferLen, bufferUsedForSign.data(), inputLength);
                if (!result)
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED);
                    break;
                }
            }
            else
            {
                recoveredMessage.resize(sourceBufferLen);
                if (!recoveredMessage.data())
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                    break;
                }

                // used for raw PSS
                inputLength = sourceBufferLen;
                bufferUsedForSign.resize(inputLength);
                if (!bufferUsedForSign.data())
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                    break;
                }

                memcpy_s(bufferUsedForSign.data(), inputLength, sourceBuffer, inputLength);
            }

            if (sourceBufferLen < hashLength ||
                sourceBufferLen >= (rsaBlockSize - rsaPkcs1SchemeAdditionalPlaceholder))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            RSA_blinding_on(asymKey.key, nullptr);

            if (RsaPadding::rsaPkcs1 == rsaPadding)
            {
                int verifyResult = 0;
                verifyResult = RSA_public_decrypt(signatureBufferLen,
                                                  signatureBuffer,
                                                  recoveredMessage.data(),
                                                  asymKey.key,
                                                  static_cast<int>(rsaPadding));

                if (verifyResult >= 0)
                {
                    if (verifyResult == inputLength)
                    {
                        if (recoveredMessage == bufferUsedForSign)
                        {
                            result = true;
                        }
                        else
                        {
                            result = false;
                        }
                    }
                    else
                    {
                        status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                        break;
                    }
                }
                else
                {
                    result = false;
                }
            }
            else  // PSS
            {
                result = verifySignaturePss(asymKey,
                                            bufferUsedForSign.data(),
                                            signatureBuffer,
                                            rsaBlockSize,
                                            evpMd,
                                            salt,
                                            &cryptStatus);
            }

            RSA_blinding_off(asymKey.key);

            if (!result)
            {
                if (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != cryptStatus)
                {
                    status = static_cast<SgxStatus>(cryptStatus);
                }
                else
                {
                    status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_SIGNATURE);
                }
            }

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::verifySign(const uint32_t&   keyId,
                                           const uint8_t*    sourceBuffer,
                                           const uint32_t&   sourceBufferLen,
                                           const uint8_t*    signatureBuffer,
                                           const uint32_t&   signatureBufferLen,
                                           const uint32_t&   hashAlgorithm,
                                           const RsaPadding& rsaPadding,
                                           const HashMode&   hashMode,
                                           const uint32_t&   salt)
    {
        SgxStatus status = 0;

        if (mAsymmetricPublicKeyCache.isRsaKey(keyId))
        {
            status = rsaVerify(keyId,
                               sourceBuffer,
                               sourceBufferLen,
                               signatureBuffer,
                               signatureBufferLen,
                               hashAlgorithm,
                               rsaPadding,
                               hashMode,
                               salt);
        }
        else if (mAsymmetricPublicKeyCache.isEcKey(keyId))
        {
#ifdef EC_VERIFY
            status = ecVerify(keyId,
                              sourceBuffer,
                              sourceBufferLen,
                              signatureBuffer,
                              signatureBufferLen);
#else
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
#endif
        }
        else if (mAsymmetricPublicKeyCache.isEdKey(keyId))
        {
#ifdef ED_VERIFY
            status = edVerify(keyId,
                              sourceBuffer,
                              sourceBufferLen,
                              signatureBuffer,
                              signatureBufferLen);
#else
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
#endif
        }
        else
        {
            status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::signHashPss(const AsymmetricKey& asymKey,
                                       const uint8_t*       sourceBuffer,
                                       uint8_t*             destBuffer,
                                       const int&           rsaBlockSize,
                                       const EVP_MD*        evpMd,
                                       const uint32_t&      salt,
                                       SgxCryptStatus*      status)
    {
        bool result = true;

        if (!status)
        {
            return false;
        }

        do
        {
            uint32_t hashLength{};
            if (!evpMd)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            hashLength = evpMd->md_size;
#else
            hashLength = EVP_MD_size(evpMd);
            #endif

            const uint32_t maxSalt = getMaxSalt(rsaBlockSize, hashLength);

            if (destBuffer && (salt > maxSalt))
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            std::unique_ptr<uint8_t[]> tempDestBuffer(new (std::nothrow) uint8_t[rsaBlockSize], std::default_delete<uint8_t[]>());
            if (!tempDestBuffer.get())
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            // Apply PSS padding on input hash for given salt & Hash Alg
            result = RSA_padding_add_PKCS1_PSS(asymKey.key,
                                               tempDestBuffer.get(),
                                               sourceBuffer,
                                               evpMd,
                                               salt);

            if (!result)
            {
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            // Generate signature from the PSS padded hash
            const int encryptDataSize = RSA_private_encrypt(rsaBlockSize,
                                                            tempDestBuffer.get(),
                                                            destBuffer,
                                                            asymKey.key,
                                                            static_cast<int>(RsaPadding::rsaNoPadding));
            if (encryptDataSize < 0)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::verifySignaturePss(const AsymmetricKey&  asymKey,
                                              const uint8_t*        sourceBuffer,
                                              const uint8_t*        signatureBuffer,
                                              const int&            rsaBlockSize,
                                              const EVP_MD*         evpMd,
                                              const uint32_t&       salt,
                                              SgxCryptStatus*       status)
    {
        bool result = false;

        if (!status)
        {
            return false;
        }

        do
        {
            uint32_t hashLength{};
            if (!evpMd)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            //hashLength = evpMd->md_size;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            hashLength = evpMd->md_size;
#else
            hashLength = EVP_MD_size(evpMd);
#endif

            const uint32_t maxSalt = getMaxSalt(rsaBlockSize, hashLength);

            if (salt > maxSalt)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            std::unique_ptr<uint8_t[]> tempDestBuffer(new (std::nothrow) uint8_t[rsaBlockSize], std::default_delete<uint8_t[]>());
            if (!tempDestBuffer.get())
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            const int decryptDataSize = RSA_public_decrypt(rsaBlockSize,
                                                            signatureBuffer,
                                                            tempDestBuffer.get(),
                                                            asymKey.key,
                                                            static_cast<int>(RsaPadding::rsaNoPadding));
            if (decryptDataSize < 0)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            result = RSA_verify_PKCS1_PSS(asymKey.key,
                                          sourceBuffer,
                                          evpMd,
                                          tempDestBuffer.get(),
                                          salt);
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::getPublicKeyHash(const uint32_t&    keyId,
                                                 uint8_t*           destBuffer,
                                                 const uint32_t&    destBufferLen,
                                                 const HashMode&    hashMode)
    {
        SgxStatus   status              = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        uint32_t    rsaPublicKeySize    = 0;
        uint32_t    cbPublicExp         = 0;
        uint32_t    cbModulus           = 0;

        do
        {
            if (!destBuffer || !destBufferLen)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            if (!mAsymmetricPublicKeyCache.find(keyId))
            {
                return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            }

            const AsymmetricKey asymKey = mAsymmetricPublicKeyCache.get(keyId);

            status = exportPublicKey(keyId, nullptr, 0, &cbModulus, &cbPublicExp);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }

            // Frame the public key in RSA PUBLIC KEY format
            rsaPublicKeySize = cbModulus + cbPublicExp;
            std::unique_ptr<uint8_t[]> rsaPublicKey(new (std::nothrow) uint8_t[rsaPublicKeySize], std::default_delete<uint8_t[]>());
            if (!rsaPublicKey.get())
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                break;
            }

            status = exportPublicKey(keyId,
                                     rsaPublicKey.get(),
                                     rsaPublicKeySize,
                                     &cbModulus,
                                     &cbPublicExp);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }

            // Compute the Hash of this formatted public key
            uint32_t hashLength = 0;
            if (HashMode::sha256 == hashMode)
            {
                hashLength = static_cast<uint32_t>(HashDigestLength::sha256);
            }
            else if (HashMode::sha512 == hashMode)
            {
                hashLength = static_cast<uint32_t>(HashDigestLength::sha512);
            }
            else
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }

            if (destBufferLen < hashLength)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
            }
            const bool hashResult = getHashValue(hashMode,
                                                 rsaPublicKey.get(),
                                                 rsaPublicKeySize,
                                                 destBuffer,
                                                 hashLength); // Even if destbufferlen > hashLength,
                                                              // we populate the first hashLength bytes.
            if (!hashResult)
            {
                memset_s(destBuffer, destBufferLen, 0, destBufferLen);
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                break;
            }
        } while (false);

        return status;
    }

    //---------------------------------------------------------------------------------------------
    static std::vector<uint8_t> getEcPublicKey(const EC_KEY*   ecKey,
                                               const EC_GROUP* ecGroup)
    {
        bool                 result       = false;
        uint64_t             publicKeyLen = 0;
        std::vector<uint8_t> publicKey{};

        do
        {
            if (!ecKey || !ecGroup)
            {
                break;
            }

            const EC_POINT* ecPoint = EC_KEY_get0_public_key(ecKey);
            if (!ecPoint)
            {
                break;
            }

            size_t point_length = EC_POINT_point2oct(ecGroup,
                                                     ecPoint,
                                                     POINT_CONVERSION_UNCOMPRESSED,
                                                     nullptr,
                                                     0,
                                                     nullptr);

            // Definite, short
            if (point_length <= 0x7f)
            {
                publicKeyLen = 2 + point_length;

                publicKey.resize(publicKeyLen);

                unsigned char *derQ = publicKey.data();
                derQ[0] = V_ASN1_OCTET_STRING;
                derQ[1] = point_length & 0x7f;
                result = EC_POINT_point2oct(ecGroup,
                                            ecPoint,
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            publicKey.data() + 2,
                                            point_length,
                                            nullptr);
                if (!result)
                {
                    break;
                }
            }
            // Definite, long
            else
            {
                // Count significate bytes
                size_t bytes = sizeof(size_t);
                for(; bytes > 0; bytes--)
                {
                    size_t value = point_length >> ((bytes - 1) * 8);
                    if (value & 0xFF) break;
                }

                publicKeyLen = 2 + bytes + point_length;
                publicKey.resize(publicKeyLen);

                unsigned char *derQ = publicKey.data();
                derQ[0] = V_ASN1_OCTET_STRING;
                derQ[1] = 0x80 | bytes;

                size_t len = point_length;
                size_t offset = 0;
                for (size_t i = 1; i <= bytes; i++)
                {
                    offset = 2 + bytes - i;
                    publicKey[offset] = (unsigned char) (len & 0xFF);
                    len >>= 8;
                }

                offset = 2 + bytes;
                result = EC_POINT_point2oct(ecGroup,
                                            ecPoint,
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            publicKey.data() + offset,
                                            point_length,
                                            nullptr);
                if (!result)
                {
                    break;
                }
            }

            result = true;
        } while(false);

        if (!result)
        {
            publicKey.resize(0);
        }

        return publicKey;
    }

    //---------------------------------------------------------------------------------------------
    static std::vector<uint8_t> getEncodedEcKey(const EC_KEY* ecKey)
    {
        std::vector<uint8_t> encodedKey;

        do
        {
            if (!ecKey)
            {
                break;
            }

            // Extract private key
            const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
            if (!ecGroup)
            {
                break;
            }

            const BIGNUM* ecPrivateKey = EC_KEY_get0_private_key(ecKey);
            if (!ecPrivateKey)
            {
                break;
            }

            uint8_t privateKeyLen = BN_num_bytes(ecPrivateKey);

            // Extract der params
            std::vector<uint8_t> derParams;
            derParams.resize(i2d_ECPKParameters(ecGroup, nullptr));

            size_t derParamsLen = derParams.size();

            unsigned char *derPtr = derParams.data();
            if (!i2d_ECPKParameters(ecGroup, &derPtr))
            {
                break;
            }

            // Extract public key
            std::vector<uint8_t> publicKey = getEcPublicKey(ecKey, ecGroup);
            if (publicKey.empty())
            {
                break;
            }

            size_t publicKeyLen = publicKey.size();

            // Allocate memory for public key, private key and derParams.
            size_t offset = 3; // Allocate 3 extra bytes for sizes.
            encodedKey.resize(offset + privateKeyLen + publicKeyLen + derParamsLen);

            // Copy the sizes
            offset = 0;
            encodedKey[offset++] = privateKeyLen;
            encodedKey[offset++] = derParamsLen;
            encodedKey[offset++] = publicKeyLen;

            // Copy private key
            BN_bn2bin(ecPrivateKey, encodedKey.data() + offset);
            offset += privateKeyLen;

            // Copy der params
            memcpy_s(encodedKey.data() + offset, derParamsLen, derParams.data(), derParamsLen);
            offset += derParamsLen;

            // Copy encoded public key
            memcpy_s(encodedKey.data() + offset, publicKeyLen, publicKey.data(), publicKeyLen);

        } while(false);

        return encodedKey;
    }

    //---------------------------------------------------------------------------------------------
    static std::vector<uint8_t> getEncodedEdKey(EVP_PKEY* edKey)
    {
        std::vector<uint8_t> encodedKey;

        do
        {
            if (!edKey)
            {
                break;
            }

            // Extract der params
            std::vector<uint8_t> derParams;

            int nid = EVP_PKEY_id(edKey);
            derParams.resize(i2d_ASN1_OBJECT(OBJ_nid2obj(nid), nullptr));

            size_t derParamsLen = derParams.size();

            unsigned char *derPtr = derParams.data();
            if (!i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &derPtr))
            {
                break;
            }

            // Extract public key
            size_t publicKeyLen = 0;

            if (1 != EVP_PKEY_get_raw_public_key(edKey, nullptr, &publicKeyLen))
            {
                break;
            }

            if (ed25519KeyLength != publicKeyLen)
            {
                break;
            }

            std::vector<uint8_t> edPublicKey(publicKeyLen);
            if (1 != EVP_PKEY_get_raw_public_key(edKey, edPublicKey.data(), &publicKeyLen))
            {
                break;
            }

            // Extract private key
            size_t privateKeyLen = 0;

            if (1 != EVP_PKEY_get_raw_private_key(edKey, nullptr, &privateKeyLen))
            {
                break;
            }

            if (ed25519KeyLength != privateKeyLen)
            {
                break;
            }

            std::vector<uint8_t> edPrivateKey(privateKeyLen);
            if (1 != EVP_PKEY_get_raw_private_key(edKey, edPrivateKey.data(), &privateKeyLen))
            {
                break;
            }

            // Allocate memory for public key, private key and derParams.
            size_t offset = 3; // Allocate 3 extra bytes for sizes.
            encodedKey.resize(offset + privateKeyLen + publicKeyLen + derParamsLen);

            // Copy the sizes
            offset = 0;
            encodedKey[offset++] = privateKeyLen;
            encodedKey[offset++] = derParamsLen;
            encodedKey[offset++] = publicKeyLen;

            // Copy private key
            memcpy_s(encodedKey.data() + offset, privateKeyLen, edPrivateKey.data(), privateKeyLen);
            offset += privateKeyLen;

            // Copy der params
            memcpy_s(encodedKey.data() + offset, derParamsLen, derParams.data(), derParamsLen);
            offset += derParamsLen;

            // Copy encoded public key
            memcpy_s(encodedKey.data() + offset, publicKeyLen, edPublicKey.data(), publicKeyLen);

        } while(false);

        return encodedKey;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::updateKeyFile(const uint32_t&   keyId,
                                              const uint8_t&    keyType,
                                              const uint64_t*   attributeBuffer,
                                              const uint64_t&   attributeBufferLen,
                                              const ByteBuffer& pinMaterial)
    {
        SgxCryptStatus       status     = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool                 result     = keyId;
        uint8_t*             encodedKey = nullptr;
        std::vector<uint8_t> encodedEccKey;

        do
        {
            result = keyId;
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            AsymmetricKey asymKey{};
            result = getAsymmetricKey(keyId, &asymKey, OperationType::Any);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            std::string filePath = asymKey.keyFile;
            if (filePath.empty())
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                break;
            }

            uint64_t encodedKeySize = 0;

            if (static_cast<uint8_t>(KeyType::Rsa) == keyType)
            {
                if (!encodeRsaKey(asymKey.key, &encodedKey, &encodedKeySize))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }
            else if (static_cast<uint8_t>(KeyType::Ec) == keyType)
            {
                encodedEccKey = getEncodedEcKey(asymKey.ecKey);
                if (encodedEccKey.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                encodedKey = encodedEccKey.data();
                encodedKeySize = encodedEccKey.size();
            }
            else if (static_cast<uint8_t>(KeyType::Ed) == keyType)
            {
                encodedEccKey = getEncodedEdKey(asymKey.edKey);
                if (encodedEccKey.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                encodedKey = encodedEccKey.data();
                encodedKeySize = encodedEccKey.size();
            }
            else
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            std::string newFileName = Utils::SgxFileUtils::generateRandomFilename();
            if (newFileName.empty())
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                break;
            }

            std::string newFilePath;

            result = Utils::TokenObjectParser::writeTokenObject(newFileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                encodedKey, encodedKeySize, asymKey.isUsedForWrapping, asymKey.pairKeyId, &newFilePath);
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                break;
            }

            Utils::SgxFileUtils::remove(filePath);

            asymKey.keyFile = newFilePath;

            if (mAsymmetricPublicKeyCache.find(keyId))
            {
                mAsymmetricPublicKeyCache.add(keyId, asymKey);
            }
            else if (mAsymmetricPrivateKeyCache.find(keyId))
            {
                mAsymmetricPrivateKeyCache.add(keyId, asymKey);
            }

        } while(false);

        if ((static_cast<uint8_t>(KeyType::Rsa) == keyType) && encodedKey)
        {
            delete encodedKey;
            encodedKey = nullptr;
        }

        return static_cast<SgxStatus>(status);
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::updateHandle(const uint32_t& keyHandle, const uint32_t& newKeyHandle)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        AsymmetricKey  asymmetricKey{};
        bool           removeTokenFile = false;

        if (!newKeyHandle)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
        }

        if (mAsymmetricPrivateKeyCache.find(keyHandle))
        {
            asymmetricKey = mAsymmetricPrivateKeyCache.get(keyHandle);

            mAsymmetricPrivateKeyCache.add(newKeyHandle, asymmetricKey);

            if (!mAsymmetricPrivateKeyCache.remove(keyHandle, removeTokenFile))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
            }
        }
        else if (mAsymmetricPublicKeyCache.find(keyHandle))
        {
            asymmetricKey = mAsymmetricPublicKeyCache.get(keyHandle);

            mAsymmetricPublicKeyCache.add(newKeyHandle, asymmetricKey);

            if (!mAsymmetricPublicKeyCache.remove(keyHandle, removeTokenFile))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
            }
        }
        else
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::generateEccKey(const uint32_t&      publicKeyId,
                                               const uint32_t&      privateKeyId,
                                               const unsigned char* curveOid,
                                               const uint32_t&      curveOidLen,
                                               const uint64_t*      attributeBufferPublic,
                                               const uint64_t&      attributeBufferPublicLen,
                                               const uint64_t*      attributeBufferPrivate,
                                               const uint64_t&      attributeBufferPrivateLen,
                                               const ByteBuffer&    pinMaterial)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);

        if (!curveOid || !curveOidLen)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
        }

        if (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
        }

        if (static_cast<SgxMaxKeyLimits>(mAsymmetricPrivateKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL);
        }

        std::vector<uint8_t> tempCurveOid(curveOid, curveOid + curveOidLen);
        const unsigned char* oidPtr = reinterpret_cast<const unsigned char*>(tempCurveOid.data());

        int curveNid = OBJ_obj2nid(d2i_ASN1_OBJECT(nullptr, &oidPtr, tempCurveOid.size()));
        switch(curveNid)
        {
            case NID_X9_62_prime256v1:
            case NID_secp384r1:
                status = generateEcKey(publicKeyId, privateKeyId,
                                       curveOid, curveOidLen,
                                       attributeBufferPublic,  attributeBufferPublicLen,
                                       attributeBufferPrivate, attributeBufferPrivateLen,
                                       pinMaterial);
                break;

            case EVP_PKEY_ED25519:
                status = generateEdKey(publicKeyId, privateKeyId,
                                       curveOid, curveOidLen,
                                       attributeBufferPublic,  attributeBufferPublicLen,
                                       attributeBufferPrivate, attributeBufferPrivateLen,
                                       pinMaterial);
                break;

            default:
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER);
                break;
        }

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::generateEcKey(const uint32_t&      publicKeyId,
                                              const uint32_t&      privateKeyId,
                                              const unsigned char* curveOid,
                                              const uint32_t&      curveOidLen,
                                              const uint64_t*      attributeBufferPublic,
                                              const uint64_t&      attributeBufferPublicLen,
                                              const uint64_t*      attributeBufferPrivate,
                                              const uint64_t&      attributeBufferPrivateLen,
                                              const ByteBuffer&    pinMaterial)
    {
        SgxCryptStatus status  = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        bool           result  = false;
        std::string    filePathPublicKey, filePathPrivateKey;

        do
        {
            result = publicKeyId && privateKeyId && curveOid && curveOidLen;

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            std::vector<uint8_t> tempCurveOid(curveOid, curveOid + curveOidLen);
            const unsigned char* ptr = reinterpret_cast<const unsigned char*>(tempCurveOid.data());

            int curveNid = OBJ_obj2nid(d2i_ASN1_OBJECT(nullptr, &ptr, tempCurveOid.size()));
            if ((NID_X9_62_prime256v1 != curveNid) && (NID_secp384r1 != curveNid))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            EC_KEY* ecKey = EC_KEY_new();
            if (!ecKey)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            EC_GROUP* ecGroup = d2i_ECPKParameters(nullptr, &curveOid, curveOidLen);
            EC_KEY_set_group(ecKey, ecGroup);
            EC_GROUP_free(ecGroup);

            if (!EC_KEY_generate_key(ecKey))
            {
                EC_KEY_free(ecKey);

                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            uint64_t pairKeyId = 0;
            if (SGX_SUCCESS != sgx_read_rand(reinterpret_cast<unsigned char*>(&pairKeyId), sizeof(pairKeyId)))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            std::vector<uint8_t> encodedKey;

            if (attributeBufferPublic || attributeBufferPrivate)
            {
                encodedKey = getEncodedEcKey(ecKey);
                if (encodedKey.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            if (attributeBufferPublic)
            {
                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBufferPublic, attributeBufferPublicLen,
                                                                    encodedKey.data(), encodedKey.size(), false, pairKeyId, &filePathPublicKey);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            if (attributeBufferPrivate)
            {
                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBufferPrivate, attributeBufferPrivateLen,
                                                                    encodedKey.data(), encodedKey.size(), false, pairKeyId, &filePathPrivateKey);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            AsymmetricKey asymKey{};

            asymKey.ecKey = ecKey;

            EC_KEY* dupEcKey = EC_KEY_dup(asymKey.ecKey);
            if (!dupEcKey)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            // Add public key into cache
            asymKey.pairKeyId = pairKeyId;
            asymKey.keyFile   = filePathPublicKey;
            mAsymmetricPublicKeyCache.add(publicKeyId, asymKey);

            // Add private key into cache
            asymKey.ecKey   = dupEcKey;
            asymKey.keyFile = filePathPrivateKey;
            mAsymmetricPrivateKeyCache.add(privateKeyId, asymKey);

            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        } while (false);

        if (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != status)
        {
            Utils::SgxFileUtils::remove(filePathPublicKey);
            Utils::SgxFileUtils::remove(filePathPrivateKey);
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    static EVP_PKEY* getDuplicateEdKey(const EVP_PKEY* edKey)
    {
        if (!edKey)
        {
            return nullptr;
        }

        EVP_PKEY* dupEdKey;

        size_t privateKeyLen = 0;

        if (1 != EVP_PKEY_get_raw_private_key(edKey, nullptr, &privateKeyLen))
        {
            return nullptr;
        }

        if (ed25519KeyLength != privateKeyLen)
        {
            return nullptr;
        }

        std::vector<uint8_t> edPrivateKey(privateKeyLen);
        if (1 != EVP_PKEY_get_raw_private_key(edKey, edPrivateKey.data(), &privateKeyLen))
        {
            return nullptr;
        }

        dupEdKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, edPrivateKey.data(), privateKeyLen);
        if (!dupEdKey)
        {
            return nullptr;
        }

        return dupEdKey;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::generateEdKey(const uint32_t&      publicKeyId,
                                              const uint32_t&      privateKeyId,
                                              const unsigned char* curveOid,
                                              const uint32_t&      curveOidLen,
                                              const uint64_t*      attributeBufferPublic,
                                              const uint64_t&      attributeBufferPublicLen,
                                              const uint64_t*      attributeBufferPrivate,
                                              const uint64_t&      attributeBufferPrivateLen,
                                              const ByteBuffer&    pinMaterial)
    {
        SgxCryptStatus status  = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        bool           result  = false;
        std::string    filePathPublicKey, filePathPrivateKey;

        do
        {
            result = publicKeyId && privateKeyId && curveOid && curveOidLen;

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            EVP_PKEY* edKey = nullptr;

            int curveNid = OBJ_obj2nid(d2i_ASN1_OBJECT(nullptr, &curveOid, curveOidLen));
            if (EVP_PKEY_ED25519 != curveNid)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(curveNid, nullptr);
            if (!ctx)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            result = (EVP_PKEY_keygen_init(ctx) == 1) && (EVP_PKEY_keygen(ctx, &edKey) == 1);

            EVP_PKEY_CTX_free(ctx);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            uint64_t pairKeyId = 0;
            if (SGX_SUCCESS != sgx_read_rand(reinterpret_cast<unsigned char*>(&pairKeyId), sizeof(pairKeyId)))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            std::vector<uint8_t> encodedKey;

            if (attributeBufferPublic || attributeBufferPrivate)
            {
                encodedKey = getEncodedEdKey(edKey);
                if (encodedKey.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            if (attributeBufferPublic)
            {
                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBufferPublic, attributeBufferPublicLen,
                                                                    encodedKey.data(), encodedKey.size(), false, pairKeyId, &filePathPublicKey);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            if (attributeBufferPrivate)
            {
                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBufferPrivate, attributeBufferPrivateLen,
                                                                    encodedKey.data(), encodedKey.size(), false, pairKeyId, &filePathPrivateKey);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            AsymmetricKey asymKey{};

            asymKey.edKey = edKey;

            EVP_PKEY* dupEdKey = getDuplicateEdKey(asymKey.edKey);
            if (!dupEdKey)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            // Add public key into cache
            asymKey.pairKeyId = pairKeyId;
            asymKey.keyFile   = filePathPublicKey;
            mAsymmetricPublicKeyCache.add(publicKeyId, asymKey);

            // Add private key into cache
            asymKey.edKey   = dupEdKey;
            asymKey.keyFile = filePathPrivateKey;
            mAsymmetricPrivateKeyCache.add(privateKeyId, asymKey);

            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        } while (false);

        if (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != status)
        {
            Utils::SgxFileUtils::remove(filePathPublicKey);
            Utils::SgxFileUtils::remove(filePathPrivateKey);
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::getEcParams(const uint32_t& keyId,
                                            uint8_t*        destBuffer,
                                            const uint32_t& destBufferLen,
                                            uint32_t*       destBufferWritten)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;

        do
        {
            if (!destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            AsymmetricKey asymKey;
            if (!getAsymmetricKey(keyId, &asymKey, OperationType::Any))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            if (asymKey.ecKey)
            {
                const EC_GROUP* ecGroup = EC_KEY_get0_group(asymKey.ecKey);
                if (!ecGroup)
                {
                    break;
                }

                *destBufferWritten = i2d_ECPKParameters(ecGroup, nullptr);

                if (!destBuffer)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
                    break;
                }

                if (destBufferLen < *destBufferWritten)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                    break;
                }

                unsigned char *derPtr = destBuffer;
                if (!i2d_ECPKParameters(ecGroup, &derPtr))
                {
                    *destBufferWritten = 0;
                    break;
                }
            }
            else if (asymKey.edKey)
            {
                int nid = EVP_PKEY_id(asymKey.edKey);

                *destBufferWritten = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), nullptr);

                if (!destBuffer)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
                    break;
                }

                if (destBufferLen < *destBufferWritten)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                    break;
                }

                unsigned char *derPtr = destBuffer;
                if (!i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &derPtr))
                {
                    *destBufferWritten = 0;
                    break;
                }
            }
            else
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::setWrappingStatus(const uint32_t& keyId)
    {
        if (!mAsymmetricPublicKeyCache.find(keyId))
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
        }

        AsymmetricKey asymmetricKeyPub = mAsymmetricPublicKeyCache.get(keyId);

        if (asymmetricKeyPub.isUsedForWrapping)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        }

        if (!asymmetricKeyPub.keyFile.empty())
        {
            if (!Utils::TokenObjectParser::setWrappingStatus(asymmetricKeyPub.keyFile, asymmetricKeyPub.pairKeyId))
            {
                return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            }
        }

        asymmetricKeyPub.isUsedForWrapping = true;

        mAsymmetricPublicKeyCache.add(keyId, asymmetricKeyPub);

        if (asymmetricKeyPub.pairKeyId)
        {
            uint32_t privateKeyId = mAsymmetricPrivateKeyCache.findKeyIdForPairKeyId(asymmetricKeyPub.pairKeyId);

            AsymmetricKey asymmetricKeyPriv = mAsymmetricPrivateKeyCache.get(privateKeyId);

            if (asymmetricKeyPriv.isUsedForWrapping)
            {
                return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
            }

            if (!asymmetricKeyPriv.keyFile.empty())
            {
                if (!Utils::TokenObjectParser::setWrappingStatus(asymmetricKeyPriv.keyFile, asymmetricKeyPriv.pairKeyId))
                {
                    return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                }
            }

            asymmetricKeyPriv.isUsedForWrapping = true;

            mAsymmetricPrivateKeyCache.add(privateKeyId, asymmetricKeyPriv);
        }

        return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::checkWrappingStatus(const uint32_t& keyId, const OperationType& type)
    {
        AsymmetricKey asymmetricKey {};
        if (OperationType::Public == type)
        {
            asymmetricKey = mAsymmetricPublicKeyCache.get(keyId);
        }
        else if (OperationType::Private == type)
        {
            asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);
        }
        else
        {
            return false;
        }

        return asymmetricKey.isUsedForWrapping;
    }

} //CryptoSgx