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
                                const BIGNUM *bn_p = nullptr;
                                const BIGNUM *bn_q = nullptr;
                                RSA_get0_factors(asymKey.key, &bn_p, &bn_q);

                                if (bn_p && bn_q)
                                {
                                    return true;
                                }
#endif
                                return false;
                           };

    //---------------------------------------------------------------------------------------------
    auto getEncodedKey = [](const AsymmetricKey& asymKey, uint8_t** encodedKey, const bool& onlyPubicKeyPresent) -> int
                           {
                              int bytesWritten = 0;
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
    SgxStatus AsymmetricCrypto::removeAsymmetricKey(const uint32_t& keyId)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        AsymmetricKey  asymmetricKey{};

        if (mAsymmetricPrivateKeyCache.find(keyId)) // Check in private key cache
        {
            asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);

            if (!asymmetricKey.pairKeyId)
            {
                RSA_free(asymmetricKey.key);
            }
            else
            {
                if (mAsymmetricPublicKeyCache.find(asymmetricKey.pairKeyId))
                {
                    AsymmetricKey asymmetricKeyPb = mAsymmetricPublicKeyCache.get(asymmetricKey.pairKeyId);
                    asymmetricKeyPb.pairKeyId     = 0;
                    mAsymmetricPublicKeyCache.add(asymmetricKey.pairKeyId, asymmetricKeyPb);
                }
            }

            if (!mAsymmetricPrivateKeyCache.remove(keyId))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
            }
        }
        else if (mAsymmetricPublicKeyCache.find(keyId)) // Check in public key cache
        {
            asymmetricKey = mAsymmetricPublicKeyCache.get(keyId);

            if (!asymmetricKey.pairKeyId)
            {
                RSA_free(asymmetricKey.key);
            }
            else
            {
                if (mAsymmetricPrivateKeyCache.find(asymmetricKey.pairKeyId))
                {
                    AsymmetricKey asymmetricKeyPr = mAsymmetricPrivateKeyCache.get(asymmetricKey.pairKeyId);
                    asymmetricKeyPr.pairKeyId     = 0;
                    mAsymmetricPrivateKeyCache.add(asymmetricKey.pairKeyId, asymmetricKeyPr);
                }
            }

            if (!mAsymmetricPublicKeyCache.remove(keyId))
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
                result         = asymmetricKey->key;
            }
        }
        else if (OperationType::Private == opType)
        {
            if (mAsymmetricPrivateKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);
                result         = asymmetricKey->key;
            }
        }
        else if (OperationType::Any == opType)
        {
            if (mAsymmetricPublicKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPublicKeyCache.get(keyId);
                result         = asymmetricKey->key;
            }
            else if (mAsymmetricPrivateKeyCache.find(keyId))
            {
                *asymmetricKey = mAsymmetricPrivateKeyCache.get(keyId);
                result         = asymmetricKey->key;
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
                                  RsaPadding::rsaPkcs1Oaep == rsaPadding));

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
                                  RsaPadding::rsaPkcs1Oaep == rsaPadding));

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
    SgxStatus AsymmetricCrypto::generateAsymmetricKey(const uint32_t&           publicKeyId,
                                                      const uint32_t&           privateKeyId,
                                                      const AsymmetricKeySize&  modulusLength)
    {
        SgxCryptStatus  status  = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        BIGNUM*         bigNum  = nullptr;
        RSA*            rsaKey  = nullptr;
        bool            result  = false;

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

                asymKey.key                 = rsaKey;
                asymKey.pairKeyId           = privateKeyId;
                asymKey.isUsedForWrapping   = false;

                // add public key to the cache
                mAsymmetricPublicKeyCache.add(publicKeyId, asymKey);

                asymKey.pairKeyId = publicKeyId;
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

        if (rsaKey && !result)
        {
            RSA_free(rsaKey);
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
                                                const uint32_t&   exponentBufferLen)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
        RSA*            rsaKey = nullptr;
        bool            result = false;

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
            BIGNUM *bn_p = nullptr;
            BIGNUM *bn_q = nullptr;

            bn_d = BN_secure_new();
            bn_n = BN_bin2bn(modulusBuffer, modulusBufferLen, nullptr);
            bn_e = BN_bin2bn(exponentBuffer, exponentBufferLen, nullptr);

            RSA_set0_key(rsaKey, bn_n, bn_e, bn_d);
            RSA_set0_factors(rsaKey, bn_p, bn_q);

            if (!BN_is_odd(bn_e) || BN_is_one(bn_e))
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }
#endif
            AsymmetricKey asymKey;
            asymKey.key                 = rsaKey;
            asymKey.pairKeyId           = 0;
            asymKey.isUsedForWrapping   = false;

            mAsymmetricPublicKeyCache.add(keyId, asymKey);
        } while (false);

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
    SgxStatus AsymmetricCrypto::exportAsymmetricKeyPbind(const uint32_t&  keyId,
                                                         uint8_t*         destBuffer,
                                                         const uint32_t&  destBufferLen,
                                                         uint32_t*        destBufferWritten)
    {
        bool            result = false;
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        AsymmetricKey   asymKey{};

        do
        {
            if (!keyId)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            if (!destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            result = getAsymmetricKey(keyId,
                                      &asymKey,
                                      OperationType::Public);

            if (!result || !asymKey.key)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            result = exportPlatformBoundKey(asymKey,
                                            destBuffer,
                                            destBufferLen,
                                            destBufferWritten,
                                            &status);
        } while (false);

        if (result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::exportPlatformBoundKey(const AsymmetricKey&  asymKey,
                                                  uint8_t*              destBuffer,
                                                  const uint32_t&       destBufferLen,
                                                  uint32_t*             destBufferWritten,
                                                  SgxCryptStatus*       status)
    {
        bool        result                  = false;
        uint8_t*    encodedKey              = nullptr;
        bool        onlyPublicKeyPresent    = false;
        int         encodedKeySize          = 0;
        uint32_t    pbindInputDataSize      = 0;
        uint32_t    sealDataSize            = 0;
        int         bytesWritten            = 0;

        if (!status)
        {
            return false;
        }

        do
        {
            if (!asymKey.key)
            {
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            if (!destBufferWritten)
            {
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }


            // All the RSA handles stored in table has public component.
            // Check whether it also have the private key component & encode accordingly.
            if (hasPrivateKey(asymKey))
            {
                // Both public & private keys can be encoded
                encodedKeySize = i2d_RSAPrivateKey(asymKey.key, nullptr);
            }
            else
            {
                // Only public key can be encoded
                onlyPublicKeyPresent = true;
                encodedKeySize = i2d_RSAPublicKey(asymKey.key, nullptr);
            }

            if (encodedKeySize < 0)
            {
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                break;
            }

            pbindInputDataSize = encodedKeySize + sizeof(asymKey.isUsedForWrapping);
            sealDataSize       = sgx_calc_sealed_data_size(0, pbindInputDataSize);

            if (UINT32_MAX == sealDataSize)
            {
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
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
                    result = false;
                    *status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                    break;
                }

                encodedKey = new (std::nothrow) uint8_t[encodedKeySize];
                if (!encodedKey)
                {
                    result = false;
                    *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                    break;
                }

                bytesWritten = getEncodedKey(asymKey, &encodedKey, onlyPublicKeyPresent);

                if (bytesWritten < 0)
                {
                    result = false;
                    *status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }
                // Reset the pointer to initial value as the i2d call incremented it.
                encodedKey -= (bytesWritten);

                std::unique_ptr<uint8_t[]> dataToBePlatformBound(new (std::nothrow) uint8_t[pbindInputDataSize]);
                if (!dataToBePlatformBound.get())
                {
                    result = false;
                    *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                    break;
                }

                memcpy_s(dataToBePlatformBound.get(),
                         pbindInputDataSize,
                         encodedKey,
                         bytesWritten);
                memcpy_s(dataToBePlatformBound.get() + bytesWritten,
                         pbindInputDataSize - bytesWritten,
                         &asymKey.isUsedForWrapping,
                         sizeof(asymKey.isUsedForWrapping));

                // Seal the encoded RSA Key with SGX
                const sgx_status_t sgxStatus = sgx_seal_data(0, nullptr,
                                                             pbindInputDataSize,
                                                             dataToBePlatformBound.get(),
                                                             sealDataSize,
                                                             reinterpret_cast<sgx_sealed_data_t*>(destBuffer));

                result = (sgx_status_t::SGX_SUCCESS == sgxStatus);

                if (!result)
                {
                    *status = SgxCryptStatus::SGX_CRYPT_STATUS_SEALED_DATA_FAILED;
                    *destBufferWritten = 0;
                    break;
                }
            }
        } while (false);

        if (encodedKey)
        {
            delete[] encodedKey;
            encodedKey = nullptr;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus AsymmetricCrypto::importAsymmetricKeyPbind(uint32_t*          publicKeyId,
                                                         uint32_t*          privateKeyId,
                                                         const uint8_t*     sourceBuffer,
                                                         const uint32_t&    sourceBufferLen)
    {
        bool            result = false;
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;

        do
        {
            if (!publicKeyId)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mAsymmetricPublicKeyCache.count()) >= SgxMaxKeyLimits::asymmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            /* Restricting sourceBuffer(platform bound data) whose length is more than the
               maximum allowed RSA platform bind length.*/
            if (sourceBufferLen > rsaMaxPBindDataLength)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            AsymmetricKey asymKey{};

            result = importPlatformBoundKey(&asymKey, sourceBuffer, sourceBufferLen, &status);

            if (!result)
            {
                break;
            }

            const BIGNUM *bn_n = nullptr;
            const BIGNUM *bn_e = nullptr;
            const BIGNUM *bn_d = nullptr;
            const BIGNUM *bn_p = nullptr;
            const BIGNUM *bn_q = nullptr;

            RSA_get0_factors(asymKey.key, &bn_p, &bn_q);
            RSA_get0_key(asymKey.key, &bn_n, &bn_e, &bn_d);

            if (bn_d && bn_p && bn_q)
            {
                asymKey.pairKeyId = *publicKeyId;
                mAsymmetricPrivateKeyCache.add(*privateKeyId, asymKey);
            }
            else
            {
                *privateKeyId = 0;
            }

            asymKey.pairKeyId = *privateKeyId;
            mAsymmetricPublicKeyCache.add(*publicKeyId, asymKey);

        } while (false);

        if (result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricCrypto::markAsWrappingKey(const uint32_t& keyId)
    {
        const bool result = mAsymmetricPublicKeyCache.find(keyId);

        if (result)
        {
            AsymmetricKey asymKey     = mAsymmetricPublicKeyCache.get(keyId);
            asymKey.isUsedForWrapping = true;
            mAsymmetricPublicKeyCache.add(keyId, asymKey);
        }
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::checkWrappingStatus(const uint32_t& keyId)
    {
        bool result = mAsymmetricPublicKeyCache.find(keyId);

        if (result)
        {
            AsymmetricKey asymKey = mAsymmetricPublicKeyCache.get(keyId);
            result                = asymKey.isUsedForWrapping;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricCrypto::importPlatformBoundKey(AsymmetricKey*     asymKey,
                                                  const uint8_t*     sourceBuffer,
                                                  const uint32_t&    sourceBufferLen,
                                                  SgxCryptStatus*    status)
    {
        bool        result              = true;
        bool        isUsedForWrapping   = false;
        uint8_t*    encodedKey          = nullptr;
        uint32_t    encodedKeySize      = 0;
        uint32_t    decryptedDataSize   = 0;

        if (!status || !asymKey)
        {
            return false;
        }

        do
        {
            *status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
            if (!sourceBuffer || !sourceBufferLen)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            decryptedDataSize = sgx_get_encrypt_txt_len(reinterpret_cast<const sgx_sealed_data_t*>(sourceBuffer));

            /* For sourceBuffer which is not a platform bound data, sgx_get_encrypt_txt_len() does not return
               UINT32_MAX as per the api documentation. Hence, a bound is placed on the return value of
               sgx_get_encrypt_txt_len() based on maximum supported RSA public+private key.*/
            if (UINT32_MAX == decryptedDataSize || encodedKeySize > rsaMaxUnsealDataLength)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            std::unique_ptr<uint8_t[]> decryptedData(new (std::nothrow) uint8_t[decryptedDataSize], std::default_delete<uint8_t[]>());

            if (!decryptedData.get())
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            const sgx_status_t sgxStatus = sgx_unseal_data(reinterpret_cast<const sgx_sealed_data_t*>(sourceBuffer),
                                                           nullptr,
                                                           nullptr,
                                                           decryptedData.get(),
                                                           &decryptedDataSize);
            if (sgx_status_t::SGX_SUCCESS != sgxStatus)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_SEALED_DATA_FAILED;
                break;
            }

            encodedKeySize = decryptedDataSize - sizeof(asymKey->isUsedForWrapping);
            encodedKey     = new (std::nothrow) uint8_t[encodedKeySize];

            if (!encodedKey)
            {
                result = false;
                *status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            memcpy_s(encodedKey, encodedKeySize, decryptedData.get(), encodedKeySize);

            isUsedForWrapping = static_cast<bool>(*(decryptedData.get() + encodedKeySize));

            // Load the RSA struct with the encoded key pair
            if (nullptr == d2i_RSAPrivateKey(&asymKey->key,
                                             const_cast<const unsigned char**>(&encodedKey),
                                             encodedKeySize))
            {
                // Check whether it has at least the public key
                if (nullptr == d2i_RSAPublicKey(&asymKey->key,
                                                const_cast<const unsigned char**>(&encodedKey),
                                                encodedKeySize))
                {
                    result = false;
                    *status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_WRAPPED_KEY;
                    break;
                }
            }

            asymKey->isUsedForWrapping = isUsedForWrapping;
            // Reset the pointer to initial value as the d2i call incremented it.
            encodedKey -= encodedKeySize;
        } while (false);

        if (encodedKey)
        {
            memset_s(encodedKey, encodedKeySize, 0, encodedKeySize);
            delete[] encodedKey;
            encodedKey = nullptr;
        }

        if (asymKey->key && (SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS != *status))
        {
            result = false;
            RSA_free(asymKey->key);
        }

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

            if (!asymKey.pairKeyId || !mAsymmetricPrivateKeyCache.find(asymKey.pairKeyId))
            {
                return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
            }

            status = exportPublicKey(keyId, NULL, 0, &cbModulus, &cbPublicExp);
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
} //CryptoSgx
