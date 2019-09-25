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

#include "SymmetricCrypto.h"
#include "CryptoEnclaveDefs.h"

#include <limits>
#include <type_traits>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <mbusafecrt.h>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    void SymmetricCrypto::addEVPCtxState(const uint32_t&        keyId,
                                         EVPContextHandle&      evpContext,
                                         const BlockCipherMode& cipherMode,
                                         const uint32_t&        tagBits,
                                         const uint32_t&        padding)
    {
        EVPCtxState evpCtxState;
        evpCtxState.evpCtx                  = &evpContext;
        evpCtxState.cryptParams.cipherMode  = cipherMode;
        evpCtxState.cryptParams.tagBits     = tagBits;
        evpCtxState.cryptParams.padding     = padding;

        mEVPCtxStateCache.add(keyId, evpCtxState);
    }

    //---------------------------------------------------------------------------------------------
    void SymmetricCrypto::addIppCtxState(const uint32_t&         keyId,
                                         IppContextHandle&       ippContext,
                                         const BlockCipherMode&  cipherMode,
                                         const uint8_t*          iv,
                                         const uint32_t&         ivSize,
                                         const int&              counterBits)
    {
        IppCtxState ippCtxState;
        ippCtxState.ippCtx                  = &ippContext;
        ippCtxState.cryptParams.cipherMode  = cipherMode;
        ippCtxState.cryptParams.counterBits = counterBits;

        if (iv && ivSize)
        {
            ippCtxState.cryptParams.iv.allocate(ivSize);
            if (!ippCtxState.cryptParams.iv.isValid())
            {
                return;
            }

            ippCtxState.cryptParams.iv.fromData(iv, ivSize);
        }

        mIppCtxStateCache.add(keyId, ippCtxState);
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricCrypto::getEVPCtxState(const uint32_t&    keyId,
                                         EVPCtxState*       evpContext)
    {
        const bool result = mEVPCtxStateCache.find(keyId);
        if (result && evpContext)
        {
            *evpContext = mEVPCtxStateCache.get(keyId);
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricCrypto::getIppCtxState(const uint32_t&    keyId,
                                         IppCtxState*       ippCtxContext)
    {
        const bool result = mIppCtxStateCache.find(keyId);
        if (result && ippCtxContext)
        {
            *ippCtxContext = mIppCtxStateCache.get(keyId);
        }
        return result;
    }

    //---------------------------------------------------------------------------------------------
    auto isSupportedAesMode = [](const BlockCipherMode& cipherMode) -> bool
                                {
                                    return (BlockCipherMode::ctr == cipherMode) ||
                                           (BlockCipherMode::gcm == cipherMode) ||
                                           (BlockCipherMode::cbc == cipherMode);
                                };

    //---------------------------------------------------------------------------------------------
    auto isSupportedIvSize = [](const uint32_t& ivSize) -> bool
                               {
                                   return (supportedIvSize == ivSize);
                               };

    //---------------------------------------------------------------------------------------------
    auto isSupportedCounterBitsSize = [](const int& counterBits) -> bool
                                        {
                                            return (counterBits >= minCounterBitsSupported) &&
                                                   (counterBits <= maxCounterBitsSupported);
                                        };

    //---------------------------------------------------------------------------------------------
    auto isSupportedTagSize = [](const uint32_t& tagSize) -> bool
                                {
                                    return (tagSize >= minTagLengthSupported) &&
                                           (tagSize <= maxTagLengthSupported);
                                };

    //---------------------------------------------------------------------------------------------
    void freeEvpContext(EVP_CIPHER_CTX* evpContext)
    {
        EVP_CIPHER_CTX_free(evpContext);
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::encryptInitEvp(const uint32_t&       keyId,
                                                   const CryptParams&    cryptParams)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool           result = false;
        EVPEncrypt     evpEncrypt;
        cipherModeKeyLengthPair cipherModeKeyLengthPair = std::make_pair(cryptParams.cipherMode,
                                                                         static_cast<SymmetricKeySize>(cryptParams.key.size()));

        do
        {
            if (!evpCipherFn.count(cipherModeKeyLengthPair))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            result = evpEncrypt.init(evpCipherFn[cipherModeKeyLengthPair](), cryptParams);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            addEVPCtxState(keyId,
                           evpEncrypt.getContext(),
                           cryptParams.cipherMode,
                           cryptParams.tagBits,
                           cryptParams.padding);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::encryptInitIpp(const uint32_t&       keyId,
                                                   const CryptParams&    cryptParams)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result = false;
        IppEncrypt      ippEncrypt;

        do
        {
            result = ippEncrypt.encryptInit(cryptParams);
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            addIppCtxState(keyId,
                           ippEncrypt.getIppContext(),
                           cryptParams.cipherMode,
                           cryptParams.iv.get(),
                           cryptParams.iv.size(),
                           cryptParams.counterBits);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::encryptInit(const uint32_t&         keyId,
                                           const BlockCipherMode&  cipherMode,
                                           const uint8_t*          iv,
                                           const uint32_t&         ivSize,
                                           const uint8_t*          aad,
                                           const uint32_t&         aadSize,
                                           const uint32_t&         padding,
                                           const uint32_t&         tagBits,
                                           const int&              counterBits)
    {
        SgxCryptStatus  status      = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result      = false;
        SymmetricKey    symKey{};
        CryptParams     cryptParams{};

        do
        {
            result = isSupportedAesMode(cipherMode);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BLOCK_CIPHER_MODE;
                break;
            }

            if (BlockCipherMode::ctr == cipherMode)
            {
                result = iv                             &&
                         !padding                       &&
                         isSupportedIvSize(ivSize)      &&
                         isSupportedCounterBitsSize(counterBits);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }
            }
            else if (BlockCipherMode::gcm == cipherMode)
            {
                result = !padding && isSupportedTagSize(tagBits/8);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }
            }
            else if (BlockCipherMode::cbc == cipherMode)
            {
                result = iv && isSupportedIvSize(ivSize);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }
            }

            result = getSymmetricKey(keyId, &symKey);
            if (result)
            {
                fillCryptInitParams(&cryptParams,
                                    cipherMode,
                                    symKey.key,
                                    iv,
                                    ivSize,
                                    aad,
                                    aadSize,
                                    tagBits,
                                    counterBits,
                                    padding);

                if (BlockCipherMode::ctr == cipherMode)
                {
                    status = encryptInitIpp(keyId, cryptParams);
                }
                else
                {
                    status = encryptInitEvp(keyId, cryptParams);
                }
            }
            else
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
            }

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::encryptUpdateEvp(const uint32_t&     keyId,
                                                     const uint8_t*      sourceBuffer,
                                                     const uint32_t&     sourceBufferLen,
                                                     uint8_t*            destBuffer,
                                                     const uint32_t&     destBufferLen,
                                                     uint32_t*           destBufferWritten,
                                                     bool                doFullEncryptWithoutFinal)
    {
        SgxCryptStatus  status          = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result          = false;
        int             bytesEncrypted  = 0;
        EVPEncrypt      evpEncrypt;
        EVPCtxState     evpCtxState;

        do
        {
            result = getEVPCtxState(keyId, &evpCtxState);
            if (!result || !destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!destBuffer) // To return bytes needed for dest Buffer.
            {
                if (BlockCipherMode::cbc             == evpCtxState.cryptParams.cipherMode &&
                    BlockCipherPadding::BlockPadding == static_cast<BlockCipherPadding>(evpCtxState.cryptParams.padding))
                {
                    uint8_t tailBlockDataSize = sourceBufferLen % aesBlockSize;
                    *destBufferWritten = sourceBufferLen - tailBlockDataSize;
                }
                else //For GCM and CBC(no padding)
                {
                    if (BlockCipherMode::cbc == evpCtxState.cryptParams.cipherMode &&
                        sourceBufferLen     != aesBlockSize)
                    {
                        result = false;
                        status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                        *destBufferWritten = 0;
                        break;
                    }
                    *destBufferWritten = sourceBufferLen;
                }
                result = true;
                break;
            }

            // If padding is not enabled in cbc mode, reject all inputs that are not of aesBlockSize.
            if (BlockCipherMode::cbc           == evpCtxState.cryptParams.cipherMode   &&
                (0                             != (sourceBufferLen % aesBlockSize))    &&
                (BlockCipherPadding::NoPadding == static_cast<BlockCipherPadding>(evpCtxState.cryptParams.padding)))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            result = evpEncrypt.encryptUpdate(&evpCtxState,
                                              destBuffer,
                                              &bytesEncrypted,
                                              sourceBuffer,
                                              sourceBufferLen);
            if (!result)
            {
                status              = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                *destBufferWritten  = 0;
                break;
            }

            *destBufferWritten = bytesEncrypted;
            if (doFullEncryptWithoutFinal)
            {
                int offset      = bytesEncrypted;
                bytesEncrypted  = 0;

                result = evpEncrypt.encryptFinal(&evpCtxState, destBuffer + offset, &bytesEncrypted);
                if (!result)
                {
                    status              = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                    *destBufferWritten  = 0;
                    break;
                }
                *destBufferWritten += bytesEncrypted;

                freeEvpContext(evpCtxState.evpCtx);
                mEVPCtxStateCache.remove(keyId);
            }
            else
            {
                mEVPCtxStateCache.add(keyId, evpCtxState);
            }
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::encryptUpdateIpp(const uint32_t&     keyId,
                                                     const uint8_t*      sourceBuffer,
                                                     const uint32_t&     sourceBufferLen,
                                                     uint8_t*            destBuffer,
                                                     const uint32_t&     destBufferLen,
                                                     uint32_t*           destBufferWritten,
                                                     IppCtxState*        ippCtxState,
                                                     bool                doFullEncryptWithoutFinal)
    {
        SgxCryptStatus  status          = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result          = false;
        int             bytesEncrypted  = 0;
        IppEncrypt      ippEncrypt;

        do
        {
            if (!destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!destBuffer) // To return bytes needed for dest Buffer.
            {
                *destBufferWritten  = sourceBufferLen;
                result              = true;
                break;
            }

            result = ippEncrypt.encryptUpdate(ippCtxState, destBuffer, &bytesEncrypted, sourceBuffer, sourceBufferLen);
            if (!result)
            {
                status              = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                *destBufferWritten  = 0;
                break;
            }
            *destBufferWritten = bytesEncrypted;

            if (doFullEncryptWithoutFinal)
            {
                ippEncrypt.encryptFinal(ippCtxState);

                // Remove from cache as the encrypt operation is complete
                mIppCtxStateCache.remove(keyId);
            }
            else
            {
                mIppCtxStateCache.add(keyId, *ippCtxState);
            }

        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::encryptUpdate(const uint32_t&     keyId,
                                             const uint8_t*      sourceBuffer,
                                             const uint32_t&     sourceBufferLen,
                                             uint8_t*            destBuffer,
                                             const uint32_t&     destBufferLen,
                                             uint32_t*           destBufferWritten,
                                             bool                doFullEncryptWithoutFinal)
    {
        SgxCryptStatus  status      = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result      = false;
        bool            ctrMode     = false;
        IppCtxState     ippCtxState;

        do
        {
            result = getIppCtxState(keyId, &ippCtxState);
            if (result)
            {
                ctrMode = true;
            }

            if (ctrMode)
            {
                status = encryptUpdateIpp(keyId,
                                          sourceBuffer,
                                          sourceBufferLen,
                                          destBuffer,
                                          destBufferLen,
                                          destBufferWritten,
                                          &ippCtxState,
                                          doFullEncryptWithoutFinal);
            }
            else
            {
                status = encryptUpdateEvp(keyId,
                                          sourceBuffer,
                                          sourceBufferLen,
                                          destBuffer,
                                          destBufferLen,
                                          destBufferWritten,
                                          doFullEncryptWithoutFinal);
            }

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::encryptFinalIpp(const uint32_t& keyId,
                                                    uint8_t*        destBuffer,
                                                    uint32_t*       destBufferWritten,
                                                    IppCtxState*    ippCtxState)
    {
        SgxCryptStatus  status  = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        IppEncrypt      ippEncrypt;

        do
        {
            if (!destBuffer)
            {
                *destBufferWritten = 0;
                break;
            }

            ippEncrypt.encryptFinal(ippCtxState);

            mIppCtxStateCache.remove(keyId);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::encryptFinalEvp(const uint32_t& keyId,
                                                    uint8_t*        destBuffer,
                                                    uint32_t*       destBufferWritten)
    {
        SgxCryptStatus status           = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool           result           = false;
        int            bytesEncrypted   = 0;
        EVPEncrypt     evpEncrypt;
        EVPCtxState    evpCtxState;

        do
        {
            result = getEVPCtxState(keyId, &evpCtxState);
            if (!result || !destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!destBuffer)
            {
                if (BlockCipherMode::gcm == evpCtxState.cryptParams.cipherMode &&
                    evpCtxState.cryptParams.tagBits)
                {
                    *destBufferWritten = evpCtxState.cryptParams.tagBits / bitsPerByte;
                    break;
                }
            }

            result = evpEncrypt.encryptFinal(&evpCtxState, destBuffer, &bytesEncrypted);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                bytesEncrypted = 0;
                break;
            }

            *destBufferWritten = bytesEncrypted;

            freeEvpContext(evpCtxState.evpCtx);
            mEVPCtxStateCache.remove(keyId);

        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::encryptFinal(const uint32_t&    keyId,
                                            uint8_t*           destBuffer,
                                            uint32_t*          destBufferWritten)
    {
        SgxCryptStatus status  = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool           result  = false;
        bool           ctrMode = false;
        IppCtxState    ippCtxState;

        do
        {
            result = getIppCtxState(keyId, &ippCtxState);
            if (result)
            {
                ctrMode = true;
            }

            if (ctrMode)
            {
                status = encryptFinalIpp(keyId,
                                         destBuffer,
                                         destBufferWritten,
                                         &ippCtxState);
            }
            else
            {
                status = encryptFinalEvp(keyId,
                                         destBuffer,
                                         destBufferWritten);
            }

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::updateKeyFile(const uint32_t&   keyId,
                                             const uint64_t*   attributeBuffer,
                                             const uint64_t&   attributeBufferLen,
                                             const ByteBuffer& pinMaterial)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result = keyId;

        do
        {
            result = keyId;
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            SymmetricKey symKey{};
            result = getSymmetricKey(keyId, &symKey);

            if (!result || !symKey.key.get())
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
                break;
            }

            std::string filePath = symKey.keyFile;
            if (filePath.empty())
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
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
                                                                symKey.key.get(), symKey.key.size(), symKey.isUsedForWrapping, 0, &newFilePath);
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                break;
            }

            Utils::SgxFileUtils::remove(filePath);

            symKey.keyFile = newFilePath;

            mSymmetricKeyCache.add(keyId, symKey);

        } while(false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::generateSymmetricKey(const uint32_t&         keyId,
                                                    const SymmetricKeySize& keyLength,
                                                    const uint64_t*         attributeBuffer,
                                                    const uint64_t&         attributeBufferLen,
                                                    const ByteBuffer&       pinMaterial)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result = keyId;

        do
        {
            result = keyId;
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mSymmetricKeyCache.count()) >= SgxMaxKeyLimits::symmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            SymmetricKey symKey{};

            result = allocateSymmetricKey(&symKey, keyLength);
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            result = populateSymmetricKey(&symKey);
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            std::string filePath;

            // If attributeBuffer != nullptr, it's a request to create a token object.
            // Hence save the key along with attribute buffer into disk.
            if (attributeBuffer)
            {
                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                    symKey.key.get(), symKey.key.size(), false, 0, &filePath);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                symKey.keyFile = filePath;
            }

            //Store in internal cache
            mSymmetricKeyCache.add(keyId, symKey);

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::addSymmetricKey(const uint32_t&         keyId,
                                               const std::string&      tokenObjectFilePath,
                                               const uint8_t*          keyBuffer,
                                               const SymmetricKeySize& keyBufferLen,
                                               const bool&             usedForWrapping)
    {
        SgxStatus status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);

        do
        {
            if (!keyBuffer ||
                !((SymmetricKeySize::keyLength128) == keyBufferLen ||
                  (SymmetricKeySize::keyLength192) == keyBufferLen ||
                  (SymmetricKeySize::keyLength256) == keyBufferLen))
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
                break;
            }

            SymmetricKey symKey{};

            bool result = allocateSymmetricKey(&symKey, keyBufferLen);
            if (!result)
            {
                status = static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY);
                break;
            }

            size_t keySize = static_cast<const uint32_t>(keyBufferLen);
            memcpy_s(symKey.key.get(), keySize, keyBuffer, keySize);

            symKey.keyFile = tokenObjectFilePath;
            symKey.isUsedForWrapping = usedForWrapping;

            status = addSymmetricKey(keyId, symKey);
            if (static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS) != status)
            {
                break;
            }
        } while(false);

        return status;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::addSymmetricKey(const uint32_t&     keyId,
                                               const SymmetricKey& symKey)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result = keyId;

        do
        {
            result = keyId;

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (static_cast<SgxMaxKeyLimits>(mSymmetricKeyCache.count()) >= SgxMaxKeyLimits::symmetric)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            //Store in internal cache
            mSymmetricKeyCache.add(keyId, symKey);

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricCrypto::allocateSymmetricKey(SymmetricKey*           symKeyStruct,
                                               const SymmetricKeySize& keyLength)
    {
        if (!symKeyStruct)
        {
            return false;
        }

        symKeyStruct->key.allocate(static_cast<size_t>(keyLength));
        if (!symKeyStruct->key.isValid())
        {
            return false;
        }

        return (keyLength == static_cast<SymmetricKeySize>(symKeyStruct->key.size()));
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricCrypto::populateSymmetricKey(SymmetricKey* symKey)
    {
        if (!symKey)
        {
            return false;
        }

        const sgx_status_t keyPopulated = sgx_read_rand(symKey->key.get(), symKey->key.size());
        return (sgx_status_t::SGX_SUCCESS == keyPopulated);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::removeSymmetricKey(const uint32_t& keyId)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        if (!mSymmetricKeyCache.remove(keyId))
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricCrypto::getSymmetricKey(const uint32_t& keyId,
                                          SymmetricKey*   key)
    {
        const bool result = mSymmetricKeyCache.find(keyId);

        if (result && key)
        {
            *key = mSymmetricKeyCache.get(keyId);
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    void SymmetricCrypto::clearKeys()
    {
        mSymmetricKeyCache.clear();
    }

#ifdef IMPORT_RAW_KEY
    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::importRawKey(const uint32_t&   keyId,
                                            const uint8_t*    sourceBuffer,
                                            const uint16_t&   sourceBufferLen,
                                            const uint64_t*   attributeBuffer,
                                            const uint64_t&   attributeBufferLen,
                                            const ByteBuffer& pinMaterial)
    {
        bool            result = false;
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;

        do
        {
            result = sourceBuffer       &&
                     sourceBufferLen    &&
                     keyId;

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            result = static_cast<SgxMaxKeyLimits>(mSymmetricKeyCache.count()) < SgxMaxKeyLimits::symmetric;

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_KEY_TABLE_FULL;
                break;
            }

            SymmetricKey symKey{};
            result = allocateSymmetricKey(&symKey, static_cast<SymmetricKeySize>(sourceBufferLen));
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_OUT_OF_MEMORY;
                break;
            }

            memcpy_s(symKey.key.get(),
                     symKey.key.size(),
                     sourceBuffer,
                     sourceBufferLen);

            std::string filePath;

            if (attributeBuffer)
            {
                std::string fileName = Utils::SgxFileUtils::generateRandomFilename();
                if (fileName.empty())
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                result = Utils::TokenObjectParser::writeTokenObject(fileName, pinMaterial, attributeBuffer, attributeBufferLen,
                                                                    symKey.key.get(), symKey.key.size(), false, 0, &filePath);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL;
                    break;
                }

                symKey.keyFile = filePath;
            }

            mSymmetricKeyCache.add(keyId, symKey);

        } while (false);

        return static_cast<SgxStatus>(status);
    }
#endif

    //---------------------------------------------------------------------------------------------
    void SymmetricCrypto::fillCryptInitParams(CryptParams*              cryptParams,
                                              const BlockCipherMode&    cipherMode,
                                              const ByteBuffer&         key,
                                              const uint8_t*            iv,
                                              const uint32_t&           ivSize,
                                              const uint8_t*            aad,
                                              const uint32_t&           aadSize,
                                              const uint32_t&           tagBits,
                                              const int&                counterBits,
                                              const uint32_t&           padding)
    {

        if (!cryptParams)
        {
            return;
        }

        cryptParams->cipherMode = cipherMode;

        if (key.get())
        {
            cryptParams->key.allocate(key.size());
            if (cryptParams->key.isValid())
            {
                cryptParams->key.fromData(key.get(), key.size());
            }
        }

        if (iv && ivSize)
        {
            cryptParams->iv.allocate(ivSize);
            if (cryptParams->iv.isValid())
            {
                cryptParams->iv.fromData(iv, ivSize);
            }
        }

        if (aad && aadSize)
        {
            cryptParams->aad.allocate(aadSize);
            if (cryptParams->aad.isValid())
            {
                cryptParams->aad.fromData(aad, aadSize);
            }
        }

        cryptParams->padding = padding;

        if (BlockCipherMode::gcm == cipherMode)
        {
            cryptParams->tagBits = tagBits;
        }

        if (BlockCipherMode::ctr == cipherMode)
        {
            cryptParams->counterBits = counterBits;
        }
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::decryptInitEvp(const uint32_t&       keyId,
                                                   const CryptParams&    cryptParams)
    {
        SgxCryptStatus          status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool                    result = false;
        EVPDecrypt              evpDecrypt;
        cipherModeKeyLengthPair cipherModeKeyLengthPair = std::make_pair(cryptParams.cipherMode,
                                                                         static_cast<SymmetricKeySize>(cryptParams.key.size()));

        do
        {
            if (!evpCipherFn.count(cipherModeKeyLengthPair))
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            result = evpDecrypt.init(evpCipherFn[cipherModeKeyLengthPair](), cryptParams);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            addEVPCtxState(keyId,
                           evpDecrypt.getContext(),
                           cryptParams.cipherMode,
                           cryptParams.tagBits,
                           cryptParams.padding);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::decryptInitIpp(const uint32_t&       keyId,
                                                   const CryptParams&    cryptParams)
    {
        SgxCryptStatus  status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result = false;
        IppDecrypt      ippDecrypt;

        do
        {
            result = ippDecrypt.decryptInit(cryptParams);
            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }

            addIppCtxState(keyId,
                           ippDecrypt.getIppContext(),
                           cryptParams.cipherMode,
                           cryptParams.iv.get(),
                           cryptParams.iv.size(),
                           cryptParams.counterBits);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::decryptInit(const uint32_t&         keyId,
                                           const BlockCipherMode&  cipherMode,
                                           const uint8_t*          iv,
                                           const uint32_t&         ivSize,
                                           const uint8_t*          aad,
                                           const uint32_t&         aadSize,
                                           const uint32_t&         padding,
                                           const uint32_t&         tagBits,
                                           const int&              counterBits)
    {
        SgxCryptStatus  status          = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result          = false;
        CryptParams     cryptParams{};
        SymmetricKey    symKey{};

        do
        {
            result = isSupportedAesMode(cipherMode);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BLOCK_CIPHER_MODE;
                break;
            }

            if (BlockCipherMode::ctr == cipherMode)
            {
                result = iv                             &&
                         !padding                       &&
                         isSupportedIvSize(ivSize)      &&
                         isSupportedCounterBitsSize(counterBits);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }
            }
            else if (BlockCipherMode::gcm == cipherMode)
            {
                result = !padding && isSupportedTagSize(tagBits/8);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }
            }
            else if (BlockCipherMode::cbc == cipherMode)
            {
                result = iv && isSupportedIvSize(ivSize);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }
            }

            result = getSymmetricKey(keyId, &symKey);
            if (result)
            {
                fillCryptInitParams(&cryptParams,
                                    cipherMode,
                                    symKey.key,
                                    iv,
                                    ivSize,
                                    aad,
                                    aadSize,
                                    tagBits,
                                    counterBits,
                                    padding);

                if (BlockCipherMode::ctr == cipherMode)
                {
                    status = decryptInitIpp(keyId, cryptParams);
                }
                else
                {
                    status = decryptInitEvp(keyId, cryptParams);
                }

            }
            else
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE;
            }
        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::decryptUpdateEvp(const uint32_t&     keyId,
                                                     const uint8_t*      sourceBuffer,
                                                     const uint32_t&     sourceBufferLen,
                                                     uint8_t*            destBuffer,
                                                     const uint32_t&     destBufferLen,
                                                     uint32_t*           destBufferWritten,
                                                     bool                doFullDecryptWithoutFinal)
    {
        SgxCryptStatus  status          = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result          = false;
        int             bytesDecrypted  = 0;
        EVPDecrypt      evpDecrypt;
        EVPCtxState     evpCtxState;

        do
        {
            result = getEVPCtxState(keyId, &evpCtxState);
            if (!result || !destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!destBuffer) // To return bytes needed for dest Buffer.
            {
                if (BlockCipherMode::cbc             == evpCtxState.cryptParams.cipherMode &&
                    BlockCipherPadding::BlockPadding == static_cast<BlockCipherPadding>(evpCtxState.cryptParams.padding))
                {
                    uint8_t tailBlockDataSize = sourceBufferLen % aesBlockSize;
                    *destBufferWritten = sourceBufferLen - tailBlockDataSize;
                }
                else if (BlockCipherMode::gcm == evpCtxState.cryptParams.cipherMode)
                {
                    if (doFullDecryptWithoutFinal)
                    {
                        *destBufferWritten = sourceBufferLen - (evpCtxState.cryptParams.tagBits / 8);
                    }
                    else
                    {
                        *destBufferWritten = 0;
                    }
                }
                else
                {
                    *destBufferWritten = sourceBufferLen;
                }

                result = true;
                break;
            }

            // Store input source buffer until decryptFinal call for GCM decryption.
            if (BlockCipherMode::gcm == evpCtxState.cryptParams.cipherMode)
            {
                uint32_t currentCipherTextSize = evpCtxState.cryptParams.cipherText.size();
                uint32_t updatedCipherTextSize = currentCipherTextSize + sourceBufferLen;

                if (updatedCipherTextSize > static_cast<uint32_t>(SgxMaxDataLimitsInBytes::cipherTextSizeForGCM))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE;
                    break;
                }

                evpCtxState.cryptParams.cipherText.resize(updatedCipherTextSize);
                memcpy_s(evpCtxState.cryptParams.cipherText.data() + currentCipherTextSize,
                         sourceBufferLen,
                         sourceBuffer,
                         sourceBufferLen);

                *destBufferWritten = 0;
                mEVPCtxStateCache.add(keyId, evpCtxState);
                status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;

                if (doFullDecryptWithoutFinal)
                {
                    *destBufferWritten = destBufferLen;
                    status = static_cast<SgxCryptStatus>(decryptFinal(keyId, destBuffer, destBufferWritten));
                }
                break;
            }
            else
            {
                // If padding is not enabled in cbc mode, reject all inputs that are not of aesBlockSize.
                if (BlockCipherMode::cbc == evpCtxState.cryptParams.cipherMode &&
                    (0 != (sourceBufferLen % aesBlockSize)) &&
                    (BlockCipherPadding::NoPadding == static_cast<BlockCipherPadding>(evpCtxState.cryptParams.padding)))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }

                result = evpDecrypt.decryptUpdate(&evpCtxState, destBuffer, &bytesDecrypted, sourceBuffer, sourceBufferLen);

                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                    *destBufferWritten = 0;
                    break;
                }
                *destBufferWritten = bytesDecrypted;
            }

            if (doFullDecryptWithoutFinal)
            {
                int offset = bytesDecrypted;
                bytesDecrypted = 0;

                result = evpDecrypt.decryptFinal(&evpCtxState, destBuffer + offset, &bytesDecrypted);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                    *destBufferWritten = 0;
                    break;
                }
                *destBufferWritten += bytesDecrypted;

                freeEvpContext(evpCtxState.evpCtx);
                mEVPCtxStateCache.remove(keyId);
            }
            else
            {
                mEVPCtxStateCache.add(keyId, evpCtxState);
            }
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::decryptUpdateIpp(const uint32_t&    keyId,
                                                     const uint8_t*     sourceBuffer,
                                                     const uint32_t&    sourceBufferLen,
                                                     uint8_t*           destBuffer,
                                                     const uint32_t&    destBufferLen,
                                                     uint32_t*          destBufferWritten,
                                                     IppCtxState*       ippCtxState,
                                                     bool               doFullDecryptWithoutFinal)
    {
        SgxCryptStatus  status          = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result          = false;
        int             bytesDecrypted  = 0;
        IppDecrypt      ippDecrypt;

        do
        {
            if (!destBufferWritten || !ippCtxState)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!destBuffer) // To return bytes needed for dest Buffer.
            {
                *destBufferWritten = sourceBufferLen;
                result             = true;
                break;
            }

            result = ippDecrypt.decryptUpdate(ippCtxState, destBuffer, &bytesDecrypted, sourceBuffer, sourceBufferLen);
            if (!result)
            {
                status             = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                *destBufferWritten = 0;
                break;
            }

            *destBufferWritten = bytesDecrypted;

            if (doFullDecryptWithoutFinal)
            {
                ippDecrypt.decryptFinal(ippCtxState);

                // Remove from cache as the encrypt operation is complete
                mIppCtxStateCache.remove(keyId);
            }
            else
            {
                mIppCtxStateCache.add(keyId, *ippCtxState);
            }

        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::decryptUpdate(const uint32_t&     keyId,
                                             const uint8_t*      sourceBuffer,
                                             const uint32_t&     sourceBufferLen,
                                             uint8_t*            destBuffer,
                                             const uint32_t&     destBufferLen,
                                             uint32_t*           destBufferWritten,
                                             bool                doFullDecryptWithoutFinal)
    {
        SgxCryptStatus  status  = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result  = false;
        bool            ctrMode = false;
        IppCtxState     ippCtxState;

        do
        {
            result = getIppCtxState(keyId, &ippCtxState);
            if (result)
            {
                ctrMode = true;
            }

            if (ctrMode)
            {
                status = decryptUpdateIpp(keyId,
                                          sourceBuffer,
                                          sourceBufferLen,
                                          destBuffer,
                                          destBufferLen,
                                          destBufferWritten,
                                          &ippCtxState,
                                          doFullDecryptWithoutFinal);
            }
            else
            {
                status = decryptUpdateEvp(keyId,
                                          sourceBuffer,
                                          sourceBufferLen,
                                          destBuffer,
                                          destBufferLen,
                                          destBufferWritten,
                                          doFullDecryptWithoutFinal);
            }

        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::decryptFinalIpp(const uint32_t& keyId,
                                                    uint8_t*        destBuffer,
                                                    uint32_t*       destBufferWritten,
                                                    IppCtxState*    ippCtxState)
    {
        SgxCryptStatus  status  = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        IppDecrypt      ippDecrypt;

        do
        {
            if (!destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            ippDecrypt.decryptFinal(ippCtxState);
            *destBufferWritten = 0;

            mIppCtxStateCache.remove(keyId);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxCryptStatus SymmetricCrypto::decryptFinalEvp(const uint32_t&    keyId,
                                                    uint8_t*           destBuffer,
                                                    uint32_t*          destBufferWritten)
    {
        SgxCryptStatus  status          = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result          = false;
        int             bytesDecrypted  = 0;
        uint32_t        destBufferLen   = 0;
        EVPDecrypt      evpDecrypt;
        EVPCtxState     evpCtxState;

        do
        {
            result = getEVPCtxState(keyId, &evpCtxState);
            if (!result || !destBufferWritten)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            destBufferLen      = *destBufferWritten;
            *destBufferWritten = 0;

            if (BlockCipherMode::gcm == evpCtxState.cryptParams.cipherMode)
            {
                uint32_t          tagBytes       = evpCtxState.cryptParams.tagBits >> 3;
                uint32_t          cipherTextSize = evpCtxState.cryptParams.cipherText.size() - tagBytes;

                result = evpDecrypt.decryptUpdate(&evpCtxState,
                                                  destBuffer,
                                                  &bytesDecrypted,
                                                  evpCtxState.cryptParams.cipherText.data(),
                                                  cipherTextSize);
                if (!result)
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                    *destBufferWritten = 0;
                    break;
                }

                *destBufferWritten = bytesDecrypted;
                bytesDecrypted = 0;
            }

            result = evpDecrypt.decryptFinal(&evpCtxState,
                                             destBuffer + *destBufferWritten,
                                             &bytesDecrypted);
            if (!result)
            {
                memset_s(destBuffer, destBufferLen, 0, destBufferLen);
                status            = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                destBufferWritten = 0;
                break;
            }

            *destBufferWritten += bytesDecrypted;

            freeEvpContext(evpCtxState.evpCtx);
            mEVPCtxStateCache.remove(keyId);
        } while(false);

        return status;
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::decryptFinal(const uint32_t& keyId,
                                            uint8_t*        destBuffer,
                                            uint32_t*       destBufferWritten)
    {
        SgxCryptStatus  status        = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result        = false;
        bool            ctrMode       = false;
        IppCtxState     ippCtxState;

        do
        {
            result = getIppCtxState(keyId, &ippCtxState);
            if (result)
            {
                ctrMode = true;
            }

            if (ctrMode)
            {
                status = decryptFinalIpp(keyId,
                                         destBuffer,
                                         destBufferWritten,
                                         &ippCtxState);
            }
            else
            {
                status = decryptFinalEvp(keyId,
                                         destBuffer,
                                         destBufferWritten);
            }
        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //--------------------------------------------------------------------------------------------
    void SymmetricCrypto::clearState(const uint32_t& keyId)
    {
        if (mEVPCtxStateCache.find(keyId))
        {
            mEVPCtxStateCache.remove(keyId);
        }
        else if (mIppCtxStateCache.find(keyId))
        {
            mIppCtxStateCache.remove(keyId);
        }
    }

    //--------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::updateHandle(uint32_t keyHandle, uint32_t newKeyHandle)
    {
        if (!mSymmetricKeyCache.find(keyHandle))
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
        }

        SymmetricKey symmetricKey = mSymmetricKeyCache.get(keyHandle);

        mSymmetricKeyCache.add(newKeyHandle, symmetricKey);

        bool removeTokenFile = false;
        mSymmetricKeyCache.remove(keyHandle, removeTokenFile);

        return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus SymmetricCrypto::setWrappingStatus(const uint32_t& keyId)
    {
        if (!mSymmetricKeyCache.find(keyId))
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_KEY_HANDLE);
        }

        SymmetricKey symmetricKey = mSymmetricKeyCache.get(keyId);

        if (symmetricKey.isUsedForWrapping)
        {
            return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
        }

        if (!symmetricKey.keyFile.empty())
        {
            if (!Utils::TokenObjectParser::setWrappingStatus(symmetricKey.keyFile, 0))
            {
                return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_UNSUCCESSFUL);
            }
        }

        symmetricKey.isUsedForWrapping = true;

        mSymmetricKeyCache.add(keyId, symmetricKey);

        return static_cast<SgxStatus>(SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS);
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricCrypto::checkWrappingStatus(const uint32_t& keyId)
    {
        SymmetricKey symmetricKey = mSymmetricKeyCache.get(keyId);

        return symmetricKey.isUsedForWrapping;
    }

} //CryptoSgx