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

#include "HashCrypto.h"
#include "Constants.h"
#include "IppHash.h"
#include "HashDefs.h"

#include <type_traits>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    void CryptoHash::addHashState(const uint32_t&   hashId,
                                  const HashMode&   hashMode,
                                  const bool&       hmac,
                                  ByteBuffer        hashContext)
    {
        HashState hashState;
        hashState.hashMode   = static_cast<HashMode>(hashMode);
        hashState.hmac       = hmac;
        hashState.ippCtx     = hashContext;
        hashState.valid      = true;

        mHashStateCache.add(hashId, hashState);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus CryptoHash::createHashState(const uint32_t&    hashId,
                                          const HashMode&    hashMode,
                                          const bool&        hmac,
                                          const uint8_t*     secret,
                                          const uint32_t&    secretLen)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool           result = hashId &&
                                (hmac ? (secret && secretLen) : true) &&
                                (HashMode::sha256 == hashMode || HashMode::sha512 == hashMode);

        do
        {
            if (!result)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }
            if (static_cast<SgxMaxKeyLimits>(mHashStateCache.count()) >= SgxMaxKeyLimits::hash)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_HASH_STATE_TABLE_FULL;
                break;
            }
            if (static_cast<SgxMaxDataLimitsInBytes>(secretLen) > SgxMaxDataLimitsInBytes::hash)
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            IppHash ippHash(hashMode, hmac);
            int ippCtxSize = ippHash.getSize();

            if (ippCtxSize)
            {
                ByteBuffer ippCtx(ippCtxSize);
                result = ippHash.init(ippCtx.get(),
                                      ippCtx.size(),
                                      secret,
                                      secretLen);

                if (result)
                {
                    addHashState(hashId, hashMode, hmac, ippCtx);
                }
            }
        } while (false);

        if (result)
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool CryptoHash::getHashState(const uint32_t& hashId,
                                  HashState*      hashState)
    {
        bool result = false;

        if (hashState && mHashStateCache.find(hashId))
        {
            *hashState = mHashStateCache.get(hashId);
            result = true;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus CryptoHash::hashData(const uint32_t&  hashId,
                                   const uint8_t*   sourceBuffer,
                                   const uint32_t&  sourceBufferLen)
    {
        SgxCryptStatus  status      = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
        bool            result      = false;
        bool            hmac        = false;
        HashMode        hashMode    = HashMode::invalid;
        HashState       hashState;

        do
        {
            result = getHashState(hashId, &hashState);

            if (result && sourceBuffer)
            {
                hashMode = hashState.hashMode;
                hmac     = hashState.hmac;

                if (0 == hashDigestLengthMap.count(static_cast<HashMode>(hashMode)))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                    break;
                }

                if (sourceBufferLen > static_cast<uint32_t>(SgxMaxDataLimitsInBytes::hash))
                {
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE;
                    break;
                }

                IppHash ippHash(hashMode, hmac);
                result = ippHash.update(hashState.ippCtx.get(),
                                        const_cast<Byte*>(sourceBuffer),
                                        sourceBufferLen);

                if (result)
                {
                    addHashState(hashId, hashMode, hmac, hashState.ippCtx);
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
                }
            }
        } while (false);

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus CryptoHash::getHashDigest(const uint32_t& hashId,
                                        uint8_t*        destBuffer,
                                        const uint32_t& destBufferLen)
    {
        SgxCryptStatus  status      = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        bool            result      = false;
        bool            hmac        = false;
        HashMode        hashMode    = HashMode::invalid;
        HashState       hashState;

        do
        {
            if (!destBuffer)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            result = getHashState(hashId, &hashState);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            hashMode = hashState.hashMode;
            hmac     = hashState.hmac;

            if (hashDigestLengthMap.count(static_cast<HashMode>(hashMode)))
            {
                if (destBufferLen < static_cast<uint32_t>(hashDigestLengthMap[static_cast<HashMode>(hashMode)]))
                {
                    result = false;
                    status = SgxCryptStatus::SGX_CRYPT_STATUS_BUFFER_TOO_SHORT;
                    break;
                }
            }
            else
            {
                result = false;
                status = SgxCryptStatus::SGX_CRYPT_STATUS_INVALID_PARAMETER;
                break;
            }

            IppHash ippHash(hashMode, hmac);
            result = ippHash.final(hashState.ippCtx.get(),
                                   destBuffer,
                                   destBufferLen);

            if (!result)
            {
                status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
                break;
            }
        } while (false);

        if (result)
        {
            destroyHash(hashId);
            status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    SgxStatus CryptoHash::destroyHash(const uint32_t& hashId)
    {
        SgxCryptStatus status = SgxCryptStatus::SGX_CRYPT_STATUS_SUCCESS;

        if (!mHashStateCache.remove(hashId))
        {
            status = SgxCryptStatus::SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED;
        }

        return static_cast<SgxStatus>(status);
    }

    //---------------------------------------------------------------------------------------------
    bool CryptoHash::computeHash(const HashMode& hashMode,
                                 const Byte*     srcBuffer,
                                 const uint32_t& srcBufferLen,
                                 Byte*           destBuffer,
                                 const uint32_t& destBufferLen)
    {
        bool        result              = false;
        int         ippCtxSize          = 0;
        uint32_t    destSizeRequired    = 0;
        do
        {
            if (HashMode::sha256 == hashMode)
            {
                destSizeRequired = static_cast<uint32_t>(HashDigestLength::sha256);
            }
            else if (HashMode::sha512 == hashMode)
            {
                destSizeRequired = static_cast<uint32_t>(HashDigestLength::sha512);
            }
            else
            {
                result = false;
                break;
            }

            result = srcBuffer && destBuffer && srcBufferLen && (destSizeRequired == destBufferLen);
            if (!result)
            {
                break;
            }

            IppHash ippHash(hashMode, false);
            ippCtxSize = ippHash.getSize();

            ByteBuffer ippCtx(ippCtxSize);
            result = ippHash.init(ippCtx.get(),
                                  ippCtx.size(),
                                  nullptr,
                                  0);
            if (!result)
            {
                break;
            }

            result = ippHash.update(ippCtx.get(),
                                    const_cast<Byte*>(srcBuffer),
                                    srcBufferLen);
            if (!result)
            {
                break;
            }

            result = ippHash.final(ippCtx.get(),
                                   destBuffer,
                                   destBufferLen);
        } while (false);

        return result;
        }

    //---------------------------------------------------------------------------------------------
    void CryptoHash::clearStates()
    {
        mHashStateCache.clear();
    }
} //CryptoSgx