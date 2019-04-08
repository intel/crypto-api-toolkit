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

#include "IppHash.h"
#include "HashDefs.h"

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    IppHash::IppHash(const HashMode& hashMode, const bool& hmac)
    {
        mHashMode = hashMode;
        mHmac     = hmac;
    }

    //---------------------------------------------------------------------------------------------
    int IppHash::getSize()
    {
        int ippStateSize{0};

        if (mHmac)
        {
            ippsHMAC_GetSize(&ippStateSize);
        }
        else
        {
            ippsHashGetSize(&ippStateSize);
        }

        return ippStateSize;
    }

    //---------------------------------------------------------------------------------------------
    bool IppHash::init(void*            destBuffer,
                       const uint32_t&  destBufferLen,
                       const uint8_t*   secret,
                       const uint32_t&  secretLen)
    {
        bool        result      = false;
        IppStatus   ippStatus   = ippStsErr;

        do
        {
            result = destBuffer && destBufferLen;

            if (!result)
            {
                break;
            }

            if (mHmac   &&
                secret  &&
                secretLen)
            {
                ippStatus = ippsHMAC_Init(secret,
                                          secretLen,
                                          reinterpret_cast<IppsHMACState*>(destBuffer),
                                          static_cast<IppHashAlgId>(mHashMode));
            }
            else
            {
                ippStatus = ippsHashInit(reinterpret_cast<IppsHashState*>(destBuffer),
                                         static_cast<IppHashAlgId>(mHashMode));

            }

            result = (ippStsNoErr == ippStatus);
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool IppHash::update(void*           ippCtx,
                         Byte*           sourceBuffer,
                         const uint32_t& sourceBufferLen)
    {
        bool        result      = false;
        IppStatus   ippStatus   = ippStsErr;

        do
        {
            result = sourceBuffer && sourceBufferLen;

            if (!result)
            {
                break;
            }

            if (mHmac)
            {
                ippStatus = ippsHMAC_Update(reinterpret_cast<Ipp8u*>(sourceBuffer),
                                            sourceBufferLen,
                                            reinterpret_cast<IppsHMACState*>(ippCtx));
            }
            else
            {
                ippStatus = ippsHashUpdate(reinterpret_cast<Ipp8u*>(sourceBuffer),
                                           sourceBufferLen,
                                           reinterpret_cast<IppsHashState*>(ippCtx));
            }

            result = (ippStsNoErr == ippStatus);
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool IppHash::final(void*           ippCtx,
                        Byte*           destBuffer,
                        const uint32_t& destBufferLen)
    {
        bool        result      = false;
        IppStatus   ippStatus   = ippStsErr;

        do
        {
            result = destBuffer &&
                     (destBufferLen >= static_cast<int>(hashDigestLengthMap[mHashMode])) ;

            if (!result)
            {
                break;
            }

            if (mHmac)
            {
                ippStatus = ippsHMAC_Final(reinterpret_cast<Ipp8u*>(destBuffer),
                                           static_cast<int>(hashDigestLengthMap[mHashMode]),
                                           reinterpret_cast<IppsHMACState*>(ippCtx));
            }
            else
            {
                if (destBufferLen < static_cast<int>(hashDigestLengthMap[mHashMode]))
                {
                    result = false;
                    break;
                }

                ippStatus = ippsHashFinal(reinterpret_cast<Ipp8u*>(destBuffer),
                                          reinterpret_cast<IppsHashState*>(ippCtx));
            }

            result = (ippStsNoErr == ippStatus);
        } while (false);

        return result;
    }
} //CryptoSgx