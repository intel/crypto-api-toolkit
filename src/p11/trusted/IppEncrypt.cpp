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

#include "IppEncrypt.h"
#include <mbusafecrt.h>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    IppEncrypt::IppEncrypt()
    {
    }

    //---------------------------------------------------------------------------------------------
    IppContextHandle& IppEncrypt::getIppContext()
    {
        return mContext;
    }

    //---------------------------------------------------------------------------------------------
    bool IppEncrypt::encryptInit(const CryptParams& cryptParams)
    {
        int         ctxSize     = 0;
        int         keySize     = 0;
        bool        result      = false;
        IppStatus   ippStatus   = ippStsErr;

        do
        {
            result = cryptParams.key.get() &&
                     mContext.allocate();
            if (!result)
            {
                break;
            }

            keySize = cryptParams.key.size();

            ippStatus = ippsAESGetSize(&ctxSize);

            result = (ippStsNoErr == ippStatus);
            if (!result)
            {
                break;
            }

            ippStatus = ippsAESInit(cryptParams.key.get(), keySize, &mContext, ctxSize);

            result = (ippStsNoErr == ippStatus);
        } while(false);

        return result;
    }
    //---------------------------------------------------------------------------------------------
    bool IppEncrypt::encryptUpdate(IppCtxState&    ippCtxState,
                                   uint8_t*        destBuffer,
                                   int&            encryptedBytes,
                                   const uint8_t*  sourceBuffer,
                                   const int       sourceBufferLen)
    {
        bool        result      = false;
        IppStatus   ippStatus   = ippStsErr;

        do
        {
            result = sourceBuffer &&
                     destBuffer   &&
                     sourceBufferLen;
            if (!result)
            {
                encryptedBytes = 0;
                break;
            }

            ippStatus = ippsAESEncryptCTR(sourceBuffer,
                                          destBuffer,
                                          sourceBufferLen,
                                          ippCtxState.ippCtx,
                                          ippCtxState.cryptParams.iv.get(),
                                          ippCtxState.cryptParams.counterBits);

            result = (ippStsNoErr == ippStatus);

            if (result) // Assuming all of sourceBuffer is encrypted with no error returned by the above ipp call..
            {
                encryptedBytes = sourceBufferLen;
            }
            else
            {
                encryptedBytes = 0;
            }
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    void IppEncrypt::encryptFinal(IppCtxState& ippCtxState)
    {
        delete [] (Ipp8u*)ippCtxState.ippCtx;
    }

} //CryptoSgx