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

#include "EVPEncrypt.h"

#include <mbusafecrt.h>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    EVPEncrypt::EVPEncrypt()
    {
    }

    //---------------------------------------------------------------------------------------------
    EVPContextHandle& EVPEncrypt::getContext()
    {
        return mContext;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::init(const EVP_CIPHER*  cipher,
                          const CryptParams& cryptParams)
    {
        bool result = mContext.allocate();

        if (result)
        {
            do
            {
                switch (cryptParams.cipherMode)
                {
                    case BlockCipherMode::gcm:
                        result = initGCM(cipher, cryptParams);
                        break;
                    case BlockCipherMode::cbc:
                        result = initCBC(cipher, cryptParams);
                        break;
                    case BlockCipherMode::ctr:
                        result = initCTR(cipher, cryptParams);
                        break;
                    default:
                        result = false;
                        break;
                }
                if (!result)
                {
                    break;
                }

            } while (false);
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::encryptUpdate(EVPCtxState*      evpCtxState,
                                   uint8_t*          destBuffer,
                                   int*              encryptedBytes,
                                   const uint8_t*    sourceBuffer,
                                   const int         sourceBufferLen)
    {
        bool result = false;

        if (!evpCtxState || !encryptedBytes)
        {
            return false;
        }

        do
        {
            result = (EVP_EncryptUpdate(evpCtxState->evpCtx,
                                        destBuffer,
                                        encryptedBytes,
                                        sourceBuffer,
                                        sourceBufferLen) == 1);
            if (!result)
            {
                break;
            }
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::encryptFinal(EVPCtxState*  evpCtxState,
                                  uint8_t*      destBuffer,
                                  int*          encryptedBytes)
    {
        bool result = false;

        if (!evpCtxState || !encryptedBytes)
        {
            return false;
        }

        result = destBuffer     &&
                 encryptedBytes &&
                 (EVP_EncryptFinal_ex(evpCtxState->evpCtx,
                                      destBuffer,
                                      encryptedBytes) == 1);

        if (result && (BlockCipherMode::gcm == evpCtxState->cryptParams.cipherMode))
        {
            uint32_t tagBytes = evpCtxState->cryptParams.tagBits / bitsPerByte;
            result = (1 == EVP_CIPHER_CTX_ctrl(evpCtxState->evpCtx,
                                               EVP_CTRL_GCM_GET_TAG,
                                               tagBytes,
                                               destBuffer + *encryptedBytes));
            *encryptedBytes += tagBytes;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::encrypt(uint8_t*          destBuffer,
                             int*              encryptedBytes,
                             const uint8_t*    sourceBuffer,
                             const int         sourceBufferLen,
                             bool              useBlockCipherPadding)
    {
        bool result = false;
        do
        {
            if (useBlockCipherPadding)
            {
                result = encryptWithPaddingCustomizations(destBuffer,
                                                          encryptedBytes,
                                                          sourceBuffer,
                                                          sourceBufferLen);
                if (!result)
                {
                    break;
                }
            }
            else
            {
                if (!encryptedBytes)
                {
                    break;
                }

                result = mContext.isValid() &&
                         (EVP_EncryptUpdate(&mContext,
                                            destBuffer,
                                            encryptedBytes,
                                            sourceBuffer,
                                            sourceBufferLen) == 1);
                if (!result)
                {
                    break;
                }
            }
        } while (false);
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::final(CryptParams* cryptParams,
                           Byte*        destBuffer,
                           int*         encryptedBytes)
    {
        bool result = false;

        if (!cryptParams || !encryptedBytes)
        {
            return false;
        }

        if (encryptedBytes > 0)
        {
            result = mContext.isValid() &&
                     destBuffer         &&
                     (EVP_EncryptFinal_ex(&mContext,
                                          destBuffer,
                                          encryptedBytes) == 1);
        }

        if (result && (BlockCipherMode::gcm == cryptParams->cipherMode)  &&
            cryptParams->tag.get())
        {
            result = (1 == EVP_CIPHER_CTX_ctrl(&mContext,
                                               EVP_CTRL_GCM_GET_TAG,
                                               cryptParams->tag.size(),
                                               cryptParams->tag.get()));
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::initGCM(const EVP_CIPHER*  cipher,
                             const CryptParams& cryptParams)
    {
        bool result = false;

        if (!cipher)
        {
            return false;
        }

        do
        {
            result = EVP_EncryptInit_ex(&mContext,
                                        cipher,
                                        nullptr,
                                        0,
                                        0);
            if (!result)
            {
                break;
            }

            result = EVP_CIPHER_CTX_ctrl(&mContext,
                                         EVP_CTRL_GCM_SET_IVLEN,
                                         cryptParams.iv.size(),
                                         0);
            if (!result)
            {
                break;
            }

            result = EVP_EncryptInit_ex(&mContext,
                                        0,
                                        nullptr,
                                        cryptParams.key.get(),
                                        cryptParams.iv.get());

            if (!result)
            {
                break;
            }

            if (cryptParams.aad.get() &&
                cryptParams.aad.size())
            {
                int outLength{};
                result = EVP_EncryptUpdate(&mContext,
                                           0,
                                           &outLength,
                                           cryptParams.aad.get(),
                                           cryptParams.aad.size());
            }

        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::initCTR(const EVP_CIPHER*  cipher,
                             const CryptParams& cryptParams)
    {
        if (!cipher)
        {
            return false;
        }

        return EVP_EncryptInit_ex(&mContext,
                                  cipher,
                                  nullptr,
                                  cryptParams.key.get(),
                                  cryptParams.iv.get());
    }

//---------------------------------------------------------------------------------------------
    bool EVPEncrypt::initCBC(const EVP_CIPHER*  cipher,
                             const CryptParams& cryptParams)
    {
        bool result = false;

        if (!cipher)
        {
            return false;
        }

        do
        {
            result = EVP_EncryptInit_ex(&mContext,
                                        cipher,
                                        nullptr,
                                        cryptParams.key.get(),
                                        cryptParams.iv.get());
            if (!result)
            {
                break;
            }
            // Do not use OpenSSL padding for the AES operation.
            result = EVP_CIPHER_CTX_set_padding(&mContext, cryptParams.padding);
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPEncrypt::encryptWithPaddingCustomizations(uint8_t*          destBuffer,
                                                      int*              encryptedBytes,
                                                      const uint8_t*    sourceBuffer,
                                                      const int         sourceBufferLen)
    {
        bool    result              = false;
        int     updatedBytes        = 0;
        uint8_t tailBlockDataSize   = 0;
        uint8_t tailBlockPadSize    = 0;

        do
        {

            if (!encryptedBytes)
            {
                result = false;
                break;
            }

            int unPaddedInputSize = sourceBufferLen - (sourceBufferLen % aesBlockSize);

            result = mContext.isValid() &&
                (EVP_EncryptUpdate(&mContext,
                                   destBuffer,
                                   encryptedBytes,
                                   sourceBuffer,
                                   unPaddedInputSize) == 1);
            if (!result)
            {
                break;
            }

            tailBlockDataSize = sourceBufferLen % aesBlockSize;
            tailBlockPadSize  = aesBlockSize - tailBlockDataSize;

            ByteBuffer tailBlock(aesBlockSize);
            //TODO: check out of memory for tailBlockSize
            // Frame the tail Block buffer with remaining bytes(tailBlock Data) & padded bytes(tailBlock pad)
            memset_s(tailBlock.get(), tailBlock.size(), tailBlockPadSize, tailBlock.size());
            if (tailBlockDataSize > 0)
            {
                memcpy_s(tailBlock.get(), tailBlock.size(), &sourceBuffer[unPaddedInputSize], tailBlockDataSize);
            }

            result = (EVP_EncryptUpdate(&mContext,
                                        (destBuffer + *encryptedBytes),
                                        &updatedBytes,
                                        tailBlock.get(),
                                        tailBlock.size()) == 1);
            *encryptedBytes += updatedBytes;
        } while (false);

        return result;
    }

} //CryptoSgx