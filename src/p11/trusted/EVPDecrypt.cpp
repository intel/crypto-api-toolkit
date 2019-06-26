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

#include "EVPDecrypt.h"

#include <mbusafecrt.h>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    EVPDecrypt::EVPDecrypt()
    {
    }

    //---------------------------------------------------------------------------------------------
    EVPContextHandle& EVPDecrypt::getContext()
    {
        return mContext;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPDecrypt::init(const EVP_CIPHER*  cipher,
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
                        result = initGCM(cipher,
                                         cryptParams);
                        break;
                    case BlockCipherMode::cbc:
                        result = initCBC(cipher,
                                         cryptParams);
                        break;
                    case BlockCipherMode::ctr:
                        result = initCTR(cipher,
                                         cryptParams);
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
    bool EVPDecrypt::decryptUpdate(EVPCtxState*   evpCtxState,
                                   uint8_t*       destBuffer,
                                   int*           decryptedLen,
                                   const uint8_t* sourceBuffer,
                                   const int      sourceBufferLen)
    {
        bool        result              = false;
        uint32_t    maxDecryptedBytes   = 0;
        do
        {
            if (!evpCtxState || !decryptedLen)
            {
                return false;
            }

            if (BlockCipherMode::cbc             == evpCtxState->cryptParams.cipherMode &&
                BlockCipherPadding::BlockPadding == static_cast<BlockCipherPadding>(evpCtxState->cryptParams.padding))
            {
                maxDecryptedBytes = (sourceBufferLen / aesBlockSize) * aesBlockSize + aesBlockSize;

                std::unique_ptr<uint8_t[]> tempDestBuffer(new (std::nothrow) uint8_t[maxDecryptedBytes], std::default_delete<uint8_t[]>());
                if (!tempDestBuffer.get())
                {
                    break;
                }

                result = (EVP_DecryptUpdate(evpCtxState->evpCtx,
                                            tempDestBuffer.get(),
                                            decryptedLen,
                                            sourceBuffer,
                                            sourceBufferLen) == 1);
                if (result && *decryptedLen > 0)
                {
                    memcpy_s(destBuffer, *decryptedLen, tempDestBuffer.get(), *decryptedLen);
                }
            }
            else
            {
                result = (EVP_DecryptUpdate(evpCtxState->evpCtx,
                                            destBuffer,
                                            decryptedLen,
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
    bool EVPDecrypt::decryptFinal(EVPCtxState*    evpCtxState,
                                  uint8_t*        destBuffer,
                                  int*            decryptedLen)
    {
        bool        result          = false;
        uint32_t    tagBytes        = 0;
        uint32_t    cipherTextSize  = 0;

        do
        {
            if (!evpCtxState || !decryptedLen)
            {
                return false;
            }

            if (BlockCipherMode::gcm == evpCtxState->cryptParams.cipherMode)
            {
                tagBytes       = evpCtxState->cryptParams.tagBits >> 3;
                cipherTextSize = evpCtxState->cryptParams.cipherText.size() - tagBytes;
                ByteBuffer  tag(evpCtxState->cryptParams.cipherText.data() + cipherTextSize, tagBytes);

                result = (1 == EVP_CIPHER_CTX_ctrl(evpCtxState->evpCtx,
                                                   EVP_CTRL_GCM_SET_TAG,
                                                   tagBytes,
                                                   tag.get()));
                if (!result)
                {
                    break;
                }
            }

            result = destBuffer &&
                     (EVP_DecryptFinal_ex(evpCtxState->evpCtx,
                                          destBuffer,
                                          decryptedLen) == 1);
        } while (false);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPDecrypt::decrypt(CryptParams*   cryptParams,
                             Byte*          destBuffer,
                             int*           decryptedBytes,
                             const Byte*    sourceBuffer,
                             const int      sourceBufferLen,
                             bool           removeBlockCipherPadding)
    {
        bool result = true;

        if (!cryptParams || !decryptedBytes)
        {
            return false;
        }

        do
        {
            result = mContext.isValid() &&
                     destBuffer         &&
                     (EVP_DecryptUpdate(&mContext,
                                        destBuffer,
                                        decryptedBytes,
                                        sourceBuffer,
                                        sourceBufferLen) == 1);
            if (!result)
            {
                break;
            }

            if (removeBlockCipherPadding)
            {
                result = decryptWithPaddingCustomizations(*cryptParams,
                                                          destBuffer,
                                                          decryptedBytes,
                                                          sourceBuffer,
                                                          sourceBufferLen);
                if (!result)
                {
                    break;
                }

            }

            if(BlockCipherMode::gcm == cryptParams->cipherMode  &&
               cryptParams->tag.get())
            {
                result = (1 == EVP_CIPHER_CTX_ctrl(&mContext,
                                                   EVP_CTRL_GCM_SET_TAG,
                                                   cryptParams->tag.size(),
                                                   cryptParams->tag.get()));
                if (!result)
                {
                    break;
                }
            }
        } while (false);
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPDecrypt::final(Byte* destBuffer, int* decryptedBytes)
    {
        return mContext.isValid()   &&
               decryptedBytes       &&
               EVP_DecryptFinal_ex(&mContext,
                                   destBuffer,
                                   decryptedBytes) == 1;
    }

    //---------------------------------------------------------------------------------------------
    bool EVPDecrypt::initGCM(const EVP_CIPHER*  cipher,
                             const CryptParams& cryptParams)
    {
        bool result = false;

        if (!cipher)
        {
            return false;
        }

        do
        {
            result = EVP_DecryptInit_ex(&mContext,
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

            result = EVP_DecryptInit_ex(&mContext,
                                        0,
                                        nullptr,
                                        cryptParams.key.get(),
                                        cryptParams.iv.get());

            if (!result)
            {
                break;
            }

            if (cryptParams.aad.get() && cryptParams.aad.size())
            {
                int outLength{};
                result = EVP_DecryptUpdate(&mContext,
                                           0,
                                           &outLength,
                                           cryptParams.aad.get(),
                                           cryptParams.aad.size());
            }

        } while (false);

        return result;
    }
    //---------------------------------------------------------------------------------------------
    bool EVPDecrypt::initCTR(const EVP_CIPHER*  cipher,
                             const CryptParams& cryptParams)
    {

        return EVP_DecryptInit_ex(&mContext,
                                  cipher,
                                  nullptr,
                                  cryptParams.key.get(),
                                  cryptParams.iv.get());
    }

    //---------------------------------------------------------------------------------------------
    bool EVPDecrypt::initCBC(const EVP_CIPHER*  cipher,
                             const CryptParams& cryptParams)
    {
        bool result = false;

        if (!cipher)
        {
            return false;
        }
        
        do
        {
            result = EVP_DecryptInit_ex(&mContext,
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
    bool EVPDecrypt::decryptWithPaddingCustomizations(CryptParams&  cryptParams,
                                                      Byte*         destBuffer,
                                                      int*          decryptedBytes,
                                                      const Byte*   sourceBuffer,
                                                      const int     sourceBufferLen)
    {
        bool result = true;

        if (!destBuffer || !decryptedBytes)
        {
            return false;
        }

        do
        {
            // Verify each of the decrypted padding bytes. The last byte
            // in the decrypted plaintext buffer is a padding byte and
            // its value is the number of padding bytes.
            uint8_t paddedBytes = destBuffer[*decryptedBytes - 1];
            if ((0 == paddedBytes) || (paddedBytes > aesBlockSize))
            {
                // cannot be zero or greater than the cipher block size.
                result = false;
                break;
            }

            for (auto i = 1; i <= paddedBytes; ++i)
            {
                if (destBuffer[(*decryptedBytes - i)] != paddedBytes)
                {
                    // Padding is not correct because a padding byte has the wrong value.
                    result = false;
                    break;
                }
                destBuffer[(*decryptedBytes - i)] = 0;
            }
            // Reduce the decrypted plaintext size by the number of padding bytes.
            decryptedBytes -= paddedBytes;
        } while (false);

        return result;
    }

} //CryptoSgx