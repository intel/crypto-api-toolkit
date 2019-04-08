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

#ifndef ENCLAVE_ASYMMETRIC_CRYPTO_H
#define ENCLAVE_ASYMMETRIC_CRYPTO_H

#include "AsymmetricKeyCache.h"
#include "ByteBuffer.h"
#include "Constants.h"

#include <string>
#include <openssl/rsa.h>

namespace CryptoSgx
{
    enum class OperationType
    {
        Public  = 0,
        Private = 1
    };

    /**
     * Asymmetric Methods implementation.
     */
    class AsymmetricCrypto
    {
    public:
        /**
         * Constructor.
         */
        AsymmetricCrypto();

        /**
         * Destructor.
         */
        ~AsymmetricCrypto();

        /**
         * Clears the asymmetric keys cached in SGX
         */
        void clearKeys();

        /**
         * Generates a new asymmetric key pair and adds the public and private keyIds to their corresponding caches
         * @param publicKeyId      The public keyId from provider
         * @param privateKeyId     The private keyId from provider
         * @param modulusLength    modulus length in bits
         * @return                 SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus generateAsymmetricKey(const uint32_t&          publicKeyId,
                                        const uint32_t&          privateKeyId,
                                        const AsymmetricKeySize& modulusLength);

        /**
        * Removes an existing asymmetric key pair from the key cache
        * @param    keyId      The key Id from provider
        * @return   SgxStatus  value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus removeAsymmetricKey(const uint32_t& keyId);

        /**
        * Encrypts a buffer using the public key
        * @param publicKeyId                The public key Id from provider
        * @param sourceBuffer               The input buffer to be encrypted
        * @param sourceBufferLen            The length of the input buffer
        * @param destBuffer                 The destination buffer where the encrypted output goes into
        * @param destBufferLen              The length of destination buffer
        * @param destBufferRequiredLength   The length of destination buffer that will be required to hold encrypted output
        * @param paddingScheme              The RSA padding scheme to be used
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus encryptBuffer(const uint32_t&   publicKeyId,
                                const uint8_t*    sourceBuffer,
                                const uint32_t&   sourceBufferLen,
                                uint8_t*          destBuffer,
                                const uint32_t&   destBufferLen,
                                uint32_t*         destBufferRequiredLength,
                                const RsaPadding& paddingScheme);

        /**
        * Decrypts a buffer using the private key
        * @param privateKeyId               The private key Id from provider
        * @param sourceBuffer               The input buffer to be decrypted
        * @param sourceBufferLen            The length of the input buffer
        * @param destBuffer                 The destination buffer where the decrypted output goes into
        * @param destBufferLen              The length of destination buffer
        * @param destBufferRequiredLength   The length of destination buffer that will be required to hold decrypted output
        * @param paddingScheme              The RSA padding scheme to be used
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus decryptBuffer(const uint32_t&   privateKeyId,
                                const uint8_t*    sourceBuffer,
                                const uint32_t&   sourceBufferLen,
                                uint8_t*          destBuffer,
                                const uint32_t&   destBufferLen,
                                uint32_t*         destBufferRequiredLength,
                                const RsaPadding& paddingScheme);

        /**
         * Exports the public key from a key pair in the key cache
         * @param keyId               The key Id from provider representing the key to be exported
         * @param destBuffer          The destination buffer where public key goes into
         * @param destBufferLength    The length of destination buffer
         * @param modulusLength       The modulus length
         * @param exponentLength      The exponent length
         * @return                    SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus exportPublicKey(const uint32_t& keyId,
                                  uint8_t*        destBuffer,
                                  const uint32_t& destBufferLength,
                                  uint32_t*       modulusLength,
                                  uint32_t*       exponentLength);

        /**
        * Imports the public key in the key cache
        * @param keyId               The key Id from provider representing the key to be imported
        * @param modulusBuffer       The modulus buffer
        * @param modulusBufferLen    The length of the modulus buffer
        * @param exponentBuffer      The exponent buffer
        * @param exponentBufferLen   The length of exponent buffer
        * @return                    SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus importPublicKey(const uint32_t& keyId,
                                  uint8_t*        modulusBuffer,
                                  const uint32_t& modulusBufferLen,
                                  uint8_t*        exponentBuffer,
                                  const uint32_t& exponentBufferLen);

        /**
        * Computes the sha256 Hash of the formatted public key.
        * @param keyId          The key Id from provider.
        * @param destBuffer     The destination buffer where the hash goes into
        * @param destBufferLen  The length of the destination buffer
        * @param hashMode       The hash algorithm to be used
        * @return               SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus getPublicKeyHash(const uint32_t&  keyId,
                                   uint8_t*         destBuffer,
                                   const uint32_t&  destBufferLen,
                                   const HashMode&  hashMode);

        /**
        * Creates a signature of buffer passed
        * @param keyId                      The key Id from provider
        * @param sourceBuffer               The input buffer to be signed
        * @param sourceBufferLen            The length of the input buffer
        * @param destBuffer                 The destination buffer where the signed output goes into
        * @param destBufferLen              The length of the destination buffer
        * @param destBufferRequiredLength   The length destination buffer that will be required to hold signature output
        * @param hashAlgorithm              The hash algorithm to be used
        * @param rsaPadding                 The RSA padding scheme to be used
        * @param hashMode                   The hash mode to be used for hashing
        * @param salt                       The salt value to be used
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus sign(const uint32_t&   keyId,
                       const uint8_t*    sourceBuffer,
                       size_t            sourceBufferLen,
                       uint8_t*          destBuffer,
                       size_t            destBufferLen,
                       uint32_t*         destBufferRequiredLength,
                       const uint32_t    hashAlgorithm,
                       const RsaPadding& rsaPadding,
                       const HashMode&   hashMode,
                       const uint32_t&   salt);

        /**
        * Verifies the signature
        * @param keyId                      The key Id from provider used to decrypt the signature
        * @param sourceBuffer               The input buffer containing the hash
        * @param sourceBufferLen            The length of the input buffer
        * @param signatureBuffer            The signature buffer
        * @param signatureBufferLen         The length of the signature buffer
        * @param hashAlgorithm              The hash algorithm used while signing
        * @param rsaPadding                 The RSA padding scheme to be used
        * @param hashMode                   The hash mode to be used for hashing
        * @param salt                       The salt value to be used
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus verifySign(const uint32_t&   keyId,
                             const uint8_t*    sourceBuffer,
                             const uint32_t&   sourceBufferLen,
                             const uint8_t*    signatureBuffer,
                             const uint32_t&   signatureBufferLen,
                             const uint32_t&   hashAlgorithm,
                             const RsaPadding& rsaPadding,
                             const HashMode&   hashMode,
                             const uint32_t&   salt);

        /**
        * Platform binds an asymmetric key
        * @param keyId                      The key Id from provider
        * @param destBuffer                 The destination buffer where the platform bound data goes into
        * @param destBufferLen              The length of destination buffer
        * @param destBufferRequiredLength   The length of destination buffer that will be required to hold platform bound output
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus exportAsymmetricKeyPbind(const uint32_t&  keyId,
                                           uint8_t*         destBuffer,
                                           const uint32_t&  destBufferLen,
                                           uint32_t*        destBufferRequiredLength);

        /**
        * Un platform binds a buffer and adds the resulting key in the cache
        * @param publicKeyId        The public key Id from provider
        * @param privateKeyId       The private key Id from provider
        * @param sourceBuffer       The platform bound buffer
        * @param sourceBufferLen    The length of the input buffer
        * @return                   SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus importAsymmetricKeyPbind(uint32_t*        publicKeyId,
                                           uint32_t*        privateKeyId,
                                           const uint8_t*   sourceBuffer,
                                           const uint32_t&  sourceBufferLen);

        /**
        * Marks a key Id to track that it is used for wrapping another key
        * @param keyId      The key Id from provider
        */
        void markAsWrappingKey(const uint32_t& keyId);

        /**
        * Checks if the key Id passed is marked as wrapping key
        * @param keyId  The key Id from provider
        * @return       True if keyId is marked as a wrapping keyId, False otherwise
        */
        bool checkWrappingStatus(const uint32_t& keyId);

    private:
        bool encrypt(AsymmetricKey&     asymmetricKey,
                     const RsaPadding&  rsaPadding,
                     uint8_t*           destBuffer,
                     const uint32_t&    destBufferLen,
                     uint32_t*          destBufferRequiredLength,
                     const uint8_t*     sourceBuffer,
                     const uint32_t&    sourceBufferLen,
                     SgxCryptStatus&    status);

        bool decrypt(AsymmetricKey&     asymmetricKey,
                    const RsaPadding&   rsaPadding,
                    uint8_t*            destBuffer,
                    const uint32_t&     destBufferLen,
                    uint32_t*           destBufferRequiredLength,
                    const uint8_t*      sourceBuffer,
                    const uint32_t&     sourceBufferLen,
                    SgxCryptStatus&     status);

        bool getAsymmetricKey(const uint32_t&       keyId,
                              AsymmetricKey&        key,
                              const OperationType&  opType);

        bool signHashPss(AsymmetricKey&     asymKey,
                         const uint8_t*     sourceBuffer,
                         uint8_t*           destBuffer,
                         const int&         rsaBlockSize,
                         const EVP_MD*      evpMd,
                         const uint32_t&    salt,
                         SgxCryptStatus&    status);

        bool verifySignaturePss(const AsymmetricKey&  asymKey,
                                const uint8_t*        sourceBuffer,
                                const uint8_t*        signatureBuffer,
                                const int&            rsaBlockSize,
                                const EVP_MD*         evpMd,
                                const uint32_t&       salt,
                                SgxCryptStatus&       status);

        bool exportPlatformBoundKey(AsymmetricKey&      symKey,
                                    uint8_t*            destBuffer,
                                    const uint32_t&     destBufferLen,
                                    uint32_t*           destBufferWritten,
                                    SgxCryptStatus&     status);

        bool importPlatformBoundKey(AsymmetricKey&      symKey,
                                    const uint8_t*      sourceBuffer,
                                    const uint32_t&     sourceBufferLen,
                                    SgxCryptStatus&     status);

        AsymmetricKeyCache mAsymmetricPublicKeyCache;
        AsymmetricKeyCache mAsymmetricPrivateKeyCache;

        const uint32_t minRsaKeySize                        = 1024;
        const uint32_t maxRsaKeySize                        = 4096;
        const uint32_t rsaKeyFactorValue                    = 1024;
        const uint32_t rsaF4                                = 0x10001L;
        const uint32_t rsaOeapSchemeAdditionalPlaceHolder   = 41;
        const uint32_t rsaPkcs1SchemeAdditionalPlaceholder  = 11;
        const uint32_t rsaMaxPBindDataLength                = 0xF00L;
        const uint32_t rsaMaxUnsealDataLength               = 0xF00L;
    };
} //CryptoSgx

#endif //ASYMMETRIC_CRYPTO_H

