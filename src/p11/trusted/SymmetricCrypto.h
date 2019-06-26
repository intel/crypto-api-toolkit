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

#ifndef ENCLAVE_SYMMETRIC_CRYPTO_H
#define ENCLAVE_SYMMETRIC_CRYPTO_H

#include "EVPEncrypt.h"
#include "EVPDecrypt.h"
#include "IppEncrypt.h"
#include "IppDecrypt.h"
#include "SymmetricKeyCache.h"
#include "IppStateCache.h"
#include <functional>

namespace CryptoSgx
{
    typedef std::pair<BlockCipherMode, SymmetricKeySize> cipherModeKeyLengthPair;
    typedef std::map<cipherModeKeyLengthPair, std::function<const EVP_CIPHER*(void)>> EvpCipherCollection;

    static EvpCipherCollection evpCipherFn  = {
                                                    { std::make_pair(BlockCipherMode::ctr, SymmetricKeySize::keyLength128), EVP_aes_128_ctr },
                                                    { std::make_pair(BlockCipherMode::ctr, SymmetricKeySize::keyLength192), EVP_aes_192_ctr },
                                                    { std::make_pair(BlockCipherMode::ctr, SymmetricKeySize::keyLength256), EVP_aes_256_ctr },
                                                    { std::make_pair(BlockCipherMode::gcm, SymmetricKeySize::keyLength128), EVP_aes_128_gcm },
                                                    { std::make_pair(BlockCipherMode::gcm, SymmetricKeySize::keyLength192), EVP_aes_192_gcm },
                                                    { std::make_pair(BlockCipherMode::gcm, SymmetricKeySize::keyLength256), EVP_aes_256_gcm },
                                                    { std::make_pair(BlockCipherMode::cbc, SymmetricKeySize::keyLength128), EVP_aes_128_cbc },
                                                    { std::make_pair(BlockCipherMode::cbc, SymmetricKeySize::keyLength192), EVP_aes_192_cbc },
                                                    { std::make_pair(BlockCipherMode::cbc, SymmetricKeySize::keyLength256), EVP_aes_256_cbc },
                                               };

    /**
     * Symmetric encryption implementation.
     */
    class SymmetricCrypto
    {
    public:
        /**
         * Constructor.
         */
        SymmetricCrypto() = default;

        SymmetricCrypto(const SymmetricCrypto& other) = delete;

        SymmetricCrypto& operator=(const SymmetricCrypto& other) = delete;

        /**
         * Generate the symmetric key for the input key size
         * @param keyId         The key Id from provider.
         * @param inputKeySize  The symmetric key size.
         * @return              SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus generateSymmetricKey(const uint32_t&         keyId,
                                       const SymmetricKeySize& inputKeySize);
        /**
         * Adds a symmetric key into cache.
         * @param keyId     The key Id from provider
         * @param symKey    The symmetric key.
         * @return          SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus addSymmetricKey(const uint32_t&       keyId,
                                  const SymmetricKey&   symKey);

        /**
         * Removes a symmetric key for the given key Id.
         * @param keyId     The key Id from provider
         * @return          SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus removeSymmetricKey(const uint32_t& keyId);

        /**
         * Adds an EVP state into the cache
         * @param   keyId               The key Id
         * @param   evpContext          The EVP context
         * @param   cipherMode          The cipher mode used
         * @param   tagBits             The tag size in bits
         * @param   padding             Parameter to indicate the use of padding, used for CBC operations
         */
        void addEVPCtxState(const uint32_t&         keyId,
                            EVPContextHandle&       evpContext,
                            const BlockCipherMode&  cipherMode,
                            const uint32_t&         tagBits,
                            const uint32_t&         padding);

        /**
         * Adds an IPP state into the cache
         * @param   keyId               The key Id
         * @param   ippContext          The IPP context
         * @param   cipherMode          The cipher mode used
         * @param   iv                  The initialization vector used
         * @param   ivSize              The size of iv in bytes
         * @param   counterBits         The counter size in bits
         */
        void addIppCtxState(const uint32_t&        keyId,
                            IppContextHandle&      ippContext,
                            const BlockCipherMode& cipherMode,
                            const uint8_t*         iv,
                            const uint32_t&        ivSize,
                            const int&             counterBits);

        /**
         * Gets an EVP state from the cache
         * @param   keyId       The key Id
         * @param   evpContext  The EVP context
         * @return  bool        True if the EVP state associated with keyId is present, false otherwise
         */
        bool getEVPCtxState(const uint32_t& keyId,
                            EVPCtxState*    evpContext);

        /**
         * Gets an IPP state from the cache
         * @param   keyId           The key Id
         * @param   ippCtxContext   The IPP context
         * @return  bool            True if the IPP state associated with keyId is present, false otherwise
         */
        bool getIppCtxState(const uint32_t& keyId,
                            IppCtxState*    ippCtxContext);

        /**
        * Platform binds a symmetric key associated with Key Id passed.
        * @param keyId                  The key Id from the provider
        * @param destBuffer             The destination buffer where the platform bound data goes into
        * @param destBufferLen          The length of destination buffer
        * @param destBufferWritten      The length of destination buffer that will be required to hold decrypted output
        * @return                       SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus exportSymmetricKeyPbind(const uint32_t&     keyId,
                                          uint8_t*            destBuffer,
                                          const uint32_t&     destBufferLen,
                                          uint32_t*           destBufferWritten);

        /**
        * Unseals the platform bound data and adds it to the cache.
        * @param keyId              The key Id from the provider
        * @param sourceBuffer       The input buffer to be unsealed and imported
        * @param sourceBufferLen    The length of the input buffer
        * @return                   SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus importSymmetricKeyPbind(const uint32_t&     keyId,
                                          const uint8_t*      sourceBuffer,
                                          const uint32_t&     sourceBufferLen);

#ifdef IMPORT_RAW_KEY
        /**
        * Imports a buffer into the cache
        * @param keyId              The key Id from the provider
        * @param sourceBuffer       The input buffer to be imported
        * @param sourceBufferLen    The length of the input buffer
        * @return                   SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus importRawKey(const uint32_t&    keyId,
                               const uint8_t*     sourceBuffer,
                               const uint16_t&    sourceBufferLen);
#endif

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

        /**
         * Clears all the keys.
         */
         void clearKeys();

        /**
        * Gets the symmetric key associated with the key Id passed
        * @param keyId     The key Id from the provider
        * @param key       The Symmetric Key to be populated
        * @return          True is the operation was successful, false otherwise
        */
        bool getSymmetricKey(const uint32_t&    keyId,
                             SymmetricKey*      key);

        /**
         * Initializes the encryption process.
         * @param keyId         The key Id
         * @param cipherMode    The cipher mode to be used for encryption
         * @param iv            The initialization vector to be used
         * @param ivSize        The size of iv in bytes
         * @param aad           The additional authentication data, to be used for GCM operations
         * @param aadSize       The size of aad in bytes
         * @param padding       Parameter to indicate the use of padding, used for CBC operations
         * @param tagBits       The size of tag in bits
         * @param counterBits   The size of counter in bits
         * @return              SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus encryptInit(const uint32_t&         keyId,
                              const BlockCipherMode&  cipherMode,
                              const uint8_t*          iv,
                              const uint32_t&         ivSize,
                              const uint8_t*          aad,
                              const uint32_t&         aadSize,
                              const uint32_t&         padding,
                              const uint32_t&         tagBits,
                              const int&              counterBits);

        /**
        * Continues an encryption operation
        * @param keyId                      The key Id from the provider
        * @param sourceBuffer               The input buffer to be encrypted
        * @param sourceBufferLen            The length of the input buffer
        * @param destBuffer                 The destination buffer where the encrypted output goes into
        * @param destBufferLen              The length of destination buffer
        * @param bytesEncrypted             The number of bytes encrypted
        * @param doFullEncryptWithoutFinal  Boolean value, if true, the operation is also finalized by calling encryptFinal() in this function
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus encryptUpdate(const uint32_t&    keyId,
                                const uint8_t*     sourceBuffer,
                                const uint32_t&    sourceBufferLen,
                                uint8_t*           destBuffer,
                                const uint32_t&    destBufferLen,
                                uint32_t*          bytesEncrypted,
                                bool               doFullEncryptWithoutFinal = false);

        /**
         * Finalizes a multi-part encryption process
         * @param keyId             The key Id from provider
         * @param destBuffer        A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param encryptedBytes    On exit, the length in bytes of the encrypted data.
         * @return                  SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus encryptFinal(const uint32_t&    keyId,
                               uint8_t*           destBuffer,
                               uint32_t*          bytesEncrypted);

        /**
         * Initializes the decryption process.
         * @param keyId         The key Id
         * @param cipherMode    The cipher mode to be used for decryption
         * @param iv            The initialization vector to be used
         * @param ivSize        The size of iv in bytes
         * @param aad           The additional authentication data, to be used for GCM operations
         * @param aadSize       The size of aad in bytes
         * @param padding       Parameter to indicate the use of padding, used for CBC operations
         * @param tagBits       The size of tag in bits
         * @param counterBits   The size of counter in bits
         * @return              SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus decryptInit(const uint32_t&         keyId,
                              const BlockCipherMode&  cipherMode,
                              const uint8_t*          iv,
                              const uint32_t&         ivSize,
                              const uint8_t*          aad,
                              const uint32_t&         aadSize,
                              const uint32_t&         padding,
                              const uint32_t&         tagBits,
                              const int&              counterBits);

        /**
        * Continues a decryption operation
        * @param keyId                      The key Id from the provider
        * @param sourceBuffer               The input buffer to be decrypted
        * @param sourceBufferLen            The length of the input buffer
        * @param destBuffer                 The destination buffer where the decrypted output goes into
        * @param destBufferLen              The length of destination buffer
        * @param bytesDecrypted             The number of bytes decrypted
        * @param doFullDecryptWithoutFinal  Boolean value, if true, the operation is also finalized by calling decryptFinal() in this function
        * @return                           SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxStatus decryptUpdate(const uint32_t&    keyId,
                                const uint8_t*     sourceBuffer,
                                const uint32_t&    sourceBufferLen,
                                uint8_t*           destBuffer,
                                const uint32_t&    destBufferLen,
                                uint32_t*          bytesDecrypted,
                                bool               doFullDecryptWithoutFinal = false);

        /**
         * Finalizes a multi-part decryption process
         * @param keyId             The key Id from provider
         * @param destBuffer        A pointer to a buffer (previously allocated) where the decrypted data will be stored.
         * @param bytesDecrypted    On exit, the length in bytes of the decrypted data.
         * @return                  SgxStatus value - SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxStatus decryptFinal(const uint32_t&    keyId,
                               uint8_t*           destBuffer,
                               uint32_t*          bytesDecrypted);

        /**
         * Initializes the IPP encryption process.
         * @param   keyId               The key Id
         * @param   cryptParams         The crypto parameters needed for encryption
         * @return  SgxCryptStatus      SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus encryptInitIpp(const uint32_t&       keyId,
                                      const CryptParams&    cryptParams);

        /**
         * Initializes the EVP encryption process.
         * @param   keyId               The key Id
         * @param   cryptParams         The crypto parameters needed for encryption
         * @return  SgxCryptStatus      SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus encryptInitEvp(const uint32_t&       keyId,
                                      const CryptParams&    cryptParams);

        /**
        * Continues an EVP encryption operation
        * @param    keyId                      The key Id from the provider
        * @param    sourceBuffer               The input buffer to be encrypted
        * @param    sourceBufferLen            The length of the input buffer
        * @param    destBuffer                 The destination buffer where the encrypted output goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    bytesEncrypted             The number of bytes encrypted
        * @param    doFullEncryptWithoutFinal  Boolean value, if true, the operation is also finalized by calling encryptFinal() in this function
        * @return   SgxCryptStatus             SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxCryptStatus encryptUpdateEvp(const uint32_t&     keyId,
                                        const uint8_t*      sourceBuffer,
                                        const uint32_t&     sourceBufferLen,
                                        uint8_t*            destBuffer,
                                        const uint32_t&     destBufferLen,
                                        uint32_t*           destBufferWritten,
                                        bool                doFullEncryptWithoutFinal = false);

        /**
        * Continues an IPP encryption operation
        * @param    keyId                      The key Id from the provider
        * @param    sourceBuffer               The input buffer to be encrypted
        * @param    sourceBufferLen            The length of the input buffer
        * @param    destBuffer                 The destination buffer where the encrypted output goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    bytesEncrypted             The number of bytes encrypted
        * @param    doFullEncryptWithoutFinal  Boolean value, if true, the operation is also finalized by calling encryptFinal() in this function
        * @return   SgxCryptStatus             SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxCryptStatus encryptUpdateIpp(const uint32_t&     keyId,
                                        const uint8_t*      sourceBuffer,
                                        const uint32_t&     sourceBufferLen,
                                        uint8_t*            destBuffer,
                                        const uint32_t&     destBufferLen,
                                        uint32_t*           destBufferWritten,
                                        IppCtxState*        ippCtxState,
                                        bool                doFullEncryptWithoutFinal = false);

        /**
         * Finalizes an EVP multi-part encryption process
         * @param   keyId             The key Id from provider
         * @param   destBuffer        A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param   encryptedBytes    On exit, the length in bytes of the encrypted data.
         * @return  SgxCryptStatus    SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus encryptFinalEvp(const uint32_t& keyId,
                                       uint8_t*        destBuffer,
                                       uint32_t*       encryptedBytes);

        /**
         * Finalizes an IPP multi-part encryption process
         * @param   keyId             The key Id from provider
         * @param   destBuffer        A pointer to a buffer (previously allocated) where the encrypted data will be stored.
         * @param   encryptedBytes    On exit, the length in bytes of the encrypted data.
         * @return  SgxCryptStatus    SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus encryptFinalIpp(const uint32_t& keyId,
                                       uint8_t*        destBuffer,
                                       uint32_t*       destBufferWritten,
                                       IppCtxState*    ippCtxState);

        /**
         * Initializes the IPP decryption process.
         * @param   keyId               The key Id
         * @param   cryptParams         The crypto parameters needed for decryption
         * @return  SgxCryptStatus      SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus decryptInitIpp(const uint32_t&       keyId,
                                      const CryptParams&    cryptParams);

        /**
         * Initializes the EVP decryption process.
         * @param   keyId               The key Id
         * @param   cryptParams         The crypto parameters needed for decryption
         * @return  SgxCryptStatus      SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus decryptInitEvp(const uint32_t&       keyId,
                                      const CryptParams&    cryptParams);

        /**
        * Continues an EVP decryption operation
        * @param    keyId                      The key Id from the provider
        * @param    sourceBuffer               The input buffer to be decrypted
        * @param    sourceBufferLen            The length of the input buffer
        * @param    destBuffer                 The destination buffer where the decrypted output goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    bytesDecrypted             The number of bytes decrypted
        * @param    doFullDecryptWithoutFinal  Boolean value, if true, the operation is also finalized by calling decryptFinal() in this function
        * @return   SgxCryptStatus             SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxCryptStatus decryptUpdateEvp(const uint32_t& keyId,
                                        const uint8_t*  sourceBuffer,
                                        const uint32_t& sourceBufferLen,
                                        uint8_t*        destBuffer,
                                        const uint32_t& destBufferLen,
                                        uint32_t*       bytesDecrypted,
                                        bool            doFullDecryptWithoutFinal = false);

        /**
        * Continues an IPP decryption operation
        * @param    keyId                      The key Id from the provider
        * @param    sourceBuffer               The input buffer to be decrypted
        * @param    sourceBufferLen            The length of the input buffer
        * @param    destBuffer                 The destination buffer where the decrypted output goes into
        * @param    destBufferLen              The length of destination buffer
        * @param    bytesDecrypted             The number of bytes decrypted
        * @param    doFullDecryptWithoutFinal  Boolean value, if true, the operation is also finalized by calling decryptFinal() in this function
        * @return   SgxCryptStatus             SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
        */
        SgxCryptStatus decryptUpdateIpp(const uint32_t& keyId,
                                        const uint8_t*  sourceBuffer,
                                        const uint32_t& sourceBufferLen,
                                        uint8_t*        destBuffer,
                                        const uint32_t& destBufferLen,
                                        uint32_t*       destBufferWritten,
                                        IppCtxState*    ippCtxState,
                                        bool            doFullDecryptWithoutFinal = false);

        /**
         * Finalizes an IPP multi-part decryption process
         * @param   keyId             The key Id from provider
         * @param   destBuffer        A pointer to a buffer (previously allocated) where the decrypted data will be stored
         * @param   bytesDecrypted    On exit, the length in bytes of the decrypted data
         * @param   ippCtxState       The IPP state of the ongoing operation
         * @return  SgxCryptStatus    SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus decryptFinalIpp(const uint32_t& keyId,
                                       uint8_t*        destBuffer,
                                       uint32_t*       bytesDecrypted,
                                       IppCtxState*    ippCtxState);

        /**
         * Finalizes an EVP multi-part decryption process
         * @param   keyId             The key Id from provider
         * @param   destBuffer        A pointer to a buffer (previously allocated) where the decrypted data will be stored
         * @param   bytesDecrypted    On exit, the length in bytes of the decrypted data
         * @return  SgxCryptStatus    SGX_CRYPT_STATUS_SUCCESS when success or error code otherwise
         */
        SgxCryptStatus decryptFinalEvp(const uint32_t& keyId,
                                       uint8_t*        destBuffer,
                                       uint32_t*       bytesDecrypted);

        /**
         * Clears the state associated with keyId, if any
         * @param   keyId  The key Id from provider
         */
        void clearState(const uint32_t& keyId);

    private:

        void fillCryptInitParams(CryptParams*           cryptParams,
                                 const BlockCipherMode& cipherMode,
                                 const ByteBuffer&      key,
                                 const uint8_t*         iv,
                                 const uint32_t&        ivSize,
                                 const uint8_t*         aad,
                                 const uint32_t&        aadSize,
                                 const uint32_t&        tagBits,
                                 const int&             counterBits,
                                 const uint32_t&        padding);

        bool allocateSymmetricKey(SymmetricKey*            symKeyStruct,
                                  const SymmetricKeySize&  keySize);

        bool populateSymmetricKey(SymmetricKey* symKey);

        bool exportRawKey(SymmetricKey&     symKey,
                          uint8_t*          destBuffer,
                          const uint32_t&   destBufferLen,
                          uint32_t*         destBufferWritten,
                          SgxCryptStatus*   status);

        bool exportPlatformBoundKey(const SymmetricKey& symKey,
                                    uint8_t*            destBuffer,
                                    const uint32_t&     destBufferLen,
                                    uint32_t*           destBufferWritten,
                                    SgxCryptStatus*     status);

        SymmetricKeyCache   mSymmetricKeyCache;
        EVPCtxStateCache    mEVPCtxStateCache;
        IppStateCache       mIppCtxStateCache;
    };
} //CryptoSgx

#endif //SYMMETRIC_CRYPTO_H

