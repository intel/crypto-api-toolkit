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

#ifndef ENCLAVE_ASYMMETRIC_KEY_CACHE_H
#define ENCLAVE_ASYMMETRIC_KEY_CACHE_H

#include "ByteBuffer.h"
#include "CryptoEnclaveDefs.h"
#include "SgxFileUtils.h"

#include <map>
#include <openssl/rsa.h>

namespace CryptoSgx
{
    /**
     * Asymmetric key structure.
     */
    struct AsymmetricKey
    {
        RSA*            key{nullptr};
        std::string     keyFile;
        EC_KEY*         ecKey{nullptr};
        EVP_PKEY*       edKey{nullptr};
        bool            isUsedForWrapping = false;
        unsigned long   pairKeyId = 0;
    };

    /**
     * Class used to store Symmetric Keys by  into a cache.
     */
    class AsymmetricKeyCache
    {
    public:
        /**
         * Finds if a key Id has an associated key on the cache.
         * @param   keyId     The key Id from provider used to decrypt the signature
         * @return           True if the key for the key Id was found on the cache, false otherwise.
         */
        bool find(const uint32_t& keyId) const;

        /**
         * Gets a key from the cache.
         * @param   keyId           The key Id from provider used to decrypt the signature
         * @return  AsymmetricKey   The asymmetric key corresponding to the key Id passed
         */
        AsymmetricKey get(const uint32_t& keyId) const;

        /**
         * Adds a key for a keyId.
         * @param keyId             The key Id.
         * @param asymmetricKey     The key associated with key Id passed.
         */
        void add(const uint32_t& keyId, const AsymmetricKey& asymmetricKey);

        /**
         * Removes a key from the cache.
         * @param   keyId   The keyId
         * @return          True if success, false otherwise.
         */
        bool remove(const uint32_t& keyId, bool removeTokenFile = true);

        /**
         * Clears all the keys.
         */
         void clear();

         /**
         * Returns the number of keys in the cache
         */
         uint32_t count() const;

         bool isEcKey(const uint32_t& keyId) const;

         bool isRsaKey(const uint32_t& keyId) const;

         bool isEdKey(const uint32_t& keyId) const;

        uint32_t findKeyIdForPairKeyId(const unsigned long& pairKeyId) const;      

    private:
        struct AsymmetricKeyData
        {
            AsymmetricKey   data;

            AsymmetricKeyData();
            AsymmetricKeyData(const AsymmetricKey& asymmetricKey);
        };

        typedef std::map<const uint32_t, AsymmetricKeyData> AsymmetricKeyCacheCollection;
        typedef AsymmetricKeyCacheCollection::iterator  CacheCollectionIterator;
        typedef AsymmetricKeyCacheCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        AsymmetricKeyCacheCollection mCache;
    };

} //CryptoSgx

#endif //ASYMMETRIC_KEY_CACHE_H

