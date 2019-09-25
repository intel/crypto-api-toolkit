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

#ifndef ENCLAVE_SYMMETRIC_KEY_CACHE_H
#define ENCLAVE_SYMMETRIC_KEY_CACHE_H

#include <map>

#include "ByteBuffer.h"
#include "SgxFileUtils.h"

namespace CryptoSgx
{
    /**
     * Symmetric Key Structure.
     */
    struct SymmetricKey
    {
        ByteBuffer  key;
        std::string keyFile;
        bool        isUsedForWrapping = false;
    };

    /**
     * Class used to store Symmetric Keys by  into a cache.
     */
    class SymmetricKeyCache
    {
    public:
        /**
         * Finds if a key Id has an associated key on the cache.
         * @param  keyId  The key Id to be found.
         * @return        True if the key for keyId was found on the cache, false otherwise.
         */
        bool find(const uint32_t keyId) const;

        /**
         * Gets a key from the cache.
         * @param  keyId  The key Id to be found.
         * @return        The symmetric key for the given key Id or an exception if the  was not found.
         */
        SymmetricKey get(const uint32_t keyId) const;

        /**
         * Adds a key for a key Id
         * @param  keyId  The key Id.
         * @param  key    The symmetric key to be added into the cache.
         */
        void add(const uint32_t keyId, const SymmetricKey& key);

        /**
         * Removes an key from the cache.
         * @param  keyId    The key Id to be found.
         * @return          True if success, false otherwise.
         */
        bool remove(const uint32_t keyId, bool removeTokenFile = true);

        /**
         * Clears all the keys.
         */
         void clear();

         /**
         * Returns the number of keys.
         */
         uint32_t count() const;

    private:
        struct SymKeyData
        {
            SymmetricKey data;

            SymKeyData();
            SymKeyData(const SymmetricKey& key);
        };

        typedef std::map<const uint32_t, SymKeyData> KeyCacheCollection;
        typedef KeyCacheCollection::iterator CacheCollectionIterator;
        typedef KeyCacheCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        KeyCacheCollection mCache;
    };

} //CryptoSgx

#endif //SYMMETRIC_KEY_CACHE_H

