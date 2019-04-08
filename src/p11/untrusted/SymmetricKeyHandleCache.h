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

#ifndef SYMMETRIC_KEY_HANDLE_CACHE
#define SYMMETRIC_KEY_HANDLE_CACHE

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "CryptoEnclaveDefs.h"
#include "SessionHandleCache.h"

namespace P11Crypto
{
    struct SymmetricKey
    {
        uint32_t sessionHandle;
    };

    class SymmetricKeyHandleCache
    {
    public:
        static std::shared_ptr<SymmetricKeyHandleCache> getSymmetricKeyHandleCache();

        /**
        * Finds if a key Id has an associated SymmetricKey on the cache.
        * @param    keyHandle   The symmetric key Id.
        * @return   bool        True if the key for the key Id was found on the cache, false otherwise.
        */
        bool find(const uint32_t& keyHandle) const;

        /**
        * Gets a key from the cache.
        * @param    keyHandle  The symmetric key Id from the provider.
        * @param    symKey     The provider's symmetric key corresponding to keyHandle.
        * @return   bool       True if the key for the key Id was found on the cache, false otherwise.
        */
        bool get(const uint32_t& keyHandle, SymmetricKey& symKey) const;

        /**
        * Adds a key for a handle.
        * @param keyHandle  The symmetric key Id.
        * @param symKey     The associated key.
        */
        void add(const uint32_t& keyHandle, const SymmetricKey& symKey);

        /**
        * Removes a key from the cache.
        * @param    keyHandle   The symmetric keyHandle
        * @return   bool        True if the key for the key Id was found and removed on the cache, false otherwise.
        */
        bool remove(const uint32_t& keyHandle);

        /**
        * Clears all the symmetric keys from the cache.
        */
        void clear();

        /**
        * Returns the number of symmetric keys in the cache
        */
        uint32_t count() const;

        /**
        * Returns the keyHandles associated with session handle passed.
        * @param sessionHandle  The session handle passed.
        * @param keyHandles     Vector that gets populated with key Ids associated with sessionHandle.
        */
        void getKeyHandlesInSession(const uint32_t&         sessionHandle,
                                    std::vector<uint32_t>&  keyHandles);

    private:
        struct SymmetricKeyData
        {
            SymmetricKey data;

            SymmetricKeyData();
            SymmetricKeyData(const SymmetricKey& symKey);
        };

        typedef std::map<uint32_t, SymmetricKeyData> SymmetricKeyDataDataCollection;
        typedef SymmetricKeyDataDataCollection::iterator  CacheCollectionIterator;
        typedef SymmetricKeyDataDataCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        SymmetricKeyDataDataCollection mCache;
        static std::mutex mCacheMutex;
    };
} //P11Crypto
#endif // SYMMETRIC_KEY_HANDLE_CACHE

