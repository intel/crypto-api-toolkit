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

#ifndef HASH_HANDLE_CACHE
#define HASH_HANDLE_CACHE

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "CryptoEnclaveDefs.h"
#include "SessionHandleCache.h"

namespace P11Crypto
{
    struct HashState
    {
        uint32_t   sessionHandle;
    };

    class HashHandleCache
    {
    public:
        static std::shared_ptr<HashHandleCache> getHashHandleCache();

        /**
        * Finds if a hash handle has an associated HashState on the cache.
        * @param    hashHandle  The hash handle.
        * @return   bool        True if the HashState for the hash handle was found on the cache, false otherwise.
        */
        bool find(const uint32_t& hashHandle) const;

        /**
        * Gets a hash state from the cache.
        * @param    hashHandle  The hash handle.
        * @param    hashState   The provider's hash state corresponding to hashHandle.
        * @return   bool        True if the hash state for the hash handle was found on the cache, false otherwise.
        */
        bool get(const uint32_t& hashHandle, HashState& hashState) const;

        /**
        * Adds a hash state for a hash handle.
        * @param hashHandle  The hash handle.
        * @param hashState   The associated hash state.
        */
        void add(const uint32_t& hashHandle, const HashState& hashState);

        /**
        * Removes a hashHandle from the cache.
        * @param    hashHandle  The hashHandle.
        * @return   bool        True if the operation is success, false otherwise.
        */
        bool remove(const uint32_t& hashHandle);

        /**
        * Clears all the hash handles from the cache.
        */
        void clear();

        /**
        * Returns the number of hash handles in the cache
        */
        uint32_t count() const;

        /**
        * Returns the hashHandles associated with session handle passed.
        * @param sessionHandle  The session handle passed.
        * @param hashHandles    Vector that gets populated with hash handles associated with sessionHandle.
        */
        void getHashHandlesInSession(const uint32_t&        sessionHandle,
                                     std::vector<uint32_t>& hashHandles);
    private:
        struct HashStateData
        {
            HashState  data;

            HashStateData();
            HashStateData(const HashState& hashState);
        };

        typedef std::map<uint32_t, HashStateData> HashStateDataCollection;
        typedef HashStateDataCollection::iterator  CacheCollectionIterator;
        typedef HashStateDataCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        HashStateDataCollection mCache;
        static std::mutex mCacheMutex;
    };
} //P11Crypto
#endif // HASH_HANDLE_CACHE

