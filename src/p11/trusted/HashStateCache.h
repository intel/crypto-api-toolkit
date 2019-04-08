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

#ifndef ENCLAVE_HASH_STATE_CACHE_H
#define ENCLAVE_HASH_STATE_CACHE_H

#include <map>

#include "ByteBuffer.h"
#include "CryptoEnclaveDefs.h"

namespace CryptoSgx
{
    /**
     * Hash State Structure.
     */
    struct HashState
    {
        HashMode    hashMode;
        bool        hmac;
        bool        valid;
        ByteBuffer  ippCtx;
    };

    /**
     * Class used to store Hash States into a cache.
     */
    class HashStateCache
    {
    public:
        /**
         * Finds if a hash Id has an associated state on the cache.
         * @param  hashId   The hash Id to be found.
         * @return          True if the key for the  was found on the cache, false otherwise.
         */
        bool find(const uint32_t& hashId) const;

        /**
         * Gets a state from the cache.
         * @param   hashId      The hash Id of the state to be retrieved.
         * @return  HashState   The hash state for the given hash Id.
         */
        HashState get(const uint32_t& hashId) const;

        /**
         * Adds a state for a hash Id.
         * @param hashId        The hash Id.
         * @param hashState     The hash state to be added to the cache.
         */
        void add(const uint32_t& hashId, const HashState& hashState);

        /**
         * Removes a hash state from the cache.
         * @param   hashId  The hash Id.
         * @return          True if success, false otherwise.
         */
        bool remove(const uint32_t& hashId);

        /**
         * Clears all the states.
         */
         void clear();

         /**
         * Returns the number of states.
         */
         uint32_t count() const;

    private:
        struct HashStateData
        {
            HashState    data;

            HashStateData();
            HashStateData(const HashState& hashState);
        };

        typedef std::map<const uint32_t, HashStateData> HashStateCacheCollection;
        typedef HashStateCacheCollection::iterator  CacheCollectionIterator;
        typedef HashStateCacheCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        HashStateCacheCollection mCache;
    };

} //CryptoSgx

#endif //HASH_STATE_CACHE_H

