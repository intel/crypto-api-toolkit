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

#ifndef ENCLAVE_SYMMETRIC_STATE_CACHE_H
#define ENCLAVE_SYMMETRIC_STATE_CACHE_H

#include <map>

#include "ByteBuffer.h"
#include "CryptoEnclaveDefs.h"
#include "EVPContextHandle.h"
#include "CryptParams.h"

namespace CryptoSgx
{
    /**
    * Symmetric State Structure.
    */
    struct EVPCtxState
    {
        EVP_CIPHER_CTX* evpCtx;
        CryptParams     cryptParams;
    };

    /**
    * Class used to store Symmetric Keys by  into a cache.
    */
    class EVPCtxStateCache
    {
    public:
        /**
        * Finds if a key Id has an associated state on the cache.
        * @param  keyId     The key Id to be found.
        * @return           True if the evp state was found on the cache, false otherwise.
        */
        bool find(const uint32_t keyId) const;

        /**
        * Gets a state from the cache.
        * @param  keyId     The keyId of the state to be retrieved.
        * @return           The evp state for given key Id.
        */
        EVPCtxState get(const uint32_t keyId) const;

        /**
        * Adds an evp state for a key Id into the cache.
        * @param keyId          The key Id.
        * @param evpCtxState    The associated evp state.
        */
        void add(const uint32_t keyId, const EVPCtxState& evpCtxState);

        /**
        * Removes an evp state corresponding to a key Id from the cache.
        * @param keyId      The key Id.
        * @return           True if success, false otherwise.
        */
        bool remove(const uint32_t keyId);

        /**
        * Clears all the states.
        */
        void clear();

        /**
        * Returns the number of states.
        */
        uint32_t count() const;

    private:
        struct EVPCtxStateData
        {
            EVPCtxState data;

            EVPCtxStateData();
            EVPCtxStateData(const EVPCtxState& evpCtxState);
        };

        typedef std::map<const uint32_t, EVPCtxStateData> EVPCtxStateCacheCollection;
        typedef EVPCtxStateCacheCollection::iterator  CacheCollectionIterator;
        typedef EVPCtxStateCacheCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        EVPCtxStateCacheCollection mCache;
    };

} //CryptoSgx

#endif //ENCLAVE_SYMMETRIC_STATE_CACHE_H

