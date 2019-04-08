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

#ifndef ENCLAVE_IPP_STATE_CACHE_H
#define ENCLAVE_IPP_STATE_CACHE_H

#pragma once

#include <map>

#include "ByteBuffer.h"
#include "CryptoEnclaveDefs.h"
#include "IppContextHandle.h"
#include "CryptParams.h"

namespace CryptoSgx
{
    /**
    *  State Structure.
    */
    struct IppCtxState
    {
        IppsAESSpec*    ippCtx;
        CryptParams     cryptParams;
    };

    /**
    * Class used to store IPP States into a cache.
    */
    class IppStateCache
    {
    public:
        /**
        * Finds if a key Id has an associated state on the cache.
        * @param  keyId     The key Id to be found.
        * @return           True if the ipp state was found on the cache, false otherwise.
        */
        bool find(const uint32_t keyId) const;

        /**
        * Gets a state from the cache.
        * @param  keyId     The keyId of the state to be retrieved.
        * @return           The ipp state for given key Id.
        */
        IppCtxState get(const uint32_t keyId) const;

        /**
        * Adds an ipp state for a key Id into the cache.
        * @param keyId          The key Id.
        * @param ippCtxState    The associated pp state.
        */
        void add(const uint32_t keyId, const IppCtxState& ippCtxState);

        /**
        * Removes an ipp state corresponding to a key Id from the cache.
        * @param keyId      The key Id.
        * @return           True if success, false otherwise.
        */
        bool remove(const uint32_t keyId);

        /**
        * Clears all the states.
        */
        void clear();

        /**
        * Returns the number of states in the cache.
        */
        uint32_t count() const;

    private:
        struct IppCtxStateData
        {
            IppCtxState data;

            IppCtxStateData();
            IppCtxStateData(const IppCtxState& ippCtxState);
        };

        typedef std::map<const uint32_t, IppCtxStateData> IppCtxStateCacheCollection;
        typedef IppCtxStateCacheCollection::iterator  CacheCollectionIterator;
        typedef IppCtxStateCacheCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        IppCtxStateCacheCollection mCache;
    };

} //CryptoSgx

#endif //ENCLAVE_IPP_STATE_CACHE_H

