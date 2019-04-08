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

#include "HashHandleCache.h"
#include <cstddef>
#include <map>

namespace P11Crypto
{
    std::mutex HashHandleCache::mCacheMutex;

    //---------------------------------------------------------------------------------------------
    std::shared_ptr<HashHandleCache> HashHandleCache::getHashHandleCache()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        std::shared_ptr<HashHandleCache> hashHandleCache = std::make_shared<HashHandleCache>();

        ulock.unlock();
        return hashHandleCache;
    }

    //---------------------------------------------------------------------------------------------
    HashHandleCache::HashStateData::HashStateData()
        : data({})
    {

    }

    //---------------------------------------------------------------------------------------------
    HashHandleCache::HashStateData::HashStateData(const HashState& HashState)
        : data(HashState)
    {

    }

    //---------------------------------------------------------------------------------------------
    bool HashHandleCache::find(const uint32_t& hashHandle) const
    {
        bool result = false;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        result = (0 != mCache.count(hashHandle));

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    uint32_t HashHandleCache::count() const
    {
        uint32_t count = 0;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        count = mCache.size();

        ulock.unlock();
        return count;
    }

    //---------------------------------------------------------------------------------------------
    void HashHandleCache::getHashHandlesInSession(const uint32_t&         sessionHandle,
                                                  std::vector<uint32_t>&  hashHandles)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            if (sessionHandle == iterator->second.data.sessionHandle)
            {
                uint32_t hashHandle = iterator->first;
                hashHandles.push_back(hashHandle);
            }

            ++iterator;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool HashHandleCache::get(const uint32_t& hashHandle, HashState& hashState) const
    {
        bool result = false;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(hashHandle);
        if (iterator != mCache.end())
        {
            hashState = iterator->second.data;
            result    = true;
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    void HashHandleCache::add(const uint32_t& hashHandle, const HashState& HashState)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache[hashHandle] = HashState;

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool HashHandleCache::remove(const uint32_t& hashHandle)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(hashHandle);
        auto retValue = iterator != mCache.end();
        if (retValue)
        {
            mCache.erase(iterator);
        }

        ulock.unlock();
        return retValue;
    }

    //---------------------------------------------------------------------------------------------
    void HashHandleCache::clear()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache.clear();

        ulock.unlock();
    }
}