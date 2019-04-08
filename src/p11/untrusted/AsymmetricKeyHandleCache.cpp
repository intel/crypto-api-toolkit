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

#include "AsymmetricKeyHandleCache.h"
#include <cstddef>
#include <map>

namespace P11Crypto
{
    std::mutex AsymmetricKeyHandleCache::mCacheMutex;

    //---------------------------------------------------------------------------------------------
    std::shared_ptr<AsymmetricKeyHandleCache> AsymmetricKeyHandleCache::getAsymmetricKeyHandleCache()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        std::shared_ptr<AsymmetricKeyHandleCache> asymmetricKeyHandleCache = std::make_shared<AsymmetricKeyHandleCache>();

        ulock.unlock();
        return asymmetricKeyHandleCache;
    }

    //---------------------------------------------------------------------------------------------
    AsymmetricKeyHandleCache::AsymmetricKeyData::AsymmetricKeyData()
        : data({})
    {

    }

    //---------------------------------------------------------------------------------------------
    AsymmetricKeyHandleCache::AsymmetricKeyData::AsymmetricKeyData(const AsymmetricKey& asymmetricKey)
        : data(asymmetricKey)
    {

    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyHandleCache::find(const uint32_t& asymmetricKeyId) const
    {
        bool result = false;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        result = (0 != mCache.count(asymmetricKeyId));

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    uint32_t AsymmetricKeyHandleCache::count() const
    {
        uint32_t count = 0;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        count = mCache.size();

        ulock.unlock();
        return count;
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricKeyHandleCache::getKeyHandlesInSession(const uint32_t&         sessionHandle,
                                                          std::vector<uint32_t>&  keyHandles)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator = mCache.begin();
        while (iterator != mCache.end())
        {
            if (sessionHandle == iterator->second.data.sessionHandle)
            {
                uint32_t keyHandle = iterator->first;
                keyHandles.push_back(keyHandle);
            }

            ++iterator;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyHandleCache::get(const uint32_t& asymmetricKeyId,
                                       AsymmetricKey&  asymmetricKey) const
    {
        bool result = false;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(asymmetricKeyId);
        if (iterator != mCache.end())
        {
            asymmetricKey = iterator->second.data;
            result = true;
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricKeyHandleCache::add(const uint32_t&      asymmetricKeyId,
                                       const AsymmetricKey& asymmetricKey)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache[asymmetricKeyId] = asymmetricKey;

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyHandleCache::remove(const uint32_t& asymmetricKeyId)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(asymmetricKeyId);
        auto retValue = iterator != mCache.end();
        if (retValue)
        {
            mCache.erase(iterator);
        }
        ulock.unlock();

        return retValue;
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricKeyHandleCache::clear()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache.clear();

        ulock.unlock();
    }
}