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

#include "AttributeCache.h"
#include "Constants.h"

namespace P11Crypto
{
    std::mutex AttributeCache::mCacheMutex;

    //---------------------------------------------------------------------------------------------
    AttributeCache::AttributesData::AttributesData()
        : data({})
    {

    }

    //---------------------------------------------------------------------------------------------
    AttributeCache::AttributesData::AttributesData(const Attributes& attributes)
        : data(attributes)
    {

    }
    //---------------------------------------------------------------------------------------------
    std::shared_ptr<AttributeCache> AttributeCache::getAttributeCache()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        std::shared_ptr<AttributeCache> attributeCache = std::make_shared<AttributeCache>();

        ulock.unlock();
        return attributeCache;
    }

    //---------------------------------------------------------------------------------------------
    void AttributeCache::add(const uint32_t&   keyHandle,
                             const Attributes& keyAttributes)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache[keyHandle] = keyAttributes;

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeCache::find(const uint32_t& keyHandle)
    {
        bool result = false;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        result = (0 != mCache.count(keyHandle));

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeCache::isPrivateObject(const uint32_t& keyHandle)
    {
        bool       result = false;
        Attributes attributes;

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(keyHandle);
        if (iterator != mCache.end())
        {
            attributes = iterator->second.data;
            if (KeyAttribute::PRIVATE & attributes.attributeBitmask)
            {
                result = true;
            }
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeCache::isTokenObject(const uint32_t& keyHandle)
    {
        bool       result = false;
        Attributes attributes;

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(keyHandle);
        if (iterator != mCache.end())
        {
            attributes = iterator->second.data;
            if (KeyAttribute::TOKEN & attributes.attributeBitmask)
            {
                result = true;
            }
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeCache::isSessionObject(const uint32_t& keyHandle)
    {
        bool result = false;

        result = !isTokenObject(keyHandle);

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeCache::isAttributeSet(const uint32_t& keyHandle, const KeyAttribute keyAttribute)
    {
        bool       result = false;
        Attributes attributes;

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(keyHandle);
        if (iterator != mCache.end())
        {
            attributes = iterator->second.data;
            if (keyAttribute & attributes.attributeBitmask)
            {
                result = true;
            }
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    void AttributeCache::getAllKeyHandles(std::vector<uint32_t>& keyHandles)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            keyHandles.push_back(iterator->first);
            ++iterator;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    void AttributeCache::getAttributes(const uint32_t& keyHandle, Attributes& keyAttributes)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(keyHandle);
        if (iterator != mCache.end())
        {
            keyAttributes = iterator->second.data;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeCache::remove(const uint32_t& keyHandle)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(keyHandle);
        auto retValue = iterator != mCache.end();
        if (retValue)
        {
            mCache.erase(iterator);
        }

        ulock.unlock();
        return retValue;
    }
}