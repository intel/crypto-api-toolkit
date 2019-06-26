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

#include "ObjectCache.h"

namespace P11Crypto
{
    std::mutex ObjectCache::mCacheMutex;

    //---------------------------------------------------------------------------------------------
    ObjectCache::ObjectCache()
    {

    }

    //---------------------------------------------------------------------------------------------
    ObjectCache::~ObjectCache()
    {

    }

    //---------------------------------------------------------------------------------------------
    bool ObjectCache::getObjectParams(const uint32_t& objectHandle, ObjectParameters* objectParams)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (objectParams && mCache.find(objectHandle) != mCache.end())
        {
            *objectParams = mCache[objectHandle];
            return true;
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    void ObjectCache::add(const uint32_t& objectHandle, const ObjectParameters& objectParams)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        mCache[objectHandle] = objectParams;
    }

    //---------------------------------------------------------------------------------------------
    void ObjectCache::remove(const uint32_t& objectHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        auto it = mCache.find(objectHandle);
        if (it != mCache.end())
        {
            auto objectParams = it->second;

            if (objectParams.objectState != ObjectState::IN_USE)
            {
                mCache.erase(it);
            }
        }
    }

    //---------------------------------------------------------------------------------------------
    void ObjectCache::clear()
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        mCache.clear();
    }

    //---------------------------------------------------------------------------------------------
    CK_KEY_TYPE ObjectCache::getKeyType(const uint32_t& keyHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        CK_KEY_TYPE keyType = CKK_VENDOR_DEFINED;

        ObjectParameters objectParams;

        if (mCache.find(keyHandle) != mCache.end())
        {
            objectParams = mCache[keyHandle];

            auto ulongAttrIter = std::find_if(objectParams.ulongAttributes.cbegin(), objectParams.ulongAttributes.cend(), [](const UlongAttributeType& p)
                                        {
                                            return (CKA_KEY_TYPE == p.first);
                                        });

            if (ulongAttrIter != objectParams.ulongAttributes.cend())
            {
                keyType = ulongAttrIter->second;
            }
        }

        return keyType;
    }

    //---------------------------------------------------------------------------------------------
    bool ObjectCache::privateObject(const uint32_t& objectHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (mCache.find(objectHandle) != mCache.end())
        {
            ObjectParameters objectParams = mCache[objectHandle];

            return objectParams.boolAttributes.test(BoolAttribute::PRIVATE);
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool ObjectCache::tokenObject(const uint32_t& objectHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (mCache.find(objectHandle) != mCache.end())
        {
            ObjectParameters objectParams = mCache[objectHandle];

            return objectParams.boolAttributes.test(BoolAttribute::TOKEN);
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool ObjectCache::attributeSet(const uint32_t& objectHandle, const BoolAttribute& boolAttribute)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (mCache.find(objectHandle) != mCache.end())
        {
            ObjectParameters objectParams = mCache[objectHandle];

            return objectParams.boolAttributes.test(boolAttribute);
        }

        return false;
    }
}
