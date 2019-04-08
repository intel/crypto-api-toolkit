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

#include "SymmetricKeyCache.h"

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    SymmetricKeyCache::SymKeyData::SymKeyData()
        : data({})
    {

    }

    //---------------------------------------------------------------------------------------------
    SymmetricKeyCache::SymKeyData::SymKeyData(const SymmetricKey& key)
        : data(key)
    {

    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricKeyCache::find(const uint32_t keyId) const
    {
        return (mCache.count(keyId) != 0);
    }

    //---------------------------------------------------------------------------------------------
    uint32_t SymmetricKeyCache::count() const
    {
        return mCache.size();
    }

    //---------------------------------------------------------------------------------------------
    SymmetricKey SymmetricKeyCache::get(const uint32_t keyId) const
    {
        SymmetricKey symKey{};
        const auto iterator = mCache.find(keyId);

        if (iterator != mCache.end())
        {
            symKey.key               = iterator->second.data.key;
            symKey.isPlatformBound   = iterator->second.data.isPlatformBound;
            symKey.isUsedForWrapping = iterator->second.data.isUsedForWrapping;
        }
        return symKey;
    }

    //---------------------------------------------------------------------------------------------
    void SymmetricKeyCache::add(const uint32_t keyId, const SymmetricKey& key)
    {
        mCache[keyId] = key;
    }

    //---------------------------------------------------------------------------------------------
    bool SymmetricKeyCache::remove(const uint32_t keyId)
    {
        const auto iterator = mCache.find(keyId);
        auto retValue       = iterator != mCache.end();
        if (retValue)
        {
            mCache.erase(iterator);
        }
        return retValue;
    }

    //---------------------------------------------------------------------------------------------
    void SymmetricKeyCache::clear()
    {
        mCache.clear();
    }

} //CryptoSgx