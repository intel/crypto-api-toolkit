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

#include "AsymmetricKeyCache.h"

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    AsymmetricKeyCache::AsymmetricKeyData::AsymmetricKeyData()
        : data({})
    {

    }

    //---------------------------------------------------------------------------------------------
    AsymmetricKeyCache::AsymmetricKeyData::AsymmetricKeyData(const AsymmetricKey& asymmetricKey)
        : data(asymmetricKey)
    {

    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyCache::find(const uint32_t& keyId) const
    {
        return (mCache.count(keyId) != 0);
    }

    //---------------------------------------------------------------------------------------------
    uint32_t AsymmetricKeyCache::count() const
    {
        return mCache.size();
    }

    //---------------------------------------------------------------------------------------------
    AsymmetricKey AsymmetricKeyCache::get(const uint32_t& keyId) const
    {
        AsymmetricKey   asymmetricKey;
        const auto      iterator = mCache.find(keyId);

        if (iterator != mCache.end())
        {
            asymmetricKey.key               = iterator->second.data.key;
            asymmetricKey.keyFile           = iterator->second.data.keyFile;
            asymmetricKey.ecKey             = iterator->second.data.ecKey;
            asymmetricKey.edKey             = iterator->second.data.edKey;
            asymmetricKey.isUsedForWrapping = iterator->second.data.isUsedForWrapping;
            asymmetricKey.pairKeyId         = iterator->second.data.pairKeyId;
        }

        return asymmetricKey;
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricKeyCache::add(const uint32_t& keyId, const AsymmetricKey& asymmetricKey)
    {
        mCache[keyId] = asymmetricKey;
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyCache::remove(const uint32_t& keyId, bool removeTokenFile)
    {
        const auto  iterator = mCache.find(keyId);
        auto        result   = iterator != mCache.end();

        if (result)
        {
            if (removeTokenFile)
            {
                std::string filePath = iterator->second.data.keyFile;
                if (!filePath.empty())
                {
                    if (!Utils::SgxFileUtils::remove(filePath))
                    {
                        return false;
                    }
                }
            }

            mCache.erase(iterator);
        }
        return result;
    }

    //---------------------------------------------------------------------------------------------
    void AsymmetricKeyCache::clear()
    {
        mCache.clear();
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyCache::isEcKey(const uint32_t& keyId) const
    {
        const auto iterator = mCache.find(keyId);

        if (iterator != mCache.end())
        {
            if (iterator->second.data.ecKey)
            {
                return true;
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyCache::isRsaKey(const uint32_t& keyId) const
    {
        const auto iterator = mCache.find(keyId);

        if (iterator != mCache.end())
        {
            if (iterator->second.data.key)
            {
                return true;
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool AsymmetricKeyCache::isEdKey(const uint32_t& keyId) const
    {
        const auto iterator = mCache.find(keyId);

        if (iterator != mCache.end())
        {
            if (iterator->second.data.edKey)
            {
                return true;
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    uint32_t AsymmetricKeyCache::findKeyIdForPairKeyId(const unsigned long& pairKeyId) const
    {
        for (auto iter = mCache.begin(); iter != mCache.end(); ++iter)
        {
            if (pairKeyId == iter->second.data.pairKeyId)
            {
                return iter->first;
            }
        }

        return 0;
    }

} //CryptoSgx