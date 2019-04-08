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

#ifndef ATTRIBUTE_CACHE
#define ATTRIBUTE_CACHE

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "AttributeHelpers.h"
#include "CryptoEnclaveDefs.h"
#include "Constants.h"
#include "p11Defines.h"

namespace P11Crypto
{
    class AttributeCache
    {
    public:
        static std::shared_ptr<AttributeCache> getAttributeCache();

        /**
        * Adds a key handle along with its attributes in the cache.
        * @param    keyHandle       The key Handle.
        * @param    keyAttributes   The key attributes.
        */
        void add(const uint32_t& keyHandle, const Attributes& keyAttributes);

        /**
        * Checks if a key is present in the cache.
        * @param    keyHandle   The key Handle.
        * @return   bool        True if the key Id passed is present in cache, false otherwise.
        */
        bool find(const uint32_t& keyHandle);

        /**
        * Checks if a key is a private object.
        * @param    keyHandle   The key Handle.
        * @return   bool        True if the key Id passed is a private object, false otherwise.
        */
        bool isPrivateObject(const uint32_t& keyHandle);

        /**
        * Checks if a key is a token object.
        * @param    keyHandle   The keyHandle.
        * @return   bool        True if the key Id passed is a token object, false if session object.
        */
        bool isTokenObject(const uint32_t& keyHandle);

        /**
        * Checks if a key is a session object.
        * @param    keyHandle   The keyHandle.
        * @return   bool        True if the key Id passed is a session object, false if token object.
        */
        bool isSessionObject(const uint32_t& keyHandle);

        /**
        * Checks if an attribute is set.
        * @param    keyHandle     The keyHandle.
        * @param    keyAttribute  The key attribute to be checked
        * @return   bool          True if the attribute passed is a set, false otherwise.
        */
        bool isAttributeSet(const uint32_t& keyHandle, const KeyAttribute keyAttribute);

        /**
        * Gets all key handles in the cache.
        * @param    keyHandles  A vector to hold the key handles.
        */
        void getAllKeyHandles(std::vector<uint32_t>& keyHandles);

        /**
        * Gets the key attributes of a key handle.
        * @param    keyHandle     The keyHandle.
        * @param    keyAttributes The key attributes of key handle, which are to be populated.
        */
        void getAttributes(const uint32_t& keyHandle, Attributes& keyAttributes);

        /**
        * Removes a key from the cache.
        * @param    keyHandle   The keyHandle
        * @return   bool        True if the key for the key Id was found and removed on the cache, false otherwise.
        */
        bool remove(const uint32_t& keyHandle);

    private:
        struct AttributesData
        {
            Attributes data;

            AttributesData();
            AttributesData(const Attributes& attributes);
        };
        typedef std::map<uint32_t, AttributesData>  attributeCollection;
        typedef attributeCollection::iterator       CacheCollectionIterator;
        typedef attributeCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        attributeCollection mCache;
        static std::mutex mCacheMutex;
    };
} //P11Crypto
#endif // ATTRIBUTE_CACHE
