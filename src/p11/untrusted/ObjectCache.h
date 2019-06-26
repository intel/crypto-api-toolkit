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

#ifndef OBJECT_CACHE
#define OBJECT_CACHE

#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <vector>
#include <algorithm>

#include "CryptoEnclaveDefs.h"
#include "Constants.h"
#include "p11Defines.h"

namespace P11Crypto
{
    class ObjectCache
    {
    public:

        ObjectCache();

        ObjectCache(const ObjectCache&) = delete;

        ObjectCache& operator=(const ObjectCache&) = delete;

        virtual ~ObjectCache();

        /**
        * Adds a session handle into the cache.
        * @param sessionHandle          The session handle from the application.
        * @param sessionParameters      The associated session parameters.
        */
        void add(const uint32_t& objectHandle, const ObjectParameters& objectParams);

        /**
        * Removes a session handle from the cache.
        * @param    sessionHandle  The session handle.
        */
        void remove(const uint32_t& objectHandle);

        /**
        * Clears all the session handles from the cache.
        */
        void clear();

        bool getObjectParams(const uint32_t& objectHandle, ObjectParameters* objectParams);

        CK_KEY_TYPE getKeyType(const uint32_t& keyHandle);

        bool privateObject(const uint32_t& objectHandle);

        bool tokenObject(const uint32_t& objectHandle);

        bool attributeSet(const uint32_t& objectHandle, const BoolAttribute& boolAttribute);

    private:

        using ObjectHandleCollection = std::map<uint32_t, ObjectParameters>;

        // Member variables
        ObjectHandleCollection mCache;
        static std::mutex mCacheMutex;
    };
} //P11Crypto
#endif // OBJECT_HANDLE_CACHE

