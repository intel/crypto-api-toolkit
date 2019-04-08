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

#include "SessionHandleCache.h"
#include <algorithm>

namespace P11Crypto
{
    std::mutex SessionHandleCache::mCacheMutex;

    //---------------------------------------------------------------------------------------------
    SessionHandleCache::SessionParametersData::SessionParametersData()
        : data({})
    {

    }

    //---------------------------------------------------------------------------------------------
    SessionHandleCache::SessionParametersData::SessionParametersData(const SessionParameters& sessionParameters)
        : data(sessionParameters)
    {

    }
    //---------------------------------------------------------------------------------------------
    std::shared_ptr<SessionHandleCache> SessionHandleCache::getSessionHandleCache()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        std::shared_ptr<SessionHandleCache> sessionHandleCache = std::make_shared<SessionHandleCache>();

        ulock.unlock();
        return sessionHandleCache;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::find(const uint32_t& sessionHandle) const
    {
        bool result = false;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        result = (0 != mCache.count(sessionHandle));

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    uint32_t SessionHandleCache::count() const
    {
        uint32_t count = 0;
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        count = mCache.size();

        ulock.unlock();
        return count;
    }

    //---------------------------------------------------------------------------------------------
    SessionParameters SessionHandleCache::get(const uint32_t& sessionHandle) const
    {
        SessionParameters sessionParameters{};
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
        }

        ulock.unlock();
        return sessionParameters;
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::getAllSessionHandles(std::vector<uint32_t>& sessionHandles)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            sessionHandles.push_back(iterator->first);
            ++iterator;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::getSessionHandlesInSlot(CK_SLOT_ID slotID, std::vector<uint32_t>& sessionHandles)
    {
        SessionParameters sessionParameters{};
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            if (slotID == sessionParameters.slotID)
            {
                sessionHandles.push_back(iterator->first);
            }
            ++iterator;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::hasROSessionInSlot(const CK_SLOT_ID& slotID)
    {
        bool              result = false;
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            if (slotID == sessionParameters.slotID)
            {
                if (SessionState::RO_PUBLIC_STATE == sessionParameters.sessionState)
                {
                    result = true;
                    break;
                }
            }
            ++iterator;
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::hasUserLoggedInROSession(const CK_SLOT_ID& slotID)
    {
        bool              result = false;
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            if (slotID == sessionParameters.slotID)
            {
                if (SessionState::RO_USER_STATE == sessionParameters.sessionState)
                {
                    result = true;
                    break;
                }
            }
            ++iterator;
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::hasUserLoggedInRWSession(const CK_SLOT_ID& slotID)
    {
        bool              result = false;
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            if (slotID == sessionParameters.slotID)
            {
                if (SessionState::RW_USER_STATE == sessionParameters.sessionState)
                {
                    result = true;
                    break;
                }
            }
            ++iterator;
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::hasSOLoggedInSession(const CK_SLOT_ID& slotID)
    {
        bool              result = false;
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            if (slotID == sessionParameters.slotID)
            {
                if (SessionState::RW_SO_STATE == sessionParameters.sessionState)
                {
                    result = true;
                    break;
                }
            }
            ++iterator;
        }

        ulock.unlock();
        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::isRWSession(const uint32_t& sessionHandle)
    {
        bool         result       = false;
        SessionState sessionState = SessionState::STATE_NONE;

        sessionState = getSessionState(sessionHandle);

        if (SessionState::RW_PUBLIC_STATE == sessionState ||
            SessionState::RW_USER_STATE   == sessionState ||
            SessionState::RW_SO_STATE     == sessionState)
        {
            result = true;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    CK_SLOT_ID SessionHandleCache::getSlotID(const uint32_t& sessionHandle)
    {
        CK_SLOT_ID          slotID = 0;
        SessionParameters   sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            slotID = sessionParameters.slotID;
        }

        ulock.unlock();
        return slotID;
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::updateSessionState(const uint32_t&     sessionHandle,
                                                const SessionState& sessionState)
    {
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            sessionParameters.sessionState = sessionState;

            mCache[sessionHandle] = sessionParameters;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    SessionState SessionHandleCache::getSessionState(const uint32_t& sessionHandle)
    {
        SessionParameters sessionParameters{};
        SessionState      sessionState = SessionState::STATE_NONE;

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            sessionState      = sessionParameters.sessionState;
        }

        ulock.unlock();

        return sessionState;
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::add(const uint32_t& sessionHandle, const SessionParameters& sessionParameters)
    {
        bool       newSlot = true;
        uint32_t   slotCount;
        CK_SLOT_ID id;

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache[sessionHandle] = sessionParameters;

        id = sessionParameters.slotID;
        slotCount = slotIDs.size();

        for (uint32_t i = 0; i < slotCount; i++)
        {
            if (id == slotIDs[i])
            {
                newSlot = false;
                break;
            }
        }

        if (newSlot)
        {
            slotIDs.push_back(id);
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::remove(const uint32_t& sessionHandle)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        auto retValue = iterator != mCache.end();
        if (retValue)
        {
            mCache.erase(iterator);
        }

        ulock.unlock();
        return retValue;
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::clear()
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        mCache.clear();

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::getAllSlotIDs(std::vector<CK_SLOT_ID>& slots)
    {
        slots = slotIDs;
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::updateMatchedKeyHandles(const uint32_t&              sessionHandle,
                                                     const std::vector<uint32_t>& keyHandles)
    {
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
            sessionParameters.keyHandles = keyHandles;

            mCache[sessionHandle] = sessionParameters;
        }

        ulock.unlock();
    }

    //---------------------------------------------------------------------------------------------
    uint32_t SessionHandleCache::getMatchedKeyHandles(const uint32_t&      sessionHandle,
                                                      CK_OBJECT_HANDLE_PTR phObject,
                                                      const uint32_t&      ulCount)
    {
        uint32_t          keyHandlesCopied = 0;
        uint32_t          keyHandleCount   = 0;
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
        }

        keyHandleCount = sessionParameters.keyHandles.size();
        for (auto i = 0; i < keyHandleCount; i++)
        {
            if (keyHandlesCopied == ulCount)
            {
                break;
            }

            phObject[keyHandlesCopied++] = sessionParameters.keyHandles[i];
        }

        // Remove/erase the copied key handles.
        const auto iteratorBegin = sessionParameters.keyHandles.begin();
        const auto iteratorEnd   = iteratorBegin + keyHandlesCopied;

        sessionParameters.keyHandles.erase(iteratorBegin, iteratorEnd);

        ulock.unlock();

        // Update the key handles back in cache.
        updateMatchedKeyHandles(sessionHandle, sessionParameters.keyHandles);

        return keyHandlesCopied;
    }

    //---------------------------------------------------------------------------------------------
    void SessionHandleCache::clearMatchedKeyHandles(const uint32_t& sessionHandle)
    {
        SessionParameters sessionParameters{};

        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionParameters = iterator->second.data;
        }

        sessionParameters.keyHandles.clear();

        ulock.unlock();

        // Update the key handles back in cache.
        updateMatchedKeyHandles(sessionHandle, sessionParameters.keyHandles);
    }

    //---------------------------------------------------------------------------------------------
    bool SessionHandleCache::isLastSessionInSlot(const CK_SLOT_ID& slotID)
    {
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        uint32_t sessionCount = 0;
        SessionParameters sessionParameters;

        auto iterator   = mCache.begin();
        while (iterator != mCache.end())
        {
            if (iterator->second.data.slotID == slotID)
            {
                sessionCount++;
            }
            ++iterator;
        }

        ulock.unlock();

        return (1 == sessionCount);
    }
}
