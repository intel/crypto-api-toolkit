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

#include "SessionCache.h"

namespace P11Crypto
{
    std::mutex SessionCache::mCacheMutex;

    //---------------------------------------------------------------------------------------------
    SessionCache::SessionCache()
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        objectCache = new (std::nothrow) ObjectCache();
    }

    //---------------------------------------------------------------------------------------------
    SessionCache::~SessionCache()
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        delete objectCache;
        objectCache = nullptr;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::find(const uint32_t& sessionHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return (mCache.find(sessionHandle) != mCache.end());
    }

    //---------------------------------------------------------------------------------------------
    uint32_t SessionCache::count() const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return mCache.size();
    }

    //---------------------------------------------------------------------------------------------
    CK_SLOT_ID SessionCache::getSlotId(const uint32_t& sessionHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);
        uint32_t slotId = maxSlotsSupported + 1;

        if (mCache.find(sessionHandle) != mCache.end())
        {
            slotId = mCache[sessionHandle].slotId;
        }

        return slotId;
    }

    //---------------------------------------------------------------------------------------------
    static bool isRWSession(const SessionState& sessionState)
    {
        if (SessionState::RWPublic == sessionState ||
            SessionState::RWUser   == sessionState ||
            SessionState::RWSO     == sessionState)
        {
            return true;
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SessionCache::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (!pInfo)
        {
            return CKR_ARGUMENTS_BAD;
        }

        auto it = mCache.find(hSession);
        if (mCache.end() == it)
        {
            return CKR_SESSION_HANDLE_INVALID;
        }

        SessionParameters sessionParams = it->second;

        pInfo->slotID = sessionParams.slotId;
        pInfo->state = static_cast<CK_STATE>(it->second.sessionState);
        pInfo->flags = CKF_SERIAL_SESSION;

        if (isRWSession(sessionParams.sessionState))
        {
            pInfo->flags |= CKF_RW_SESSION;
        }

        pInfo->ulDeviceError = 0;

        return CKR_OK;
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::updateSessionStateForLogout(const CK_SLOT_ID& slotId)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        SessionParameters sessionParameters{};
        std::vector<uint32_t> newKeyHandlesinSessionParams;

        for (auto it : mCache)
        {
            sessionParameters = it.second;
            if (slotId == sessionParameters.slotId)
            {
                // Update the session state.
                if (SessionState::RWSO   == sessionParameters.sessionState ||
                    SessionState::RWUser == sessionParameters.sessionState)
                {
                    sessionParameters.sessionState = SessionState::RWPublic;
                }
                else if (SessionState::ROUser == sessionParameters.sessionState)
                {
                    sessionParameters.sessionState = SessionState::ROPublic;
                }

                // Destroy all private objects in this session.
                if (SessionState::RWSO != sessionParameters.sessionState)
                {
                    KeyType keyType = KeyType::Invalid;

                    for (auto objectHandle : sessionParameters.sessionObjectHandles)
                    {
                        if (objectCache->privateObject(objectHandle))
                        {
                            if (CKK_AES == objectCache->getKeyType(objectHandle))
                            {
                                keyType = KeyType::Aes;
                            }
                            else if (CKK_RSA == objectCache->getKeyType(objectHandle))
                            {
                                keyType = KeyType::Rsa;
                            }
                            else if (CKK_EC == objectCache->getKeyType(objectHandle))
                            {
                                keyType = KeyType::Ec;
                            }
                            else if (CKK_EC_EDWARDS == objectCache->getKeyType(objectHandle))
                            {
                                keyType = KeyType::Ed;
                            }

                            if (objectCache->tokenObject(objectHandle))
                            {
                                uint32_t newKeyHandle = Utils::EnclaveUtils::generateRandom();
                                if (!newKeyHandle)
                                {
                                    continue;
                                }

                                // Save the new key handles to be updated in session cache.
                                newKeyHandlesinSessionParams.push_back(newKeyHandle);

                                // Update new key handle in objectCache.
                                objectCache->updateKeyHandle(objectHandle, newKeyHandle);

                                Utils::EnclaveUtils::updateObjectHandle(objectHandle, newKeyHandle, keyType);
                            }
                            else
                            {
                                // Remove from enclave cache.
                                Utils::EnclaveUtils::destroyKey(objectHandle, keyType);

                                objectCache->remove(objectHandle);
                            }

                            // Remove from sessionObjectHandles vector.
                            auto sessObjIt = std::remove_if(sessionParameters.sessionObjectHandles.begin(),
                                                            sessionParameters.sessionObjectHandles.end(),
                                                            [=](const uint32_t& handle) { return (objectHandle == handle);});

                            sessionParameters.sessionObjectHandles.erase(sessObjIt, sessionParameters.sessionObjectHandles.end());

                            // Remove from objectHandles vector.
                            auto objIt = std::remove_if(objectHandles.begin(),
                                                        objectHandles.end(),
                                                        [=](const uint32_t& handle) { return (objectHandle == handle);});
                            objectHandles.erase(objIt, objectHandles.end());
                        }
                    }

                    for (auto objectHandle : newKeyHandlesinSessionParams)
                    {
                        sessionParameters.sessionObjectHandles.push_back(objectHandle);
                        objectHandles.push_back(objectHandle);
                    }
                }

                mCache[it.first] = sessionParameters;
            }
        }
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::updateSessionStateForLogin(const CK_SLOT_ID& slotId, const CK_USER_TYPE& userType)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        SessionParameters sessionParameters{};

        for (auto it : mCache)
        {
            sessionParameters = it.second;
            if (slotId == sessionParameters.slotId)
            {
                if (CKU_USER == userType)
                {
                    if (SessionState::RWPublic == sessionParameters.sessionState)
                    {
                        sessionParameters.sessionState = SessionState::RWUser;
                    }
                    else if (SessionState::ROPublic == sessionParameters.sessionState)
                    {
                        sessionParameters.sessionState = SessionState::ROUser;
                    }
                }
                else if (CKU_SO == userType)
                {
                    sessionParameters.sessionState = SessionState::RWSO;
                }

                mCache[it.first] = sessionParameters;
            }
        }
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::sessionStateExists(const CK_SLOT_ID& slotID, const SessionState& sessionState) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (mCache.end() != std::find_if(mCache.cbegin(), mCache.cend(), [&slotID, &sessionState](const std::pair<uint32_t, SessionParameters>& p)
                                        {
                                            return (p.second.slotId == slotID) && (p.second.sessionState == sessionState);
                                        }))
        {
            return true;
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    SessionState SessionCache::getSessionStateforNewSession(const CK_SLOT_ID& slotId, const CK_FLAGS& flags) const
    {
        SessionState sessionState{};

        if (sessionStateExists(slotId, SessionState::RWSO))
        {
            sessionState = SessionState::RWSO;
        }
        else if (!(CKF_RW_SESSION & flags))  // Open an RO session.
        {
            if (sessionStateExists(slotId, SessionState::ROUser))
            {
                sessionState = SessionState::ROUser;
            }
            else
            {
                sessionState = SessionState::ROPublic;
            }
        }
        else // Open an RW session.
        {
            if (sessionStateExists(slotId, SessionState::RWUser))
            {
                sessionState = SessionState::RWUser;
            }
            else
            {
                sessionState = SessionState::RWPublic;
            }
        }

        return sessionState;
    }

    //---------------------------------------------------------------------------------------------
    SessionState SessionCache::getSessionState(const uint32_t& sessionHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        SessionState sessionState = SessionState::INVALID;

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sessionState = iterator->second.sessionState;
        }

        return sessionState;
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::add(const uint32_t& sessionHandle, const SessionParameters& sessionParameters)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        // Add SessionParameters into sessionHandleCache.
        mCache[sessionHandle] = sessionParameters;

        // Update SlotCache.
        CK_SLOT_ID id = sessionParameters.slotId;
        const auto iterator = mSlotCache.find(id);
        if (mSlotCache.end() == iterator)
        {
            SlotParameters slotParameters;
            mSlotCache[id] = slotParameters;
        }
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::getObjectParams(const uint32_t& objectHandle, ObjectParameters* objectParams) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (objectParams && (std::find(objectHandles.begin(), objectHandles.end(), objectHandle) != objectHandles.end()))
        {
            return objectCache->getObjectParams(objectHandle, objectParams);
        }

        return false;

    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::findObject(const uint32_t& objectHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return (std::find(objectHandles.cbegin(), objectHandles.cend(), objectHandle) != objectHandles.cend());
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::removeObject(const uint32_t& sessionHandle, const uint32_t& objectHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        auto it = mCache.find(sessionHandle);

        if (it != mCache.end())
        {
            // Remove objectHandle from the SessionParameters.
            auto sessObjIt = std::remove_if(it->second.sessionObjectHandles.begin(),
                                            it->second.sessionObjectHandles.end(),
                                            [=](const uint32_t& handle) { return (objectHandle == handle);});

            it->second.sessionObjectHandles.erase(sessObjIt, it->second.sessionObjectHandles.end());

            // Remove objectHandle from objectHandles vector.
            auto objIt = std::remove_if(objectHandles.begin(),
                                        objectHandles.end(),
                                        [=](const uint32_t& handle) { return (objectHandle == handle);});
            objectHandles.erase(objIt, objectHandles.end());

            // Remove objectHandle from object cache.
            objectCache->remove(objectHandle);

            // Remove objectHandle from FindObjects vector.
            auto foObjIt = std::remove_if(it->second.data.foHandles.begin(),
                                          it->second.data.foHandles.end(),
                                          [=](const uint32_t& handle) { return (objectHandle == handle);});

            it->second.data.foHandles.erase(foObjIt, it->second.data.foHandles.end());
        }
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::addObject(const uint32_t&         sessionHandle,
                                 const uint32_t&         objectHandle,
                                 const ObjectParameters& objectParams)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        auto it = mCache.find(sessionHandle);
        if (it != mCache.end())
        {
            SessionParameters sessionParams = it->second;

            // Update sessionObjectHandles vector if objectHandle is not already present.
            if (sessionParams.sessionObjectHandles.end() == std::find(sessionParams.sessionObjectHandles.begin(),
                                                                      sessionParams.sessionObjectHandles.end(),
                                                                      objectHandle))
            {
                sessionParams.sessionObjectHandles.push_back(objectHandle);
            }

            // Update objectHandles vector if objectHandle is not already present.
            if (objectHandles.end() == std::find(objectHandles.begin(), objectHandles.end(), objectHandle))
            {
                objectHandles.push_back(objectHandle);
            }

            // Update session cache.
            mCache[sessionHandle] = sessionParams;

            // Update object cache.
            objectCache->add(objectHandle, objectParams);
        }
    }

    //---------------------------------------------------------------------------------------------
    static CK_RV updateAttributesInTokenFile(const CK_OBJECT_HANDLE& keyHandle,
                                             const CK_KEY_TYPE&      keyType,
                                             const ObjectParameters& objectParams)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            std::vector<CK_ULONG> packedAttributes;

            if (!Utils::AttributeUtils::packAttributes(objectParams.slotId,
                                                       objectParams.ulongAttributes,
                                                       objectParams.strAttributes,
                                                       objectParams.boolAttributes,
                                                       &packedAttributes))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            rv = Utils::EnclaveUtils::updateTokenObject(keyHandle, keyType, packedAttributes);
            if (CKR_OK != rv)
            {
                break;
            }

        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::setWrappingStatus(const uint32_t& objectHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        ObjectParameters objectParams;

        objectCache->getObjectParams(objectHandle, &objectParams);

        // Skip if wrapping status is already set.
        if (objectParams.boolAttributes.test(BoolAttribute::USED_FOR_WRAPPING))
        {
            return true;
        }

        objectParams.boolAttributes.set(BoolAttribute::USED_FOR_WRAPPING);

        if (objectParams.boolAttributes.test(BoolAttribute::TOKEN))
        {
            CK_KEY_TYPE keyType = objectCache->getKeyType(objectHandle);

            CK_RV rv = updateAttributesInTokenFile(objectHandle, keyType, objectParams);
            if (CKR_OK != rv)
            {
                return false;
            }
        }

        objectCache->add(objectHandle, objectParams);

        return true;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::checkWrappingStatus(const uint32_t& objectHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        ObjectParameters objectParams;

        objectCache->getObjectParams(objectHandle, &objectParams);

        return objectParams.boolAttributes.test(BoolAttribute::USED_FOR_WRAPPING);
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::closeSession(const uint32_t& sessionHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        auto it = mCache.find(sessionHandle);
        if (it != mCache.end())
        {
            for (auto objectHandle : it->second.sessionObjectHandles)
            {
                // Skip removal of token objects during session closure.
                if (objectCache->tokenObject(objectHandle))
                {
                    continue;
                }

                // Remove from objectHandles vector.
                auto iterator = std::find(objectHandles.begin(), objectHandles.end(), objectHandle);
                if (objectHandles.end() != iterator)
                {
                    objectHandles.erase(iterator);
                }

                // Remove object from enclave cache.
                KeyType     type    = KeyType::Invalid;
                CK_KEY_TYPE keyType = objectCache->getKeyType(objectHandle);

                if (CKK_AES == keyType)
                {
                    type = KeyType::Aes;
                }
                else if (CKK_RSA == keyType)
                {
                    type = KeyType::Rsa;
                }

                Utils::EnclaveUtils::destroyKey(objectHandle, type);

                // Remove from object cache
                objectCache->remove(objectHandle);
            }

            // Remove hash handle in the session if any
            uint32_t hashHandle = it->second.data.hashParams.hashHandle;
            if (CK_INVALID_HANDLE != hashHandle)
            {
                CK_RV returnValue = P11Crypto::HashProvider::destroyHash(hashHandle);
            }

            // Update mSlotCache(remove slotId) if current session is the last session in the slot
            CK_SLOT_ID slotId = it->second.slotId;
            if ((1 == std::count_if(mCache.cbegin(),
                                    mCache.cend(),
                                    [=](const std::pair<uint32_t, SessionParameters>& p){ return (slotId == p.second.slotId); })))
            {
                auto it = mSlotCache.find(slotId);
                if (it != mSlotCache.end())
                {
                    mSlotCache.erase(it);
                }
            }

            // Remove the sessionHandle's entry from session cache
            mCache.erase(it);
            return true;
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SessionCache::closeAllSessions(const uint32_t& slotId)
    {
        // (To-Do) : Investigate if code can be reorganized to remove unique_lock.
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        std::vector<uint32_t> sessionHandlesInSlot;
        for (auto it : mCache)
        {
            SessionParameters sessionParams = it.second;
            if (slotId == sessionParams.slotId)
            {
                sessionHandlesInSlot.push_back(it.first);
            }
        }

        auto slotIt = mSlotCache.find(slotId);
        if (slotIt != mSlotCache.end())
        {
            mSlotCache.erase(slotIt);
        }

        if (ulock.owns_lock())
        {
            ulock.unlock();
        }

        uint32_t sessionHandleCount = sessionHandlesInSlot.size();
        for (auto i = 0; i < sessionHandleCount; ++i)
        {
            closeSession(sessionHandlesInSlot[i]);
        }

        return CKR_OK;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SessionCache::findObjectsInit(const uint32_t&   sessionHandle,
                                        const Attributes& attributes,
                                        const bool&       findAllHandles)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        auto iterator = mCache.find(sessionHandle);
        if (iterator == mCache.end())
        {
            return CKR_SESSION_HANDLE_INVALID;
        }

        SessionState sessionState = iterator->second.sessionState;
        bool         isPublicSession = !(SessionState::RWUser == sessionState || SessionState::ROUser == sessionState);

        std::vector<uint32_t> matchedHandles;
        ObjectParameters objectParams;

        for (auto it : objectHandles)
        {
            // Skipping private objects if session is Public.
            if (isPublicSession && objectCache->privateObject(it))
            {
                continue;
            }

            if (findAllHandles)
            {
                matchedHandles.push_back(it);
            }
            else
            {
                if (objectCache->getObjectParams(it, &objectParams))
                {
                    if (Utils::AttributeUtils::matchAttributes(attributes, objectParams))
                    {
                        matchedHandles.push_back(it);
                    }
                }
            }
        }

        iterator->second.data.foHandles = matchedHandles;
        iterator->second.activeOperation.reset(ActiveOp::FindObjects_None);

        return CKR_OK;
    }

    //---------------------------------------------------------------------------------------------
    uint32_t SessionCache::findObjects(const uint32_t&      sessionHandle,
                                       CK_OBJECT_HANDLE_PTR phObject,
                                       const uint32_t&      ulCount)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        uint32_t          keyHandlesCopied = 0;
        uint32_t          keyHandleCount   = 0;
        SessionParameters sessionParameters{};

        const auto iterator = mCache.find(sessionHandle);
        if (!phObject || mCache.end() == iterator)
        {
            return keyHandlesCopied;
        }

        sessionParameters = iterator->second;

        keyHandleCount = sessionParameters.data.foHandles.size();
        for (auto i = 0; i < keyHandleCount; ++i)
        {
            if (keyHandlesCopied == ulCount)
            {
                break;
            }

            phObject[keyHandlesCopied++] = sessionParameters.data.foHandles[i];
        }

        // Remove/erase the copied key handles.
        const auto iteratorBegin = sessionParameters.data.foHandles.begin();
        const auto iteratorEnd   = iteratorBegin + keyHandlesCopied;

        sessionParameters.data.foHandles.erase(iteratorBegin, iteratorEnd);

        // Update the key handles back in cache.
        iterator->second = sessionParameters;

        return keyHandlesCopied;
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::findObjectsFinal(const uint32_t& sessionHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            iterator->second.data.foHandles.clear();
            iterator->second.activeOperation.set(ActiveOp::FindObjects_None);
        }
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::isSessionPublic(const uint32_t& sessionHandle)
    {
        if (find(sessionHandle))
        {
            SessionParameters sessionParams = mCache[sessionHandle];

            if (SessionState::RWUser == sessionParams.sessionState ||
                SessionState::ROUser == sessionParams.sessionState ||
                SessionState::RWSO   == sessionParams.sessionState)
            {
                return false;
            }

            return true;
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::isUserLoggedIn(const uint32_t& sessionHandle)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        if (mCache.find(sessionHandle) != mCache.end())
        {
            SessionParameters sessionParams = mCache[sessionHandle];

            if (SessionState::RWUser == sessionParams.sessionState ||
                SessionState::ROUser == sessionParams.sessionState)
            {
                return true;
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::clear()
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        mCache.clear();
        mSlotCache.clear();
        objectCache->clear();
        objectHandles.clear();
    }

    //---------------------------------------------------------------------------------------------
    std::vector<CK_SLOT_ID> SessionCache::getAllSlotIDs() const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        std::vector<CK_SLOT_ID> slotIDs;
        slotIDs.resize(mSlotCache.size());

        std::transform(mSlotCache.begin(), mSlotCache.end(), slotIDs.begin(), [](const std::pair<CK_SLOT_ID, SlotParameters>& it){return it.first;} );

        return slotIDs;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV SessionCache::createSession(const CK_SLOT_ID& slotId, const CK_FLAGS& flags, uint32_t* sessionId)
    {
        if (!sessionId)
        {
            return CKR_ARGUMENTS_BAD;
        }
        else
        {
            SessionState sessionState = getSessionStateforNewSession(slotId, flags);

            // Rejecting the attempt to open RO session with already existing RWSO session.
            if (SessionState::RWSO == sessionState && !(CKF_RW_SESSION & flags))
            {
                return CKR_SESSION_READ_WRITE_SO_EXISTS;
            }

            *sessionId = Utils::EnclaveUtils::generateRandom();

            if (!*sessionId)
            {
                return CKR_DEVICE_ERROR;
            }

            SessionParameters sessionParameters {};
            sessionParameters.slotId       = slotId;
            sessionParameters.sessionState = sessionState;
            this->add(*sessionId, sessionParameters);

            return CKR_OK;
        }
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::logoutRequired(const CK_SLOT_ID& slotID, const uint32_t& sessionHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        auto it = mCache.find(sessionHandle);
        if (it != mCache.end())
        {
            SessionState sessionState = it->second.sessionState;

            if (SessionState::RWSO   == sessionState ||
                SessionState::RWUser == sessionState ||
                SessionState::ROUser == sessionState)
            {
                return (1 == std::count_if(mCache.cbegin(),
                                           mCache.cend(),
                                           [=](const std::pair<uint32_t, SessionParameters>& p){ return (slotID == p.second.slotId); }));
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::logoutRequired(const CK_SLOT_ID& slotId) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        for (auto it : mCache)
        {
            SessionParameters sessionParams = it.second;
            if (slotId == sessionParams.slotId)
            {
                SessionState sessionState = it.second.sessionState;

                if (SessionState::RWSO   == sessionState ||
                    SessionState::RWUser == sessionState ||
                    SessionState::ROUser == sessionState)
                {
                    return true;
                }
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    CK_KEY_TYPE SessionCache::getKeyType(const uint32_t& keyHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return objectCache->getKeyType(keyHandle);
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::checkKeyType(const uint32_t& keyHandle, const CK_KEY_TYPE& keyType) const
    {
        return findObject(keyHandle) && (keyType == getKeyType(keyHandle));
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::attributeSet(const uint32_t& objectHandle, const BoolAttribute& boolAttribute) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return objectCache->attributeSet(objectHandle, boolAttribute);
    }

    //---------------------------------------------------------------------------------------------
    SessionParameters SessionCache::getSessionParameters(const uint32_t& sessionHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        SessionParameters sesionParameters;

        const auto iterator = mCache.find(sessionHandle);
        if (iterator != mCache.end())
        {
            sesionParameters = iterator->second;
        }

        return sesionParameters;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::privateObject(const uint32_t& objectHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return objectCache->privateObject(objectHandle);
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::tokenObject(const uint32_t& objectHandle) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        return objectCache->tokenObject(objectHandle);
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::isLoggedIn(const CK_SLOT_ID& slotId, const CK_USER_TYPE& userType)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        const auto iterator = mSlotCache.find(slotId);
        if (iterator != mSlotCache.end())
        {
            SlotParameters slotParameters = mSlotCache[slotId];
            if (CKU_SO == userType)
            {
                return slotParameters.loginStatus.soLoggedIn;
            }
            else if (CKU_USER == userType)
            {
                return slotParameters.loginStatus.userLoggedIn;
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::login(const CK_SLOT_ID& slotId, const CK_USER_TYPE& userType)
    {
        // (To-Do) : Investigate if code can be reorganized to remove unique_lock.
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        bool result = true;

        const auto iterator = mSlotCache.find(slotId);
        if (mSlotCache.end() == iterator)
        {
            return false;
        }

        SlotParameters slotParameters = mSlotCache[slotId];
        switch(userType)
        {
            case CKU_SO:
                slotParameters.loginStatus.soLoggedIn ? (result = false) : (slotParameters.loginStatus.soLoggedIn = true);
                break;
            case CKU_USER:
                slotParameters.loginStatus.userLoggedIn ? (result = false) : (slotParameters.loginStatus.userLoggedIn = true);
                break;
            default:
                result = false;
                break;
        }

        if (result)
        {
            mSlotCache[slotId] = slotParameters;
            if (ulock.owns_lock())
            {
                ulock.unlock();
            }
            updateSessionStateForLogin(slotId, userType);
        }

        if (ulock.owns_lock())
        {
            ulock.unlock();
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::logout(const CK_SLOT_ID& slotId)
    {
        CK_USER_TYPE userType = CKU_USER_INVALID;
        if (isLoggedIn(slotId, CKU_SO))
        {
            userType = CKU_SO;
        }
        else if (isLoggedIn(slotId, CKU_USER))
        {
            userType = CKU_USER;
        }
        else
        {
            return false;
        }

        // (To-Do) : Investigate if code can be reorganized to remove unique_lock.
        std::unique_lock<decltype(mCacheMutex)> ulock(mCacheMutex, std::defer_lock);
        ulock.lock();

        bool result = true;

        const auto iterator = mSlotCache.find(slotId);
        if (mSlotCache.end() == iterator)
        {
            return false;
        }

        SlotParameters slotParameters = mSlotCache[slotId];

        switch(userType)
        {
            case CKU_SO:
                (!slotParameters.loginStatus.soLoggedIn) ? (result = false) : (slotParameters.loginStatus.soLoggedIn = false);
                break;
            case CKU_USER:
                (!slotParameters.loginStatus.userLoggedIn) ? (result = false) : (slotParameters.loginStatus.userLoggedIn = false);
                break;
            default:
                result = false;
        }

        if (result)
        {
            mSlotCache[slotId] = slotParameters;
            if (ulock.owns_lock())
            {
                ulock.unlock();
            }
            updateSessionStateForLogout(slotId);
        }

        if (ulock.owns_lock())
        {
            ulock.unlock();
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::sessionExists(const CK_SLOT_ID& slotId) const
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        SessionParameters sessionParameters{};

        for (auto it : mCache)
        {
            sessionParameters = it.second;
            if (slotId == sessionParameters.slotId)
            {
                return true;
            }
        }

        return false;
    }

    //---------------------------------------------------------------------------------------------
    void SessionCache::updateTokenObjectStatus(const CK_SLOT_ID& slotId)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        SlotParameters slotParameters;
        slotParameters.tokenObjectsLoaded = true;

        mSlotCache[slotId] = slotParameters;
    }

    //---------------------------------------------------------------------------------------------
    bool SessionCache::tokenObjectsLoaded(const CK_SLOT_ID& slotId)
    {
        std::lock_guard<std::mutex> lockMutex(mCacheMutex);

        const auto iterator = mSlotCache.find(slotId);
        if (mSlotCache.end() == iterator)
        {
            return false;
        }

        SlotParameters slotParameters = iterator->second;
        return slotParameters.tokenObjectsLoaded;

    }
}
