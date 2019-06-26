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

#ifndef SESSION_CACHE
#define SESSION_CACHE

#include "ObjectCache.h"
#include "EnclaveUtils.h"
#include "AttributeUtils.h"
#include "HashProvider.h"

namespace P11Crypto
{
    enum class LoginState : uint8_t
    {
        NotLoggedIn = 0x00,
        LoggedIn    = 0x01,
    };

    enum class UserType
    {
        UserTypeSO      = CKU_SO,
        UserTypeNormal  = CKU_USER
    };

    class SessionCache
    {
    public:
        SessionCache();

        SessionCache(const SessionCache&) = delete;

        SessionCache& operator=(const SessionCache&) = delete;

        virtual ~SessionCache();

        /**
        * Finds if a session handle has associated SessionParameters on the cache.
        * @param    keyHandle   The session handle.
        * @return   bool        True if SessionParameters for the session handle was found on the cache, false otherwise.
        */
        bool find(const uint32_t& sessionHandle) const;

        /**
        * Adds a session handle into the cache.
        * @param sessionHandle          The session handle from the application.
        * @param sessionParameters      The associated session parameters.
        */
        void add(const uint32_t& sessionHandle, const SessionParameters& sessionParameters);

        /**
        * Removes a session handle from the cache.
        * @param    sessionHandle  The session handle.
        * @return   bool           True if success, false otherwise.
        */
        bool remove(const uint32_t& sessionHandle);

        /**
        * Clears all the session handles from the cache.
        */
        void clear();

        /**
        * Returns the number of session handles in the cache.
        */
        uint32_t count() const;

        /**
        * Gets the slotID corresponding to the session handle.
        * @param   sessionHandle  The session handle.
        * @return  CK_SLOT_ID     The slot ID corresponding to sessionHandle.
        */
        CK_SLOT_ID getSlotId(const uint32_t& sessionHandle);

        /**
        * Gets all slot IDs.
        */
        std::vector<CK_SLOT_ID> getAllSlotIDs() const;

        /**
        * Creates a session
        * @param   sessionId    session ID of the created session
        */
        void createSession(uint32_t* sessionId);

        CK_KEY_TYPE getKeyType(const uint32_t& keyHandle) const;

        CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) const;

        bool sessionStateExists(const CK_SLOT_ID& slotID, const SessionState& sessionState) const;

        SessionState getSessionState(const uint32_t& sessionHandle) const;

        bool getObjectParams(const uint32_t& objectHandle, ObjectParameters* objectParams) const;

        bool findObject(const uint32_t& objectHandle) const;

        void removeObject(const uint32_t& sessionHandle, const uint32_t& objectHandle);

        void addObject(const uint32_t&         sessionHandle,
                       const uint32_t&         objectHandle,
                       const ObjectParameters& objectParams);

        bool closeSession(const uint32_t& sessionHandle);

        CK_RV closeAllSessions(const uint32_t& slotId);

        CK_RV findObjectsInit(const uint32_t&   sessionHandle,
                              const Attributes& attributes,
                              const bool&       findAllHandles);

        uint32_t findObjects(const uint32_t&      sessionHandle,
                             CK_OBJECT_HANDLE_PTR phObject,
                             const uint32_t&      ulCount);

        void findObjectsFinal(const uint32_t& sessionHandle);

        bool isUserLoggedIn(const uint32_t& sessionHandle);

        CK_RV createSession(const CK_SLOT_ID& slotId, const CK_FLAGS& flags, uint32_t* sessionId);

        bool logoutRequired(const CK_SLOT_ID& slotId, const uint32_t& sessionHandle) const;

        bool logoutRequired(const CK_SLOT_ID& slotId) const;

        bool checkKeyType(const uint32_t& keyHandle, const CK_KEY_TYPE& keyType) const;

        bool attributeSet(const uint32_t& objectHandle, const BoolAttribute& boolAttribute) const;

        SessionParameters getSessionParameters(const uint32_t& sessionHandle) const;

        bool privateObject(const uint32_t& objectHandle) const;

        bool tokenObject(const uint32_t& objectHandle) const;

        bool isLoggedIn(const CK_SLOT_ID& slotId, const CK_USER_TYPE& userType);

        bool login(const CK_SLOT_ID& slotId, const CK_USER_TYPE& userType);

        bool logout(const CK_SLOT_ID& slotId);

        bool sessionExists(const CK_SLOT_ID& slotId) const;
        
        void updateSessionStateForLogin(const CK_SLOT_ID& slotId, const CK_USER_TYPE& userType);

    private:

        SessionState getSessionStateforNewSession(const CK_SLOT_ID& slotId, const CK_FLAGS& flags) const;

        bool isSessionPublic(const uint32_t& sessionHandle);

        void updateSessionStateForLogout(const CK_SLOT_ID& slotId);


        using SessionHandleCollection = std::map<uint32_t, SessionParameters>;

        SessionHandleCollection mCache{};

        std::vector<uint32_t>   objectHandles{}; // Objects created across all sessions
        ObjectCache             *objectCache = nullptr;

        static std::mutex mCacheMutex;

        struct LoginStatus
        {
            bool soLoggedIn   = false;
            bool userLoggedIn = false;
        };

        using SlotIdCollection = std::map<CK_SLOT_ID, LoginStatus>;
        SlotIdCollection mSlotCache{};
    };
} //P11Crypto
#endif // SESSION_HANDLE_CACHE

