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

#ifndef SESSION_HANDLE_CACHE
#define SESSION_HANDLE_CACHE

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "CryptoEnclaveDefs.h"
#include "Constants.h"
#include "p11Defines.h"

namespace P11Crypto
{
    struct CryptoParams
    {
        BlockCipherMode blockCipherMode   = BlockCipherMode::unknown;
        bool            padding           = false;
        uint32_t        keyHandle         = 0;
        uint32_t        currentBufferSize = 0;
        uint32_t        tagBytes          = 0;
    };

    struct HashParams
    {
        HashMode hashMode   = HashMode::invalid;
        uint32_t hashHandle = 0;
    };

    struct SignVerifyParams
    {
        RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
        uint32_t   keyHandle  = 0;
        HashMode   hashMode   = HashMode::invalid;
    };

    enum class SessionLoginState
    {
        NONE = 0,
        SO   = 1,
        USER = 2
    };

    enum class SessionState
    {
        STATE_NONE      = 0,
        RW_PUBLIC_STATE = 1,
        RO_PUBLIC_STATE = 2,
        RW_SO_STATE     = 3,
        RW_USER_STATE   = 4,
        RO_USER_STATE   = 5
    };

    struct SessionParameters
    {
        // Parameters for encryption, decryption, hash, hmac, sign and verify
        CryptoParams     encryptParams;
        CryptoParams     decryptParams;
        HashParams       hashParams;
        SignVerifyParams signParams;
        SignVerifyParams verifyParams;

        // Session operation modes, all these operations can continue simulataneously..
        SessionOperation encryptOperation     = SessionOperation::SESSION_OP_ENCRYPT_NONE;
        SessionOperation decryptOperation     = SessionOperation::SESSION_OP_DECRYPT_NONE;
        SessionOperation hashOperation        = SessionOperation::SESSION_HASH_OP_NONE;
        SessionOperation signOperation        = SessionOperation::SESSION_OP_SIGN_NONE;
        SessionOperation verifyOperation      = SessionOperation::SESSION_OP_VERIFY_NONE;
        SessionOperation findObjectsOperation = SessionOperation::SESSION_OP_FIND_OBJECTS_NONE;

        // Slot ID
        CK_SLOT_ID slotID;

        // Session State
        SessionState sessionState;

        // All key handles that match a template (for FindObjects API)
        std::vector<uint32_t> keyHandles;
    };

    class SessionHandleCache
    {
    public:
        static std::shared_ptr<SessionHandleCache> getSessionHandleCache();

        /**
        * Finds if a session handle has associated SessionParameters on the cache.
        * @param    keyHandle   The session handle.
        * @return   bool        True if SessionParameters for the session handle was found on the cache, false otherwise.
        */
        bool find(const uint32_t& sessionHandle) const;

        /**
        * Gets the session parameters from the cache.
        * @param    sessionHandle       The session handle from provider.
        * @return   SessionParameters   The session parameters associated with sessionHandle.
        */
        SessionParameters get(const uint32_t& sessionHandle) const;

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
        * Gets all session handles in the cache.
        * @param   sessionHandles   A vector to hold all session handles in the cache.
        */
        void getAllSessionHandles(std::vector<uint32_t>& sessionHandles);

        /**
        * Gets all session handles in the slotID from the cache.
        * @param   slotID                 The slot ID.
        * @param   sessionHandles         A vector to hold all session handles.
        */
        void getSessionHandlesInSlot(CK_SLOT_ID slotID, std::vector<uint32_t>& sessionHandles);

        /**
        * Gets the slotID corresponding to the session handle.
        * @param   sessionHandle  The session handle.
        * @return  CK_SLOT_ID     The slot ID corresponding to sessionHandle.
        */
        CK_SLOT_ID getSlotID(const uint32_t& sessionHandle);

        /**
        * Gets the session state corresponding to the session handle.
        * @param   sessionHandle  The session handle.
        * @return  SessionState   The session state corresponding to sessionHandle.
        */
        SessionState getSessionState(const uint32_t& sessionHandle);

        /**
        * Checks if a slot has atleast one RO session.
        * @param   slotID   The slot ID.
        * @return  bool     True if the is atleast one RO session in slot, false otherwise.
        */
        bool hasROSessionInSlot(const CK_SLOT_ID& slotID);

        /**
        * Checks if a slot has user logged in RO session.
        * @param   slotID   The slot ID.
        * @return  bool     True if the is an RO session with user logged in, in the slot, false otherwise.
        */
        bool hasUserLoggedInROSession(const CK_SLOT_ID& slotID);

        /**
        * Checks if a slot has user logged in RW session.
        * @param   slotID   The slot ID.
        * @return  bool     True if the is an RW session with user logged in, in the slot, false otherwise.
        */
        bool hasUserLoggedInRWSession(const CK_SLOT_ID& slotID);

        /**
        * Checks if a slot has SO logged in session.
        * @param   slotID   The slot ID.
        * @return  bool     True if the is slot has SO logged in session, false otherwise.
        */
        bool hasSOLoggedInSession(const CK_SLOT_ID& slotID);

        /**
        * Checks if a session is RW session.
        * @param   sessionHandle  The session handle.
        * @return  bool           True if the session is an RW session, false otherwise.
        */
        bool isRWSession(const uint32_t& sessionHandle);

        /**
        * Updates the session state of a session.
        * @param   sessionHandle  The session handle.
        * @param   sessionState   The new session state.
        */
        void updateSessionState(const uint32_t& sessionHandle, const SessionState& sessionState);

        /**
        * Gets all slot IDs.
        * @param   slotIDs A vector of all slot IDs.
        */
        void getAllSlotIDs(std::vector<CK_SLOT_ID>& slotIDs);

        /**
        * Updates the vector of key handles in the cache, associated with session handle passed.
        * @param  sessionHandle     The session handle.
        * @param  keyHandles        The key handles.
        */
        void updateMatchedKeyHandles(const uint32_t&              sessionHandle,
                                     const std::vector<uint32_t>& keyHandles);

        /**
        * Gets a list of key handles in the cache, associated with session handle passed.
        * @param   sessionHandle     The session handle.
        * @param   phObject          A pointer where the key handles are to be placed.
        * @param   ulCount           The number of key handles that can be placed in phObject.
        * @return  uint32_t          The number of key handles that are copied into phObject.
        */
        uint32_t getMatchedKeyHandles(const uint32_t&      sessionHandle,
                                      CK_OBJECT_HANDLE_PTR phObject,
                                      const uint32_t&      ulCount);

        /**
        * Clears the vector of key handles in the cache, associated with session handle passed.
        * @param   sessionHandle     The session handle.
        */
        void clearMatchedKeyHandles(const uint32_t& sessionHandle);

        /**
        * Returns if the slot ID passed has only one session.
        * @param   slotID     The slot ID.
        * @return  bool       Returns true if there is only one session open in slot ID passed, false otherwise.
        */
        bool isLastSessionInSlot(const CK_SLOT_ID& slotID);

    private:
        struct SessionParametersData
        {
            SessionParameters  data;

            SessionParametersData();
            SessionParametersData(const SessionParameters& sessionParameters);
        };
        typedef std::map<uint32_t, SessionParametersData> sessionHandleCollection;
        typedef sessionHandleCollection::iterator  CacheCollectionIterator;
        typedef sessionHandleCollection::const_iterator CacheCollectionConstIterator;

        // Member variables
        sessionHandleCollection mCache;
        static std::mutex mCacheMutex;

        std::vector<CK_SLOT_ID> slotIDs;
    };
} //P11Crypto
#endif // SESSION_HANDLE_CACHE

