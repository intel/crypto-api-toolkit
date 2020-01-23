/*
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 UnsupportedAPITests.cpp

 Contains test cases to test unsupported APIs to return errors
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "UnsupportedAPITests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(UnsupportedAPITests);

void UnsupportedAPITests::testGetOperationState()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_GetOperationState(hSession, NULL_PTR, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testSetOperationState()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_SetOperationState(hSession, NULL_PTR, 0, 0, 0) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testDigestKey()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CK_OBJECT_HANDLE hObject{};

    rv = CRYPTOKI_F_PTR( C_DigestKey(hSession, hObject) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testSignRecoverInit()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CK_OBJECT_HANDLE hObject{0};
    CK_MECHANISM mech{};

    rv = CRYPTOKI_F_PTR(C_SignRecoverInit (hSession, &mech, hObject) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testSignRecover()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_SignRecover(hSession, NULL_PTR, 0, NULL_PTR, 0) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testVerifyRecoverInit()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_VerifyRecoverInit (hSession, NULL_PTR, 0) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testVerifyRecover()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_VerifyRecover(hSession, NULL_PTR, 0, NULL_PTR, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testDigestEncryptUpdate()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_DigestEncryptUpdate(hSession, NULL_PTR, 0, NULL_PTR, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testDecryptDigestUpdate()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_DecryptDigestUpdate(hSession, NULL_PTR, 0, NULL_PTR, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testSignEncryptUpdate()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_SignEncryptUpdate(hSession, NULL_PTR, 0, NULL_PTR, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testDecryptVerifyUpdate()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_DecryptVerifyUpdate(hSession, NULL_PTR, 0, NULL_PTR, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testDeriveKey()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testSeedRandom()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_SeedRandom(hSession, NULL_PTR, 0) );
    CPPUNIT_ASSERT(rv == CKR_RANDOM_SEED_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void UnsupportedAPITests::testWaitForSlotEvent()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_WaitForSlotEvent(0, NULL_PTR, NULL_PTR)  );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

// This is not an unsupported function, but a legacy function returning a standard error code
void UnsupportedAPITests::testGetFunctionStatus()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_GetFunctionStatus(hSession) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_PARALLEL);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

// This is not an unsupported function, but a legacy function returning a standard error code
void UnsupportedAPITests::testCancelFunction()
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_CancelFunction(hSession) );
    CPPUNIT_ASSERT(rv == CKR_FUNCTION_NOT_PARALLEL);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
    CPPUNIT_ASSERT(rv == CKR_OK);

    CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

