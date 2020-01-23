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
 UnsupportedAPITests.h

 Contains test cases to test unsupported APIs to return errors
 *****************************************************************************/

#ifndef _SOFTHSM_V2_UNSUPPORTEDAPITESTS_H
#define _SOFTHSM_V2_UNSUPPORTEDAPITESTS_H

#include "TestsNoPINInitBase.h"
#include <cppunit/extensions/HelperMacros.h>

class UnsupportedAPITests : public TestsNoPINInitBase
{
    CPPUNIT_TEST_SUITE(UnsupportedAPITests);
    CPPUNIT_TEST(testGetOperationState);
    CPPUNIT_TEST(testSetOperationState);
    CPPUNIT_TEST(testDigestKey);
    CPPUNIT_TEST(testSignRecoverInit);
    CPPUNIT_TEST(testSignRecover);
    CPPUNIT_TEST(testVerifyRecoverInit);
    CPPUNIT_TEST(testVerifyRecover);
    CPPUNIT_TEST(testDigestEncryptUpdate);
    CPPUNIT_TEST(testDecryptDigestUpdate);
    CPPUNIT_TEST(testSignEncryptUpdate);
    CPPUNIT_TEST(testDecryptVerifyUpdate);
    CPPUNIT_TEST(testDeriveKey);
    CPPUNIT_TEST(testSeedRandom);
    CPPUNIT_TEST(testWaitForSlotEvent);
    CPPUNIT_TEST(testGetFunctionStatus);
    CPPUNIT_TEST(testCancelFunction);
    CPPUNIT_TEST_SUITE_END();

public:
    void testGetOperationState();
    void testSetOperationState();
    void testDigestKey();
    void testSignRecoverInit();
    void testSignRecover();
    void testVerifyRecoverInit();
    void testVerifyRecover();
    void testDigestEncryptUpdate();
    void testDecryptDigestUpdate();
    void testSignEncryptUpdate();
    void testDecryptVerifyUpdate();
    void testDeriveKey();
    void testSeedRandom();
    void testWaitForSlotEvent();
    void testGetFunctionStatus();
    void testCancelFunction();
};

#endif // !_SOFTHSM_V2_UNSUPPORTEDAPITESTS_H
