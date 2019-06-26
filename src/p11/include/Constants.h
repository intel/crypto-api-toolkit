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

#ifndef CONSTANTS_H
#define CONSTANTS_H

// Minimum and maximum tag sizes supported
const int minTagSize = 12;
const int maxTagSize = 16;

// Supported RSA Key sizes
const int rsaKeySize1024 = 1024;
const int rsaKeySize2048 = 2048;
const int rsaKeySize3072 = 3072;
const int rsaKeySize4096 = 4096;

// Supported Salt value for RSA signing
const int saltSizeBytes = 32;

// Supported algorithm ID value for RSA signing
const int hashAlgorithmIdSha256 = 672;

// Current session operation modes
enum SessionOpState
{
    // Hash operations
    SESSION_HASH_OP_INIT                = 1,
    SESSION_HASH_OP_DIGEST              = 2,

    // Symmetric Encrypt
    SESSION_OP_SYMMETRIC_ENCRYPT_INIT   = 3,
    SESSION_OP_SYMMETRIC_ENCRYPT        = 4,

    // Symmetric Decrypt
    SESSION_OP_SYMMETRIC_DECRYPT_INIT   = 5,
    SESSION_OP_SYMMETRIC_DECRYPT        = 6,

    // Asymmetric Encrypt
    SESSION_OP_ASYMMETRIC_ENCRYPT_INIT  = 9,
    SESSION_OP_ASYMMETRIC_ENCRYPT       = 10,

    // Asymmetric Decrypt
    SESSION_OP_ASYMMETRIC_DECRYPT_INIT  = 11,
    SESSION_OP_ASYMMETRIC_DECRYPT       = 12,

    // Sign/Verify operations
    SESSION_OP_SIGN_INIT                = 15,
    SESSION_OP_VERIFY_INIT              = 16,

    // FindObjects operations
    SESSION_OP_FIND_OBJECTS_INIT        = 17,
    SESSION_OP_FIND_OBJECTS             = 18,

    SESSION_OP_MAX                      = 19
};

typedef unsigned char Byte;

typedef int SgxStatus;

#endif //CONSTANTS_H

