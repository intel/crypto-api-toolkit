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
enum SessionOperation
{
    // Hash operations...
    SESSION_HASH_OP_NONE = 0,
    SESSION_HASH_OP_INIT,
    SESSION_HASH_OP_DIGEST,

    // Encryption/Decryption operations..
    SESSION_OP_ENCRYPT_NONE,
    SESSION_OP_DECRYPT_NONE,
    SESSION_OP_SYMMETRIC_ENCRYPT_INIT,
    SESSION_OP_SYMMETRIC_ENCRYPT,
    SESSION_OP_SYMMETRIC_DECRYPT_INIT,
    SESSION_OP_SYMMETRIC_DECRYPT,
    SESSION_OP_ASYMMETRIC_ENCRYPT_INIT,
    SESSION_OP_ASYMMETRIC_ENCRYPT,
    SESSION_OP_ASYMMETRIC_DECRYPT_INIT,
    SESSION_OP_ASYMMETRIC_DECRYPT,

    // Sign/Verify operations..
    SESSION_OP_SIGN_NONE,
    SESSION_OP_VERIFY_NONE,
    SESSION_OP_SIGN_INIT,
    SESSION_OP_VERIFY_INIT,

    // FindObjects operations..
    SESSION_OP_FIND_OBJECTS_NONE,
    SESSION_OP_FIND_OBJECTS_INIT,
};

// Key attributes : Grows in power of 2.
enum KeyAttribute
{
    ENCRYPT      = 0x00000001, // 1
    DECRYPT      = 0x00000002, // 2
    WRAP         = 0x00000004, // 4
    UNWRAP       = 0x00000008, // 8
    SIGN         = 0x00000010, // 16
    VERIFY       = 0x00000020, // 32
    TOKEN        = 0x00000040, // 64
    PRIVATE      = 0x00000080, // 128
    LOCAL        = 0x00000100, // 256
    MODIFIABLE   = 0x00000200, // 512
    DERIVE       = 0x00000400, // 1024
    COPYABLE     = 0x00000800  // 2048
};

enum QuoteSignatureType
{
    UNLINKABLE_SIGNATURE = 1,
    LINKABLE_SIGNATURE   = 2
};

// Custom error codes..
#define CKR_DEVICE_TABLE_FULL            0x80000001UL
#define CKR_CIPHER_OPERATION_FAILED      0x80000002UL
#define CKR_PLATFORM_SEAL_UNSEAL_FAILED  0x80000003UL
#define CKR_POWER_STATE_INVALID          0x80000004UL
#define CKR_LOGGED_IN                    0x80000005UL
#define CKR_NOT_LOGGED                   0x80000006UL
#define CKR_USER_PIN_ALREADY_INITIALIZED 0x80000007UL
#define CKR_OPERATION_NOT_PERMITTED      0x80000008UL

typedef unsigned char Byte;

typedef int SgxStatus;

#endif //CONSTANTS_H

