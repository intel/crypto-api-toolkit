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

#ifndef CRYPTOENCLAVEDEFS_H
#define CRYPTOENCLAVEDEFS_H

#include <string>
#include "config.h"

static const uint8_t  bitsPerByte                = 8;
static const uint8_t  aesBlockSize               = 16;
static const uint8_t  maxAesKeySizeForHmacImport = 200;
static const uint8_t  supportedIvSize            = 16;
static const uint8_t  minTagLengthSupported      = 12;
static const uint8_t  maxTagLengthSupported      = 16;
static const uint32_t minCounterBitsSupported    = 1;
static const uint32_t maxCounterBitsSupported    = 128;
static const uint8_t  maxSlotsSupported          = 100;
static const uint8_t  minPinLength               = 1;
static const uint8_t  maxPinLength               = 255;
static const uint8_t  maxSessionCount            = 100;

static const std::string toolkitPath        = CRYPTOTOOLKIT_TOKENPATH;
static const std::string tokenPath          = toolkitPath + "/tokens/";
static const std::string installationPath   = INSTALL_DIRECTORY;
static const std::string libraryDirectory   = installationPath + "/lib/";
static const std::string defaultLibraryPath = "/usr/local/lib/";

enum class ProviderType
{
    Unknown = 0,
    PKCS11
};

// Supported AES block cipher modes.
enum class BlockCipherMode
{
    unknown = 0,
    ctr     = 1,
    gcm     = 2,
    cbc     = 3,
    ecb     = 4
};

enum class HashMode
{
    invalid     = 0,
    sha1        = 1,
    sha256      = 2,
    sha224      = 3,
    sha512      = 4,
    sha384      = 5,
    md5         = 6,
    sm3         = 7,
    sha512_224  = 8,
    sha512_256  = 9,
};

enum class HashDigestLength
{
    invalid     = 0,
    sha1        = 20,
    sha256      = 32,
    sha224      = 28,
    sha512      = 64,
    sha384      = 48,
    md5         = 16,
    sm3         = 32,
    sha512_224  = 32,
    sha512_256  = 32,
};

// Crypt Params to pass in for encrypt/decrypt
enum class KeyWrapMode
{
    raw,
    platformBind,
    rsa,
    ctr,
    gcm,
    cbc,
    ecb
};

// Active session operation
enum class ActiveOperation
{
    NONE,
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    HASH
};

enum class SymmetricKeySize
{
    keyLength128 = 16,
    keyLength192 = 24,
    keyLength256 = 32
};

enum class AsymmetricKeySize
{
    keyLength1024 = 1024,
    keyLength2048 = 2048,
    keyLength3072 = 3072,
    keyLength4096 = 4096
};

enum class SgxMaxKeyLimits
{
    symmetric   = 64,
    asymmetric  = 128,
    hash        = 64
};

enum class SgxMaxDataLimitsInBytes
{
    hash                 = 10 * 1024 * 1024,
    symmetric            = 10 * 1024 * 1024,
    asymmetric           = 1  * 1024 * 1024,
    cipherTextSizeForGCM = 30 * 1024 * 1024
};

enum class RsaPadding
{
    rsaNoPadding = 3,
    rsaPkcs1Oaep,
    rsaPkcs1,
    rsaSslv23,
    rsaX391,
    rsaPkcs1Pss
};

enum class BlockCipherPadding
{
    NoPadding,
    BlockPadding,
};

enum class UpdateSession
{
    OPEN  = 0,
    CLOSE = 1
};

enum class KeyGenerationMechanism
{
    aesGenerateKey,
    aesImportRawKey,
    rsaGeneratePublicKey,
    rsaGeneratePrivateKey,
    aesCTRUnwrapKey,
    aesGCMUnwrapKey,
    aesCBCUnwrapKey,
    aesCBCPADUnwrapKey,
    rsaUnwrapKey,
    rsaImportPublicKey,
    aesImportPbindKey,
    rsaImportPbindPublicKey,
    rsaImportPbindPrivateKey
};

// SGX status Codes
enum class SgxCryptStatus
{
    SGX_CRYPT_STATUS_SUCCESS,
    SGX_CRYPT_STATUS_CIPHER_OPERATION_FAILED,
    SGX_CRYPT_STATUS_BUFFER_TOO_SHORT,
    SGX_CRYPT_STATUS_INVALID_PARAMETER,
    SGX_CRYPT_STATUS_SEALED_DATA_FAILED,
    SGX_CRYPT_STATUS_KEY_TABLE_FULL,
    SGX_CRYPT_STATUS_INVALID_KEY_HANDLE,
    SGX_CRYPT_STATUS_INVALID_BLOCK_CIPHER_MODE,
    SGX_CRYPT_STATUS_OUT_OF_MEMORY,
    SGX_CRYPT_STATUS_INVALID_SIGNATURE_LENGTH,
    SGX_CRYPT_STATUS_INVALID_SIGNATURE,
    SGX_CRYPT_STATUS_HASH_STATE_TABLE_FULL,
    SGX_CRYPT_STATUS_INVALID_WRAPPED_KEY,
    SGX_CRYPT_STATUS_INVALID_TAG_SIZE,
    SGX_CRYPT_STATUS_INVALID_BUFFER_SIZE,
    SGX_CRYPT_STATUS_UNSUCCESSFUL,
    SGX_CRYPT_STATUS_SESSION_EXISTS,
    SGX_CRYPT_STATUS_LOGGED_IN,
    SGX_CRYPT_STATUS_NOT_LOGGED
};
#endif //CRYPTOENCLAVEDEFS_H

