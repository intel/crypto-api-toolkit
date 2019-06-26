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

#include "config.h"

#include <string>
#include <sgx_key.h>

#ifdef DCAP_SUPPORT
#include "sgx_pce.h"
#endif

#include <vector>
#include <bitset>
#include <set>
#include "p11Defines.h"
#include "Constants.h"

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
static const uint8_t  maxSessionsSupported       = 100;
static const uint8_t  maxRwSessionsSupported     = 100;

static const std::string toolkitPath        = CRYPTOTOOLKIT_TOKENPATH;
static const std::string tokenPath          = toolkitPath + "/tokens/";
static const std::string installationPath   = INSTALL_DIRECTORY;
static const std::string libraryDirectory   = installationPath + "/lib/";
static const std::string defaultLibraryPath = "/usr/local/lib/";

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
    rsaPkcs1     = 1,
    rsaNoPadding = 3,
    rsaPkcs1Oaep = 4,
    rsaPkcs1Pss  = 6
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

enum class KeyType : uint8_t
{
    Invalid = 0,
    Aes     = 1,
    Rsa     = 2
};

enum class KeyGenerationMechanism
{
    invalid,
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
    SGX_CRYPT_STATUS_UNSUCCESSFUL


};

// Bool key attributes : Grows in power of 2.
enum BoolAttribute
{
    ENCRYPT              = 1,
    DECRYPT              = 2,
    WRAP                 = 3,
    UNWRAP               = 4,
    SIGN                 = 5,
    VERIFY               = 6,
    TOKEN                = 7,
    PRIVATE              = 8,
    LOCAL                = 9,
    MODIFIABLE           = 10,
    DERIVE               = 11,
    COPYABLE             = 12,
    MAX_BOOL_ATTRIBUTES  = 13
};

using UlongAttributeType  = std::pair<CK_ULONG, CK_ULONG>;
using StringAttributeType = std::pair<CK_ULONG, std::string>;

using UlongAttributeSet  = std::set<UlongAttributeType>;
using StringAttributeSet = std::set<StringAttributeType>;
using BoolAttributeSet   = std::bitset<MAX_BOOL_ATTRIBUTES>;

struct Attributes
{
    BoolAttributeSet   boolAttributes{};
    UlongAttributeSet  ulongAttributes{};
    StringAttributeSet strAttributes{};
};

enum ObjectState
{
    NOT_IN_USE  = 0,
    IN_USE      = 1,
};

struct ObjectParameters
{
    CK_SLOT_ID         slotId;
    CK_SESSION_HANDLE  sessionHandle;
    UlongAttributeSet  ulongAttributes;
    StringAttributeSet strAttributes;
    BoolAttributeSet   boolAttributes;
    ObjectState        objectState;
};

enum class SessionState : CK_ULONG
{
    ROPublic = CKS_RO_PUBLIC_SESSION,
    ROUser   = CKS_RO_USER_FUNCTIONS,
    RWPublic = CKS_RW_PUBLIC_SESSION,
    RWUser   = CKS_RW_USER_FUNCTIONS,
    RWSO     = CKS_RW_SO_FUNCTIONS,
    INVALID  = CKS_INVALID
};

enum class CurrentOperation
{
    None,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Hash
};

enum ActiveOp
{
    Encrypt_None    = 0x00,
    AesEncrypt_Init = 0x01,
    AesEncrypt      = 0x02,

    Decrypt_None    = 0x03,
    AesDecrypt_Init = 0x04,
    AesDecrypt      = 0x05,

    Sign_None       = 0x06,
    Sign_Init       = 0x07,

    Verify_None     = 0x08,
    Verify_Init     = 0x09,

    Hash_None       = 0x0a,
    Hash_Init       = 0x0b,
    Hash            = 0x0c,

    RsaEncrypt_Init = 0x0d,
    RsaDecrypt_Init = 0x0e,

    FindObjects_None = 0x0f,

    Max             = 0x10
};

struct CryptoParams
{
    BlockCipherMode blockCipherMode;
    bool            padding;
    uint32_t        keyHandle;
    uint32_t        currentBufferSize;
    uint32_t        tagBytes;

    CryptoParams()
    {
        clear();
    }

    ~CryptoParams()
    {
        clear();
    }

    void clear()
    {
        blockCipherMode   = BlockCipherMode::unknown;
        padding           = false;
        keyHandle         = 0;
        currentBufferSize = 0;
        tagBytes          = 0;
    }
};

struct HashParams
{
    HashMode hashMode;
    uint32_t hashHandle;

    HashParams()
    {
        clear();
    }

    ~HashParams()
    {
        clear();
    }

    void clear()
    {
        hashMode   = HashMode::invalid;
        hashHandle = 0;
    }
};

struct SignVerifyParams
{
    RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
    uint32_t   keyHandle  = 0;
    HashMode   hashMode   = HashMode::invalid;

    SignVerifyParams()
    {
        clear();
    }

    ~SignVerifyParams()
    {
        clear();
    }

    void clear()
    {
        rsaPadding = RsaPadding::rsaNoPadding;
        keyHandle  = 0;
        hashMode   = HashMode::invalid;
    }
};

struct ActiveOperationData
{
    CryptoParams          encryptParams;
    CryptoParams          decryptParams;
    SignVerifyParams      signParams;
    SignVerifyParams      verifyParams;
    HashParams            hashParams;
    std::vector<uint32_t> foHandles;
};

struct SessionParameters
{
    uint32_t              slotId;
    SessionState          sessionState;
    std::vector<uint32_t> sessionObjectHandles;
    ActiveOperationData   data;
    std::bitset<ActiveOp::Max> activeOperation;

    SessionParameters()
    {
        slotId       = INVALID_SLOT_ID;
        sessionState = SessionState::INVALID;

        sessionObjectHandles.clear();

        activeOperation.set(ActiveOp::Encrypt_None);
        activeOperation.set(ActiveOp::Decrypt_None);
        activeOperation.set(ActiveOp::Sign_None);
        activeOperation.set(ActiveOp::Verify_None);
        activeOperation.set(ActiveOp::Hash_None);
        activeOperation.set(ActiveOp::FindObjects_None);
    }
};

struct SymmetricKeyParams
{
    KeyGenerationMechanism  keyGenMechanism;
    std::vector<uint8_t>    rawKeyBuffer;
    uint32_t                keyLength;

    SymmetricKeyParams()
    {
        clear();
    }

    ~SymmetricKeyParams()
    {
        clear();
    }

    void clear()
    {
        keyGenMechanism = KeyGenerationMechanism::invalid;
        rawKeyBuffer.clear();
        keyLength = 0;
    }
};

struct AsymmetricKeyParams
{
    KeyGenerationMechanism  keyGenMechanism;
    uint32_t                modulusLength;

    AsymmetricKeyParams()
    {
        clear();
    }

    ~AsymmetricKeyParams()
    {
        clear();
    }

    void clear()
    {
        keyGenMechanism = KeyGenerationMechanism::invalid;
        modulusLength = 0;
    }
};

struct RsaCryptParams
{
    RsaPadding rsaPadding = RsaPadding::rsaNoPadding;
};

struct RsaEpidQuoteParams
{
    std::vector<uint8_t> sigRL;
    std::vector<uint8_t> spid;
    uint32_t             signatureType;

    RsaEpidQuoteParams()
    {
        clear();
    }

    ~RsaEpidQuoteParams()
    {
        clear();
    }

    void clear()
    {
        signatureType = INVALID_SIGNATURE;
        sigRL.clear();
        spid.clear();
    }
};

#ifdef DCAP_SUPPORT
struct RsaEcdsaQuoteParams
{
    uint32_t qlPolicy;

    RsaEcdsaQuoteParams()
    {
        reset();
    }

    ~RsaEcdsaQuoteParams()
    {
        reset();
    }

    void reset()
    {
        qlPolicy = SGX_QL_DEFAULT;
    }
};
#endif

struct AesCryptParams
{
    BlockCipherMode      cipherMode;
    std::vector<uint8_t> iv;
    int                  counterBits;
    std::vector<uint8_t> aad;
    uint32_t             tagBits;
    bool                 padding;

    AesCryptParams()
    {
        clear();
    }

    ~AesCryptParams()
    {
        clear();
    }

    void clear()
    {
        cipherMode  = BlockCipherMode::unknown;
        padding     = false;
        counterBits = 0;
        tagBits     = 0;
        aad.clear();
        iv.clear();
    }
};

#endif //CRYPTOENCLAVEDEFS_H

