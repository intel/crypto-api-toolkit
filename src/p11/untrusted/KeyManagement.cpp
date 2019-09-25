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

#include "KeyManagement.h"

static KeyGenMechanismAttributeValue getKeyMechanismAttributeValue(const AesCryptParams& aesUnwrapParams)
{
    KeyGenMechanismAttributeValue kgmav{KeyGenerationMechanism::invalid, CKM_VENDOR_DEFINED_INVALID};

    switch(aesUnwrapParams.cipherMode)
    {
        case BlockCipherMode::cbc:
            kgmav.first = KeyGenerationMechanism::aesCBCUnwrapKey;
            if (aesUnwrapParams.padding)
            {
                kgmav.second = CKM_AES_CBC_PAD;
            }
            else
            {
                kgmav.second = CKM_AES_CBC;
            }
            break;
        case BlockCipherMode::gcm:
            kgmav.first = KeyGenerationMechanism::aesGCMUnwrapKey;
            kgmav.second = CKM_AES_GCM;
            break;
        case BlockCipherMode::ctr:
            kgmav.first = KeyGenerationMechanism::aesCTRUnwrapKey;
            kgmav.second = CKM_AES_CTR;
            break;
        default:
            break;
    }

    return kgmav;
}

//---------------------------------------------------------------------------------------------
CK_RV generateKey(CK_SESSION_HANDLE    hSession,
                  CK_MECHANISM_PTR     pMechanism,
                  CK_ATTRIBUTE_PTR     pTemplate,
                  CK_ULONG             ulCount,
                  CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!phKey || !pMechanism || !pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!hSession || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (CKM_AES_KEY_GEN != pMechanism->mechanism)
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        if (nullptr != pMechanism->pParameter ||
            0       != pMechanism->ulParameterLen)
        {
            rv = CKR_MECHANISM_PARAM_INVALID;
            break;
        }

        rv = P11Crypto::checkWriteAccess(hSession, pTemplate, ulCount);
        if (CKR_OK != rv)
        {
            break;
        }

        StringAttributeSet strAttributes{};
        UlongAttributeSet  ulongAttributes{};
        BoolAttributeSet   boolAttributes{};
        SymmetricKeyParams symKeyParams{};
        Utils::AttributeUtils::AttributeValidatorStruct attrValStruct{};

        rv = Utils::AttributeUtils::extractAttributesFromTemplate(pTemplate,
                                                                  ulCount,
                                                                  &ulongAttributes,
                                                                  &strAttributes,
                                                                  &boolAttributes,
                                                                  &attrValStruct);

        if (CKR_OK != rv)
        {
            break;
        }

        rv = Utils::AttributeUtils::getAesKeyGenParameters(ulongAttributes,
                                                           strAttributes,
                                                           boolAttributes,
                                                           &symKeyParams);

        if (CKR_OK != rv)
        {
            break;
        }

        KeyGenerationMechanism keyGenMechanism = symKeyParams.keyGenMechanism;

        Utils::AttributeUtils::addDefaultAttributes(keyGenMechanism, &boolAttributes);

        ulongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_AES_KEY_GEN));

        bool importKey   = (keyGenMechanism == KeyGenerationMechanism::aesImportRawKey);
        bool generateKey = (keyGenMechanism == KeyGenerationMechanism::aesGenerateKey);

        if ((!importKey && !generateKey) ||
             (generateKey && !Utils::AttributeUtils::isSupportedSymKeyLength(symKeyParams.keyLength)) ||
             !Utils::AttributeUtils::validateAesKeyGenAttributes(keyGenMechanism, attrValStruct))
        {
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
            break;
        }

        std::vector<CK_ULONG> packedAttributes;

        CK_SLOT_ID slotId = gSessionCache->getSlotId(hSession);
        if (slotId > maxSlotsSupported)
        {
            rv = CKR_GENERAL_ERROR;
            break;
        }

        bool tokenObject = boolAttributes.test(Utils::AttributeUtils::p11AttributeToBoolAttribute[CKA_TOKEN]);
        if (tokenObject)
        {
            if (!Utils::AttributeUtils::packAttributes(slotId,
                                                       ulongAttributes,
                                                       strAttributes,
                                                       boolAttributes,
                                                       &packedAttributes))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }
        }

        rv = P11Crypto::SymmetricProvider::generateAesKey(symKeyParams, importKey, packedAttributes, phKey);
        if (CKR_OK != rv)
        {
            break;
        }

        if (!symKeyParams.rawKeyBuffer.empty())
        {
            symKeyParams.rawKeyBuffer.clear();
            auto strAttrIter = std::find_if(strAttributes.begin(), strAttributes.end(), [](const StringAttributeType& p)
                                    {
                                        return (p.first == CKA_VALUE_KEY_BUFFER);
                                    });

            if (strAttrIter != std::end(strAttributes))
            {
                strAttributes.erase(strAttrIter);
            }
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        ObjectParameters objectParams {};

        objectParams.slotId          = slotId;
        objectParams.sessionHandle   = sessionId;
        objectParams.ulongAttributes = ulongAttributes;
        objectParams.strAttributes   = strAttributes;
        objectParams.boolAttributes  = boolAttributes;
        objectParams.objectState     = ObjectState::NOT_IN_USE;

        gSessionCache->addObject(sessionId, *phKey, objectParams);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV generateKeyPair(CK_SESSION_HANDLE    hSession,
                      CK_MECHANISM_PTR     pMechanism,
                      CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
                      CK_ULONG             ulPublicKeyAttributeCount,
                      CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
                      CK_ULONG             ulPrivateKeyAttributeCount,
                      CK_OBJECT_HANDLE_PTR phPublicKey,
                      CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism         ||
            !phPublicKey        || !phPrivateKey ||
            !pPublicKeyTemplate || !pPrivateKeyTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        bool ecKpGeneration  = (CKM_EC_KEY_PAIR_GEN == pMechanism->mechanism);
        bool rsaKpGeneration = (CKM_RSA_PKCS_KEY_PAIR_GEN == pMechanism->mechanism);
        bool edKpGeneration  = (CKM_EC_EDWARDS_KEY_PAIR_GEN == pMechanism->mechanism);

        if (!hSession || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkWriteAccess(hSession, pPublicKeyTemplate, ulPublicKeyAttributeCount);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = P11Crypto::checkWriteAccess(hSession, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
        if (CKR_OK != rv)
        {
            break;
        }

        StringAttributeSet  publicStrAttributes{};
        UlongAttributeSet   publicUlongAttributes{};
        BoolAttributeSet    publicBoolAttributes{};
        AsymmetricKeyParams asymKeyParams{};
        Utils::AttributeUtils::AttributeValidatorStruct publicAttrValStruct{}, privateAttrValStruct{};

        rv = Utils::AttributeUtils::extractAttributesFromTemplate(pPublicKeyTemplate,
                                                                  ulPublicKeyAttributeCount,
                                                                  &publicUlongAttributes,
                                                                  &publicStrAttributes,
                                                                  &publicBoolAttributes,
                                                                  &publicAttrValStruct);

        if (CKR_OK != rv)
        {
            break;
        }

        if (rsaKpGeneration)
        {
            rv = Utils::AttributeUtils::getRsaKeyGenParameters(publicUlongAttributes,
                                                               publicStrAttributes,
                                                               publicBoolAttributes,
                                                               &asymKeyParams);
            if (CKR_OK != rv)
            {
                break;
            }

            if (KeyGenerationMechanism::invalid == asymKeyParams.keyGenMechanism)
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            Utils::AttributeUtils::addDefaultAttributes(asymKeyParams.keyGenMechanism, &publicBoolAttributes);

            if ((asymKeyParams.keyGenMechanism != KeyGenerationMechanism::rsaGeneratePublicKey  ||
                !Utils::AttributeUtils::isSupportedAsymKeyLength(asymKeyParams.modulusLength)   ||
                !Utils::AttributeUtils::validateRsaKeyGenAttributes(asymKeyParams.keyGenMechanism, publicAttrValStruct)))
            {
                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
            }
        }
        else if (ecKpGeneration || edKpGeneration)
        {
            rv = Utils::AttributeUtils::getEcKeyGenParameters(publicStrAttributes, &asymKeyParams);
            if (CKR_OK != rv)
            {
                break;
            }

            if (KeyGenerationMechanism::invalid == asymKeyParams.keyGenMechanism ||
                asymKeyParams.curveOid.empty())
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            if (edKpGeneration)
            {
                asymKeyParams.keyGenMechanism = KeyGenerationMechanism::edGeneratePublicKey;
            }

            Utils::AttributeUtils::addDefaultAttributes(asymKeyParams.keyGenMechanism, &publicBoolAttributes);

            if (!validateEcKeyGenAttributes(asymKeyParams.keyGenMechanism, publicAttrValStruct, publicBoolAttributes))
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        StringAttributeSet privateStrAttributes{};
        UlongAttributeSet  privateUlongAttributes{};
        BoolAttributeSet   privateBoolAttributes{};

        rv = Utils::AttributeUtils::extractAttributesFromTemplate(pPrivateKeyTemplate,
                                                                  ulPrivateKeyAttributeCount,
                                                                  &privateUlongAttributes,
                                                                  &privateStrAttributes,
                                                                  &privateBoolAttributes,
                                                                  &privateAttrValStruct);

        if (CKR_OK != rv)
        {
            break;
        }

        if (!Utils::AttributeUtils::validateId(publicStrAttributes, privateStrAttributes))
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
            break;
        }

        bool tokenObjectPublicKey  = publicBoolAttributes.test(Utils::AttributeUtils::p11AttributeToBoolAttribute[CKA_TOKEN]);
        bool tokenObjectPrivateKey = privateBoolAttributes.test(Utils::AttributeUtils::p11AttributeToBoolAttribute[CKA_TOKEN]);

        std::vector<CK_ULONG> packedAttributesPublic, packedAttributesPrivate;

        CK_SLOT_ID slotId = gSessionCache->getSlotId(hSession);
        if (slotId > maxSlotsSupported)
        {
            rv = CKR_GENERAL_ERROR;
            break;
        }

        if (rsaKpGeneration || ecKpGeneration || edKpGeneration)
        {
            if (rsaKpGeneration)
            {
                asymKeyParams.keyGenMechanism = KeyGenerationMechanism::rsaGeneratePrivateKey;
                Utils::AttributeUtils::addDefaultAttributes(asymKeyParams.keyGenMechanism, &privateBoolAttributes);

                if (!Utils::AttributeUtils::validateRsaKeyGenAttributes(asymKeyParams.keyGenMechanism, privateAttrValStruct))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                publicUlongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN));
                privateUlongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN));
            }
            else if (ecKpGeneration)
            {
                asymKeyParams.keyGenMechanism = KeyGenerationMechanism::ecGeneratePrivateKey;
                Utils::AttributeUtils::addDefaultAttributes(asymKeyParams.keyGenMechanism, &privateBoolAttributes);

                if (!Utils::AttributeUtils::validateEcKeyGenAttributes(asymKeyParams.keyGenMechanism, privateAttrValStruct, privateBoolAttributes))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                publicUlongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN));
                privateUlongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN));
            }
            else if (edKpGeneration)
            {
                asymKeyParams.keyGenMechanism = KeyGenerationMechanism::edGeneratePrivateKey;
                Utils::AttributeUtils::addDefaultAttributes(asymKeyParams.keyGenMechanism, &privateBoolAttributes);

                if (!Utils::AttributeUtils::validateEcKeyGenAttributes(asymKeyParams.keyGenMechanism, privateAttrValStruct, privateBoolAttributes))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                publicUlongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_EC_EDWARDS_KEY_PAIR_GEN));
                privateUlongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, CKM_EC_EDWARDS_KEY_PAIR_GEN));
            }

            if (tokenObjectPrivateKey)
            {
                if (!Utils::AttributeUtils::packAttributes(slotId,
                                                           privateUlongAttributes,
                                                           privateStrAttributes,
                                                           privateBoolAttributes,
                                                           &packedAttributesPrivate))
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }
            }

            if (tokenObjectPublicKey)
            {
                if (!Utils::AttributeUtils::packAttributes(slotId,
                                                           publicUlongAttributes,
                                                           publicStrAttributes,
                                                           publicBoolAttributes,
                                                           &packedAttributesPublic))
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }
            }

            if (rsaKpGeneration)
            {
                rv = P11Crypto::AsymmetricProvider::generateRsaKeyPair(asymKeyParams,
                                                                       packedAttributesPublic,
                                                                       packedAttributesPrivate,
                                                                       phPublicKey,
                                                                       phPrivateKey);
            }
            else if (ecKpGeneration || edKpGeneration)
            {
                rv = P11Crypto::AsymmetricProvider::generateEcc(asymKeyParams,
                                                                packedAttributesPublic,
                                                                packedAttributesPrivate,
                                                                phPublicKey,
                                                                phPrivateKey);
            }

            if (CKR_OK != rv)
            {
                break;
            }
        }
        else
        {
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        ObjectParameters objectParams{ };

        objectParams.slotId          = gSessionCache->getSlotId(hSession);
        objectParams.sessionHandle   = sessionId;
        objectParams.ulongAttributes = publicUlongAttributes;
        objectParams.strAttributes   = publicStrAttributes;
        objectParams.boolAttributes  = publicBoolAttributes;
        objectParams.objectState     = ObjectState::NOT_IN_USE;

        gSessionCache->addObject(sessionId, *phPublicKey, objectParams);

        if (*phPrivateKey)
        {
            objectParams.slotId          = gSessionCache->getSlotId(hSession);
            objectParams.sessionHandle   = sessionId;
            objectParams.ulongAttributes = privateUlongAttributes;
            objectParams.strAttributes   = privateStrAttributes;
            objectParams.boolAttributes  = privateBoolAttributes;
            objectParams.objectState     = ObjectState::NOT_IN_USE;

            gSessionCache->addObject(sessionId, *phPrivateKey, objectParams);
        }
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV populateWrapParameters(const CK_MECHANISM_PTR pMechanism,
                                    WrapParams*            wrapParams,
                                    WrapMode*              wrapMode)
{
    CK_RV rv = CKR_OK;

    if (!pMechanism || !wrapParams || !wrapMode)
    {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_AES_CTR:
            wrapParams->aesParams.clear();
            if (!pMechanism->pParameter || (sizeof(CK_AES_CTR_PARAMS) != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::Aes;

            wrapParams->aesParams.counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
            if (!Utils::AttributeUtils::isSupportedCounterBitsSize(wrapParams->aesParams.counterBits))
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }

            wrapParams->aesParams.iv.resize(16);
            memcpy(&wrapParams->aesParams.iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
            wrapParams->aesParams.cipherMode = BlockCipherMode::ctr;
            break;

        case CKM_AES_GCM:
            wrapParams->aesParams.clear();
            if (!pMechanism->pParameter || sizeof(CK_GCM_PARAMS) != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::Aes;

            wrapParams->aesParams.iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
            memcpy(&wrapParams->aesParams.iv[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);

            wrapParams->aesParams.aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
            memcpy(&wrapParams->aesParams.aad[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);

            wrapParams->aesParams.tagBits = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
            {
                auto tagBytes = wrapParams->aesParams.tagBits >> 3;
                if (tagBytes < minTagSize ||
                    tagBytes > maxTagSize)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            wrapParams->aesParams.cipherMode = BlockCipherMode::gcm;
            break;

        case CKM_AES_CBC:
            wrapParams->aesParams.clear();
            if (!pMechanism->pParameter || (0 == pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::Aes;

            wrapParams->aesParams.iv.resize(pMechanism->ulParameterLen);
            memcpy(&wrapParams->aesParams.iv[0],
                   pMechanism->pParameter,
                   pMechanism->ulParameterLen);

            wrapParams->aesParams.cipherMode = BlockCipherMode::cbc;
            break;

        case CKM_AES_CBC_PAD:
            wrapParams->aesParams.clear();
            if (!pMechanism->pParameter || (0 == pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::Aes;

            wrapParams->aesParams.iv.resize(pMechanism->ulParameterLen);
            memcpy(&wrapParams->aesParams.iv[0],
                   pMechanism->pParameter,
                   pMechanism->ulParameterLen);

            wrapParams->aesParams.cipherMode = BlockCipherMode::cbc;
            wrapParams->aesParams.padding    = true;
            break;

        case CKM_RSA_PKCS:
            if (pMechanism->pParameter || (0 != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::Rsa;
            wrapParams->rsaParams.rsaPadding = RsaPadding::rsaPkcs1;
            break;

        case CKM_RSA_PKCS_OAEP:
            if (pMechanism->pParameter || (0 != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::Rsa;
            wrapParams->rsaParams.rsaPadding = RsaPadding::rsaPkcs1Oaep;
            break;

        case CKM_EXPORT_RSA_PUBLIC_KEY:
            if (pMechanism->pParameter || (0 != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::PublicKey;
            break;

        case CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY:
            wrapParams->rsaEpidQuoteParams.clear();
            if (!pMechanism->pParameter || (sizeof(CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS) != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::EpidQuote;

            wrapParams->rsaEpidQuoteParams.sigRL.resize(CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSigRLLen);
            memcpy(&wrapParams->rsaEpidQuoteParams.sigRL[0],
                   CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->pSigRL,
                   CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSigRLLen);

            wrapParams->rsaEpidQuoteParams.spid.resize(CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSpidLen);
            memcpy(&wrapParams->rsaEpidQuoteParams.spid[0],
                   CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->pSpid,
                   CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulSpidLen);

            wrapParams->rsaEpidQuoteParams.signatureType = CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->ulQuoteSignatureType;
            if (!(UNLINKABLE_SIGNATURE == wrapParams->rsaEpidQuoteParams.signatureType ||
                  LINKABLE_SIGNATURE   == wrapParams->rsaEpidQuoteParams.signatureType))
            {
                rv = CKR_ARGUMENTS_BAD;
            }

            break;

#ifdef DCAP_SUPPORT
        case CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY:
            wrapParams->rsaEcdsaQuoteParams.reset();
            if (!pMechanism->pParameter || (sizeof(CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS) != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *wrapMode = WrapMode::EcdsaQuote;
            wrapParams->rsaEcdsaQuoteParams.qlPolicy = CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR(pMechanism->pParameter)->qlPolicy;

            break;
#endif
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV aesWrapKey(const CK_OBJECT_HANDLE& hWrappingKey,
                        const CK_OBJECT_HANDLE& hKey,
                        const AesCryptParams&   aesCryptParams,
                        CK_BYTE_PTR             pWrappedKey,
                        CK_ULONG_PTR            pulWrappedKeyLen)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        // Key to be wrapped has to be symmetric
        if (!gSessionCache->checkKeyType(hKey, CKK_AES))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        // Wrapping key Id has to be symmetric
        if (!gSessionCache->checkKeyType(hWrappingKey, CKK_AES) ||
            !gSessionCache->attributeSet(hWrappingKey, BoolAttribute::WRAP))
        {
            rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        uint32_t destBufferLenRequired  = 0;
        uint32_t destBufferLen = *pulWrappedKeyLen;
        rv = P11Crypto::SymmetricProvider::wrapKey(hWrappingKey, hKey,
                                                   aesCryptParams,
                                                   pWrappedKey, destBufferLen,
                                                   &destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaWrapKey(const CK_OBJECT_HANDLE& hWrappingKey,
                        const CK_OBJECT_HANDLE& hKey,
                        const RsaCryptParams&   rsaCryptParams,
                        CK_BYTE_PTR             pWrappedKey,
                        CK_ULONG_PTR            pulWrappedKeyLen)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!hWrappingKey || !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        // Key to be wrapped has to be symmetric
        if (!gSessionCache->checkKeyType(hKey, CKK_AES))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        // Wrapping key Id has to be asymmetric
        if (!gSessionCache->checkKeyType(hWrappingKey, CKK_RSA) ||
            !gSessionCache->attributeSet(hWrappingKey, BoolAttribute::WRAP))
        {
            rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        uint32_t destBufferLenRequired  = 0;
        uint32_t destBufferLen = *pulWrappedKeyLen;
        rv = P11Crypto::AsymmetricProvider::wrapKey(hWrappingKey, hKey,
                                                    rsaCryptParams,
                                                    pWrappedKey, destBufferLen,
                                                    &destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaExportPublicKey(const CK_OBJECT_HANDLE& hWrappingKey,
                                const CK_OBJECT_HANDLE& hKey,
                                CK_BYTE_PTR             pWrappedKey,
                                CK_ULONG_PTR            pulWrappedKeyLen)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        // Wrapping key Id should be null for RSA export
        if (hWrappingKey || !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->checkKeyType(hKey, CKK_RSA))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        uint32_t destBufferLenRequired  = 0;
        uint32_t destBufferLen = *pulWrappedKeyLen;
        rv = P11Crypto::AsymmetricProvider::exportPublicKey(hKey,
                                                            pWrappedKey, destBufferLen,
                                                            &destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
template <typename QuoteParamsType>
static CK_RV rsaExportQuoteWithPublicKey(const CK_OBJECT_HANDLE&    hWrappingKey,
                                         const CK_OBJECT_HANDLE&    hKey,
                                         const QuoteParamsType&     rsaQuoteParams,
                                         CK_BYTE_PTR                pWrappedKey,
                                         CK_ULONG_PTR               pulWrappedKeyLen)
{
    CK_RV rv = CKR_FUNCTION_FAILED;
    do
    {
        // Wrapping key Id should be null for RSA quote + public key export
        if (hWrappingKey || !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->checkKeyType(hKey, CKK_RSA))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        uint32_t destBufferLenRequired  = 0;
        uint32_t destBufferLen = *pulWrappedKeyLen;
        rv = P11Crypto::AsymmetricProvider::exportQuoteWithRsaPublicKey(hKey,
                                                                        rsaQuoteParams,
                                                                        pWrappedKey, destBufferLen,
                                                                        &destBufferLenRequired);
        if (CKR_OK != rv)
        {
            break;
        }

        *pulWrappedKeyLen = destBufferLenRequired;
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV wrapKey(CK_SESSION_HANDLE hSession,
              CK_MECHANISM_PTR  pMechanism,
              CK_OBJECT_HANDLE  hWrappingKey,
              CK_OBJECT_HANDLE  hKey,
              CK_BYTE_PTR       pWrappedKey,
              CK_ULONG_PTR      pulWrappedKeyLen)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism || !pulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!gSessionCache->findObject(hKey))
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        if (hWrappingKey)
        {
            if (!gSessionCache->findObject(hWrappingKey))
            {
                rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
                break;
            }

            rv = P11Crypto::checkReadAccess(hSession, hWrappingKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }

        rv = P11Crypto::checkReadAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        WrapParams wrapParams;
        WrapMode   wrapMode;

        rv = populateWrapParameters(pMechanism, &wrapParams, &wrapMode);

        if (CKR_OK != rv)
        {
            break;
        }

        switch (wrapMode)
        {
            case WrapMode::Aes:
                rv = aesWrapKey(hWrappingKey,
                                hKey,
                                wrapParams.aesParams,
                                pWrappedKey,
                                pulWrappedKeyLen);

                if (CKR_OK == rv && !gSessionCache->setWrappingStatus(hWrappingKey))
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                break;

            case WrapMode::Rsa:
                rv = rsaWrapKey(hWrappingKey,
                                hKey,
                                wrapParams.rsaParams,
                                pWrappedKey,
                                pulWrappedKeyLen);

                if (CKR_OK == rv && !gSessionCache->setWrappingStatus(hWrappingKey))
                {
                    rv = CKR_GENERAL_ERROR;
                    break;
                }

                break;

            case WrapMode::PublicKey:
                rv = rsaExportPublicKey(hWrappingKey,
                                        hKey,
                                        pWrappedKey, pulWrappedKeyLen);
                break;

            case WrapMode::EpidQuote:
                rv = rsaExportQuoteWithPublicKey(hWrappingKey,
                                                 hKey,
                                                 wrapParams.rsaEpidQuoteParams,
                                                 pWrappedKey,
                                                 pulWrappedKeyLen);
                break;

#ifdef DCAP_SUPPORT
            case WrapMode::EcdsaQuote:
                rv = rsaExportQuoteWithPublicKey(hWrappingKey,
                                                 hKey,
                                                 wrapParams.rsaEcdsaQuoteParams,
                                                 pWrappedKey,
                                                 pulWrappedKeyLen);
                break;
#endif
            default:
                rv = CKR_GENERAL_ERROR;
                break;
        }
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV populateUnwrapParameters(const CK_MECHANISM_PTR pMechanism,
                                      WrapParams*            unwrapParams,
                                      WrapMode*              unwrapMode)
{
    CK_RV rv = CKR_OK;

    if (!pMechanism || !unwrapParams || !unwrapMode)
    {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism)
    {
        case CKM_AES_CTR:
            unwrapParams->aesParams.clear();
            if (!pMechanism->pParameter ||
                (sizeof(CK_AES_CTR_PARAMS) != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::Aes;

            unwrapParams->aesParams.counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
            if (!Utils::AttributeUtils::isSupportedCounterBitsSize(unwrapParams->aesParams.counterBits))
            {
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }

            unwrapParams->aesParams.iv.resize(16);
            memcpy(&unwrapParams->aesParams.iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
            unwrapParams->aesParams.cipherMode = BlockCipherMode::ctr;
            break;

        case CKM_AES_GCM:
            unwrapParams->aesParams.clear();
            if (!pMechanism->pParameter ||
                sizeof(CK_GCM_PARAMS) != pMechanism->ulParameterLen)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::Aes;

            unwrapParams->aesParams.iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
            memcpy(&unwrapParams->aesParams.iv[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);

            unwrapParams->aesParams.aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
            memcpy(&unwrapParams->aesParams.aad[0],
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                   CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);

            unwrapParams->aesParams.tagBits = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
            {
                auto tagBytes = (unwrapParams->aesParams.tagBits >> 3);
                if (tagBytes < minTagSize ||
                    tagBytes > maxTagSize)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            unwrapParams->aesParams.cipherMode = BlockCipherMode::gcm;
            break;

        case CKM_AES_CBC:
            unwrapParams->aesParams.clear();
            if (!pMechanism->pParameter || (0 == pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::Aes;

            unwrapParams->aesParams.iv.resize(pMechanism->ulParameterLen);
            memcpy(&unwrapParams->aesParams.iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
            unwrapParams->aesParams.cipherMode = BlockCipherMode::cbc;
            break;

        case CKM_AES_CBC_PAD:
            unwrapParams->aesParams.clear();
            if (!pMechanism->pParameter || (0 == pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::Aes;

            unwrapParams->aesParams.iv.resize(pMechanism->ulParameterLen);
            memcpy(&unwrapParams->aesParams.iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);

            unwrapParams->aesParams.cipherMode       = BlockCipherMode::cbc;
            unwrapParams->aesParams.padding          = true;
            break;

        case CKM_RSA_PKCS:
            if (pMechanism->pParameter || (0 != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::Rsa;
            unwrapParams->rsaParams.rsaPadding = RsaPadding::rsaPkcs1;
            break;

        case CKM_RSA_PKCS_OAEP:
            if (pMechanism->pParameter || (0 != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::Rsa;
            unwrapParams->rsaParams.rsaPadding = RsaPadding::rsaPkcs1Oaep;
            break;

        case CKM_IMPORT_RSA_PUBLIC_KEY:
            if (pMechanism->pParameter || (0 != pMechanism->ulParameterLen))
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            *unwrapMode = WrapMode::PublicKey;
            break;

        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV unwrapWithAesKey(const CK_OBJECT_HANDLE&      hUnwrappingKey,
                              const CK_BYTE_PTR            pWrappedKey,
                              const CK_ULONG&              ulWrappedKeyLen,
                              const AesCryptParams&        aesUnwrapParams,
                              const KeyType&               wrappedKeyType,
                              const std::vector<CK_ULONG>& packedAttributes,
                              CK_OBJECT_HANDLE_PTR         hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pWrappedKey || !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        // Key to unwrap has to be symmetric
        if (!gSessionCache->checkKeyType(hUnwrappingKey, CKK_AES) ||
            !gSessionCache->attributeSet(hUnwrappingKey, BoolAttribute::UNWRAP))
        {
            rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::SymmetricProvider::unwrapKey(hUnwrappingKey,
                                                     pWrappedKey, ulWrappedKeyLen,
                                                     aesUnwrapParams,
                                                     wrappedKeyType,
                                                     packedAttributes,
                                                     reinterpret_cast<uint32_t*>(hKey));
        if (CKR_OK != rv)
        {
            break;
        }
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaUnwrapKey(const CK_OBJECT_HANDLE&      hUnwrappingKey,
                          const CK_BYTE_PTR            pWrappedKey,
                          const CK_ULONG&              ulWrappedKeyLen,
                          const RsaCryptParams&        rsaUnwrapParams,
                          const std::vector<CK_ULONG>& packedAttributes,
                          CK_OBJECT_HANDLE_PTR         hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pWrappedKey || !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        // Key to unwrap has to be asymmetric
        if (!gSessionCache->checkKeyType(hUnwrappingKey, CKK_RSA) ||
            !gSessionCache->attributeSet(hUnwrappingKey, BoolAttribute::UNWRAP))
        {
            rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::AsymmetricProvider::unwrapKey(hUnwrappingKey,
                                                      pWrappedKey, ulWrappedKeyLen,
                                                      rsaUnwrapParams,
                                                      packedAttributes,
                                                      reinterpret_cast<uint32_t*>(hKey));
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV rsaImportPublicKey(const CK_OBJECT_HANDLE&      hUnwrappingKey,
                                const CK_BYTE_PTR            pWrappedKey,
                                const CK_ULONG&              ulWrappedKeyLen,
                                const std::vector<CK_ULONG>& packedAttributes,
                                CK_OBJECT_HANDLE_PTR         hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        // Unwrapping key Id should be null for RSA import
        if (hUnwrappingKey || !pWrappedKey || !hKey)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        rv = P11Crypto::AsymmetricProvider::importKey(pWrappedKey, ulWrappedKeyLen,
                                                      packedAttributes,
                                                      reinterpret_cast<uint32_t*>(hKey));
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV unwrapKey(CK_SESSION_HANDLE    hSession,
                CK_MECHANISM_PTR     pMechanism,
                CK_OBJECT_HANDLE     hUnwrappingKey,
                CK_BYTE_PTR          pWrappedKey,
                CK_ULONG             ulWrappedKeyLen,
                CK_ATTRIBUTE_PTR     pTemplate,
                CK_ULONG             ulCount,
                CK_OBJECT_HANDLE_PTR hKey)
{
    CK_RV              rv              = CKR_FUNCTION_FAILED;
    CK_ULONG           keyGenMechanism = CKM_VENDOR_DEFINED_INVALID;
    BoolAttributeSet   boolAttributes{};
    UlongAttributeSet  ulongAttributes{};
    StringAttributeSet strAttributes{};
    Utils::AttributeUtils::AttributeValidatorStruct attrValStruct{};

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pMechanism || !pWrappedKey || !pTemplate || !hKey || !ulWrappedKeyLen)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (hUnwrappingKey)
        {
            if (!gSessionCache->findObject(hUnwrappingKey))
            {
                rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
                break;
            }

            rv = P11Crypto::checkReadAccess(hSession, hUnwrappingKey);
            if (CKR_OK != rv)
            {
                break;
            }
        }

        rv = P11Crypto::checkWriteAccess(hSession, pTemplate, ulCount);
        if (CKR_OK != rv)
        {
            break;
        }

        WrapParams unwrapParams;
        WrapMode   unwrapMode;

        rv = populateUnwrapParameters(pMechanism, &unwrapParams, &unwrapMode);
        if (CKR_OK != rv)
        {
            break;
        }

        rv = Utils::AttributeUtils::extractAttributesFromTemplate(pTemplate, ulCount,
                                                                  &ulongAttributes,
                                                                  &strAttributes,
                                                                  &boolAttributes,
                                                                  &attrValStruct);
        if (CKR_OK != rv)
        {
            break;
        }

        KeyGenMechanismAttributeValue kgmav { KeyGenerationMechanism::invalid, CKM_VENDOR_DEFINED_INVALID };
        KeyGenerationMechanism keyGenerationMechanism = KeyGenerationMechanism::invalid;
        KeyType wrappedKeyType = KeyType::Invalid;

        keyGenerationMechanism = KeyGenerationMechanism::rsaGeneratePrivateKey;
        if (Utils::AttributeUtils::validateRsaKeyGenAttributes(keyGenerationMechanism, attrValStruct))
        {
            unwrapMode = WrapMode::AesWrapRsa;
        }

        std::vector<CK_ULONG> packedAttributes;

        bool tokenObject = boolAttributes.test(Utils::AttributeUtils::p11AttributeToBoolAttribute[CKA_TOKEN]);
        if (tokenObject)
        {
            CK_SLOT_ID slotId = gSessionCache->getSlotId(hSession);
            if (slotId > maxSlotsSupported)
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }

            if (!Utils::AttributeUtils::packAttributes(slotId,
                                                       ulongAttributes,
                                                       strAttributes,
                                                       boolAttributes,
                                                       &packedAttributes))
            {
                rv = CKR_GENERAL_ERROR;
                break;
            }
        }

        switch (unwrapMode)
        {
            case WrapMode::Aes:
                kgmav = getKeyMechanismAttributeValue(unwrapParams.aesParams);
                keyGenMechanism = kgmav.second;
                if (!Utils::AttributeUtils::validateAesKeyGenAttributes(kgmav.first, attrValStruct))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                wrappedKeyType = KeyType::Aes;

                rv = unwrapWithAesKey(hUnwrappingKey,
                                      pWrappedKey, ulWrappedKeyLen,
                                      unwrapParams.aesParams,
                                      wrappedKeyType,
                                      packedAttributes,
                                      hKey);
                break;

            case WrapMode::Rsa:
                keyGenMechanism = pMechanism->mechanism;

                keyGenerationMechanism = KeyGenerationMechanism::rsaUnwrapKey;
                if (!Utils::AttributeUtils::validateAesKeyGenAttributes(keyGenerationMechanism, attrValStruct))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                rv = rsaUnwrapKey(hUnwrappingKey,
                                  pWrappedKey, ulWrappedKeyLen,
                                  unwrapParams.rsaParams,
                                  packedAttributes,
                                  hKey);
                break;

            case WrapMode::PublicKey:
                keyGenMechanism = CKM_IMPORT_RSA_PUBLIC_KEY;

                keyGenerationMechanism = KeyGenerationMechanism::rsaImportPublicKey;
                if (!Utils::AttributeUtils::validateRsaKeyGenAttributes(keyGenerationMechanism, attrValStruct) ||
                    boolAttributes.test(BoolAttribute::ENCRYPT) ||
                    boolAttributes.test(BoolAttribute::VERIFY)  ||
                    boolAttributes.test(BoolAttribute::WRAP))
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }

                rv = rsaImportPublicKey(hUnwrappingKey,
                                        pWrappedKey, ulWrappedKeyLen,
                                        packedAttributes,
                                        hKey);
                break;

            case WrapMode::AesWrapRsa:
                keyGenMechanism = pMechanism->mechanism;
                keyGenerationMechanism = KeyGenerationMechanism::rsaGeneratePrivateKey;

                wrappedKeyType = KeyType::Rsa;
                rv = unwrapWithAesKey(hUnwrappingKey,
                                      pWrappedKey, ulWrappedKeyLen,
                                      unwrapParams.aesParams,
                                      wrappedKeyType,
                                      packedAttributes,
                                      hKey);
                break;

            default:
                rv = CKR_FUNCTION_FAILED;
                break;
        }
    } while (false);

    if (CKR_OK == rv)
    {
        ulongAttributes.insert(UlongAttributeType(CKA_KEY_GEN_MECHANISM, keyGenMechanism));

        uint32_t sessionId = hSession & std::numeric_limits<uint32_t>::max();

        ObjectParameters objectParams{ };

        objectParams.slotId             = gSessionCache->getSlotId(hSession);
        objectParams.sessionHandle      = sessionId;
        objectParams.ulongAttributes    = ulongAttributes;
        objectParams.strAttributes      = strAttributes;
        objectParams.boolAttributes     = boolAttributes;
        objectParams.objectState        = ObjectState::NOT_IN_USE;

        gSessionCache->addObject(sessionId, *hKey, objectParams);
    }

    return rv;
}

