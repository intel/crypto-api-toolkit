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

#include "AttributeUtils.h"

namespace Utils
{
    namespace AttributeUtils
    {
        //---------------------------------------------------------------------------------------------
        bool isSymmetricMechanism(const CK_MECHANISM_PTR pMechanism)
        {
            bool result = false;

            if (!pMechanism)
            {
                return false;
            }

            switch (pMechanism->mechanism)
            {
                case CKM_AES_CBC:
                case CKM_AES_CBC_PAD:
                case CKM_AES_CTR:
                case CKM_AES_GCM:
                    result = true;
                    break;
                default:
                    result = false;
                    break;
            }

            return result;
        }

        //---------------------------------------------------------------------------------------------
        bool isAsymmetricMechanism(const CK_MECHANISM_PTR pMechanism)
        {
            bool result = false;

            if (!pMechanism)
            {
                return false;
            }

            switch (pMechanism->mechanism)
            {
            case CKM_RSA_PKCS:
            case CKM_RSA_PKCS_OAEP:
                result = true;
                break;
            default:
                result = false;
                break;
            }
            return result;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getAesKeyGenParameters(const UlongAttributeSet&  ulongAttributes,
                                     const StringAttributeSet& strAttributes,
                                     const BoolAttributeSet&   boolAttributes,
                                     SymmetricKeyParams*       symKeyParams)
        {
            CK_RV rv = CKR_OK;

            if (!symKeyParams)
            {
                return CKR_GENERAL_ERROR;
            }

            symKeyParams->clear();

            auto strAttrIter = std::find_if(strAttributes.cbegin(), strAttributes.cend(), [](const StringAttributeType& p)
                                    {
                                        return (CKA_VALUE_KEY_BUFFER == p.first);
                                    });

            if (strAttrIter != strAttributes.cend())
            {
                std::string keyBuffer = strAttrIter->second;
                symKeyParams->rawKeyBuffer.resize(keyBuffer.size());
                symKeyParams->rawKeyBuffer.assign(keyBuffer.begin(), keyBuffer.end());

                symKeyParams->keyLength = keyBuffer.size();
                symKeyParams->keyGenMechanism = KeyGenerationMechanism::aesImportRawKey;
            }
            else // key buffer for raw key import not present, so check the key length for key generation.
            {
                auto ulongAttrIter = std::find_if(ulongAttributes.cbegin(), ulongAttributes.cend(), [](const UlongAttributeType& p)
                                        {
                                            return (CKA_VALUE_LEN == p.first);
                                        });

                if (ulongAttrIter != ulongAttributes.cend())
                {
                    symKeyParams->keyLength = ulongAttrIter->second;
                    symKeyParams->keyGenMechanism = KeyGenerationMechanism::aesGenerateKey;
                }
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getEcKeyGenParameters(const StringAttributeSet& strAttributes,
                                    AsymmetricKeyParams*      asymKeyParams)
        {
            if (!asymKeyParams)
            {
                return CKR_GENERAL_ERROR;
            }

            asymKeyParams->clear();

            auto strAttrIter = std::find_if(strAttributes.cbegin(), strAttributes.cend(), [](const StringAttributeType& p)
                                    {
                                        return (CKA_EC_PARAMS == p.first);
                                    });

            if (strAttrIter == strAttributes.cend())
            {
                return CKR_GENERAL_ERROR;
            }
            else
            {
                asymKeyParams->curveOid = strAttrIter->second;
                asymKeyParams->keyGenMechanism = KeyGenerationMechanism::ecGeneratePublicKey;
            }

            return CKR_OK;
        }
        //---------------------------------------------------------------------------------------------
        CK_RV getRsaKeyGenParameters(const UlongAttributeSet&  ulongAttributes,
                                     const StringAttributeSet& strAttributes,
                                     const BoolAttributeSet&   boolAttributes,
                                     AsymmetricKeyParams*      asymKeyParams)
        {
            CK_RV rv = CKR_OK;

            if (!asymKeyParams)
            {
                return CKR_GENERAL_ERROR;
            }

            asymKeyParams->clear();

            auto ulongAttrIter = std::find_if(ulongAttributes.cbegin(), ulongAttributes.cend(), [](const UlongAttributeType& p)
                                    {
                                        return (CKA_MODULUS_BITS == p.first);
                                    });

            if (ulongAttrIter != ulongAttributes.cend())
            {
                asymKeyParams->modulusLength = ulongAttrIter->second;
                asymKeyParams->keyGenMechanism = KeyGenerationMechanism::rsaGeneratePublicKey;
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        static bool isBoolAttribute(const CK_ATTRIBUTE_TYPE& attributeType)
        {
            return (supportedboolAttr.find(attributeType) != supportedboolAttr.end());
        }

        //---------------------------------------------------------------------------------------------
        static bool isUlongAttribute(const CK_ATTRIBUTE_TYPE& attributeType)
        {
            return (supportedUlongAttr.find(attributeType) != supportedUlongAttr.end());
        }

        //---------------------------------------------------------------------------------------------
        static bool isStringAttribute(const CK_ATTRIBUTE_TYPE& attributeType)
        {
            return (supportedStrAttr.find(attributeType) != supportedStrAttr.end());
        }

        //---------------------------------------------------------------------------------------------
        static bool isSupportedAttribute(const CK_ATTRIBUTE_TYPE& attributeType)
        {
            return (isBoolAttribute(attributeType) || isUlongAttribute(attributeType) || isStringAttribute(attributeType));
        }

        //---------------------------------------------------------------------------------------------
        static CK_RV validateBoolAttribute(CK_VOID_PTR     attributeValue,
                                           const CK_ULONG& attributeLen,
                                           CK_BBOOL*       value)
        {
            CK_RV rv = CKR_FUNCTION_FAILED;

            do
            {
                if (!attributeValue || !value)
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }
                if (sizeof(CK_BBOOL) == attributeLen)
                {
                    if (CK_TRUE == *reinterpret_cast<CK_BBOOL*>(attributeValue))
                    {
                        *value  = CK_TRUE;
                        rv      = CKR_OK;
                        break;
                    }
                    else if (CK_FALSE == *reinterpret_cast<CK_BBOOL*>(attributeValue))
                    {
                        *value  = CK_FALSE;
                        rv      = CKR_OK;
                        break;
                    }
                    else
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }
                }
                else
                {
                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                }
            } while(false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        bool validateAesKeyGenAttributes(const KeyGenerationMechanism&   keyGenMechanism,
                                         const AttributeValidatorStruct& attrValStruct)
        {
            bool  result = false;

            bool modulusBits = attrValStruct.boolAttrVal[AttrValidatorBoolParams::ModulusBits];
            bool keyLength   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::KeyLength];
            bool keyBuffer   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::RawKeyBuffer];
            bool localAttr   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::Local];

            switch(keyGenMechanism)
            {
                case KeyGenerationMechanism::aesGenerateKey:
                    result = (CKO_SECRET_KEY == attrValStruct.objectClass &&
                              CKK_AES        == attrValStruct.keyType     &&
                              keyLength                                   &&
                              !keyBuffer                                  &&
                              !modulusBits);
                    break;

                case KeyGenerationMechanism::aesImportRawKey:
                    result = (CKO_SECRET_KEY == attrValStruct.objectClass &&
                              CKK_AES        == attrValStruct.keyType     &&
                              keyBuffer                                   &&
                              !keyLength                                  &&
                              !modulusBits                                &&
                              !localAttr);
                    break;

                case KeyGenerationMechanism::aesCTRUnwrapKey:
                case KeyGenerationMechanism::aesGCMUnwrapKey:
                case KeyGenerationMechanism::aesCBCUnwrapKey:
                case KeyGenerationMechanism::aesCBCPADUnwrapKey:
                    result = (CKO_SECRET_KEY == attrValStruct.objectClass &&
                              CKK_AES        == attrValStruct.keyType     &&
                              !keyBuffer                                  &&
                              !keyLength                                  &&
                              !modulusBits                                &&
                              !localAttr);

                    break;
                case KeyGenerationMechanism::rsaUnwrapKey:
                    result = (CKO_SECRET_KEY == attrValStruct.objectClass &&
                              CKK_AES        == attrValStruct.keyType     &&
                              !keyBuffer                                  &&
                              !keyLength                                  &&
                              !modulusBits                                &&
                              !localAttr);
                    break;
                default:
                    result = false;
                    break;
            }

            return result;
        }

        //---------------------------------------------------------------------------------------------
        bool validateEcKeyGenAttributes(const KeyGenerationMechanism&   keyGenMechanism,
                                        const AttributeValidatorStruct& attrValStruct,
                                        const BoolAttributeSet&         boolAttributes)
        {
            bool  result = false;

            bool modulusBits = attrValStruct.boolAttrVal[AttrValidatorBoolParams::ModulusBits];
            bool keyLength   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::KeyLength];
            bool keyBuffer   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::RawKeyBuffer];
            bool ecParams    = attrValStruct.boolAttrVal[AttrValidatorBoolParams::EcParams];

            switch(keyGenMechanism)
            {
                case KeyGenerationMechanism::ecGeneratePublicKey:
                    result = (CKO_PUBLIC_KEY == attrValStruct.objectClass  &&
                              CKK_EC         == attrValStruct.keyType      &&
                              ecParams                                     &&
                              !modulusBits                                 &&
                              !keyBuffer                                   &&
                              !keyLength                                   &&
                              !boolAttributes.test(BoolAttribute::ENCRYPT) &&
                              !boolAttributes.test(BoolAttribute::DECRYPT) &&
                              !boolAttributes.test(BoolAttribute::WRAP)    &&
                              !boolAttributes.test(BoolAttribute::UNWRAP)  &&
                              !boolAttributes.test(BoolAttribute::SIGN));
                    break;

                case KeyGenerationMechanism::ecGeneratePrivateKey:
                    result = (CKO_PRIVATE_KEY == attrValStruct.objectClass &&
                              CKK_EC          == attrValStruct.keyType     &&
                              !ecParams                                    &&
                              !modulusBits                                 &&
                              !keyBuffer                                   &&
                              !keyLength                                   &&
                              !boolAttributes.test(BoolAttribute::ENCRYPT) &&
                              !boolAttributes.test(BoolAttribute::DECRYPT) &&
                              !boolAttributes.test(BoolAttribute::WRAP)    &&
                              !boolAttributes.test(BoolAttribute::UNWRAP)  &&
                              !boolAttributes.test(BoolAttribute::VERIFY));
                    break;
                case KeyGenerationMechanism::edGeneratePublicKey:
                    result = (CKO_PUBLIC_KEY == attrValStruct.objectClass  &&
                              CKK_EC_EDWARDS == attrValStruct.keyType      &&
                              ecParams                                     &&
                              !modulusBits                                 &&
                              !keyBuffer                                   &&
                              !keyLength                                   &&
                              !boolAttributes.test(BoolAttribute::ENCRYPT) &&
                              !boolAttributes.test(BoolAttribute::DECRYPT) &&
                              !boolAttributes.test(BoolAttribute::WRAP)    &&
                              !boolAttributes.test(BoolAttribute::UNWRAP)  &&
                              !boolAttributes.test(BoolAttribute::SIGN));
                    break;
                case KeyGenerationMechanism::edGeneratePrivateKey:
                    result = (CKO_PRIVATE_KEY == attrValStruct.objectClass &&
                              CKK_EC_EDWARDS  == attrValStruct.keyType     &&
                              !ecParams                                    &&
                              !modulusBits                                 &&
                              !keyBuffer                                   &&
                              !keyLength                                   &&
                              !boolAttributes.test(BoolAttribute::ENCRYPT) &&
                              !boolAttributes.test(BoolAttribute::DECRYPT) &&
                              !boolAttributes.test(BoolAttribute::WRAP)    &&
                              !boolAttributes.test(BoolAttribute::UNWRAP)  &&
                              !boolAttributes.test(BoolAttribute::VERIFY));
                    break;
                default:
                    result = false;
                    break;
            }

            return result;
        }

        //---------------------------------------------------------------------------------------------
        bool validateRsaKeyGenAttributes(const KeyGenerationMechanism&   keyGenMechanism,
                                         const AttributeValidatorStruct& attrValStruct)
        {
            bool  result = false;

            bool modulusBits = attrValStruct.boolAttrVal[AttrValidatorBoolParams::ModulusBits];
            bool keyLength   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::KeyLength];
            bool keyBuffer   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::RawKeyBuffer];
            bool localAttr   = attrValStruct.boolAttrVal[AttrValidatorBoolParams::Local];

            switch(keyGenMechanism)
            {
                case KeyGenerationMechanism::rsaGeneratePublicKey:
                    result = (CKO_PUBLIC_KEY == attrValStruct.objectClass &&
                              CKK_RSA        == attrValStruct.keyType     &&
                              modulusBits                                 &&
                              !keyBuffer                                  &&
                              !keyLength);
                    break;

                case KeyGenerationMechanism::rsaGeneratePrivateKey:
                    result = (CKO_PRIVATE_KEY == attrValStruct.objectClass &&
                              CKK_RSA         == attrValStruct.keyType     &&
                              !modulusBits                                 &&
                              !keyBuffer                                   &&
                              !keyLength);
                    break;

                case KeyGenerationMechanism::rsaImportPublicKey:
                    result = (CKO_PUBLIC_KEY == attrValStruct.objectClass &&
                              CKK_RSA        == attrValStruct.keyType     &&
                              !modulusBits                                &&
                              !keyBuffer                                  &&
                              !keyLength                                  &&
                              !localAttr);
                    break;
                default:
                    result = false;
                    break;
            }

            return result;
        }

        //---------------------------------------------------------------------------------------------
        void addDefaultAttributes(const KeyGenerationMechanism& keyGenMechanism, BoolAttributeSet* boolAttributes)
        {
            if (boolAttributes)
            {
                switch(keyGenMechanism)
                {
                    // For all keys generated on the token, CKA_LOCAL attribute should set to CK_TRUE.
                    case KeyGenerationMechanism::aesGenerateKey:
                    case KeyGenerationMechanism::rsaGeneratePublicKey:
                    case KeyGenerationMechanism::rsaGeneratePrivateKey:
                    case KeyGenerationMechanism::ecGeneratePublicKey:
                    case KeyGenerationMechanism::ecGeneratePrivateKey:
                    case KeyGenerationMechanism::edGeneratePublicKey:
                    case KeyGenerationMechanism::edGeneratePrivateKey:
                        boolAttributes->set(p11AttributeToBoolAttribute[CKA_LOCAL]);
                        break;
                    default:
                        break;
                }
            }
        }

        //---------------------------------------------------------------------------------------------
        static CK_RV checkForIncompatibleBoolAttributes(const CK_OBJECT_CLASS&  objectClass,
                                                        const BoolAttributeSet& attributeBitset)
        {
            CK_RV rv = CKR_OK;

            do
            {
                switch(objectClass)
                {
                    case CKO_SECRET_KEY:    // Can't set CKA_SIGN and CKA_VERIFY on AES Keys
                        if (attributeBitset.test(BoolAttribute::SIGN)||
                            attributeBitset.test(BoolAttribute::VERIFY))
                        {
                            rv = CKR_TEMPLATE_INCONSISTENT;
                        }
                        break;
                    case CKO_PUBLIC_KEY:    // Can't set CKA_DECRYPT, CKA_SIGN and CKA_UNWRAP on RSA public Keys
                        if (attributeBitset.test(BoolAttribute::DECRYPT) ||
                            attributeBitset.test(BoolAttribute::SIGN)    ||
                            attributeBitset.test(BoolAttribute::UNWRAP))
                        {
                            rv = CKR_TEMPLATE_INCONSISTENT;
                        }
                        break;
                    case CKO_PRIVATE_KEY:   // Can't set CKA_ENCRYPT, CKA_VERIFY and CKA_WRAP on RSA private Keys
                        if (attributeBitset.test(BoolAttribute::ENCRYPT) ||
                            attributeBitset.test(BoolAttribute::VERIFY)  ||
                            attributeBitset.test(BoolAttribute::WRAP))
                        {
                            rv = CKR_TEMPLATE_INCONSISTENT;
                        }
                        break;
                    default:
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                }
            } while(false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        static CK_RV extractBoolAttributes(const CK_ATTRIBUTE_TYPE& attributeType,
                                           const CK_VOID_PTR        attributeValue,
                                           const CK_ULONG&          attributeLen,
                                           bool*                    modifiable,
                                           BoolAttributeSet*        boolAttributeBitset)
        {
            CK_BBOOL attributeSet = CK_FALSE;
            CK_RV    rv           = CKR_GENERAL_ERROR;

            if (!modifiable || !boolAttributeBitset)
            {
                return rv;
            }

            rv = validateBoolAttribute(attributeValue, attributeLen, &attributeSet);

            if (CKR_OK == rv)
            {
                if (attributeSet)
                {
                    // Rejecting if CKA_COPYABLE or CKA_DERIVE is set to CK_TRUE.
                    if ((CKA_COPYABLE == attributeType) || (CKA_DERIVE == attributeType))
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    else
                    {
                        boolAttributeBitset->set(p11AttributeToBoolAttribute[attributeType]);
                    }
                }
                else if (CKA_MODIFIABLE == attributeType)
                {
                    *modifiable = false;
                }
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        static CK_RV extractUlongAttributes(const CK_ATTRIBUTE_TYPE&  attributeType,
                                            const CK_VOID_PTR         attributeValue,
                                            const CK_ULONG&           attributeLen,
                                            CK_ULONG*                 modulusLength,
                                            CK_ULONG*                 keyLength,
                                            CK_OBJECT_CLASS*          objectClass,
                                            CK_KEY_TYPE*              keyType,
                                            bool*                     objectClassPresent,
                                            bool*                     keyTypePresent,
                                            AttributeValidatorStruct* attrValStruct,
                                            UlongAttributeSet*        ulongAttributes)
        {
            CK_RV rv = CKR_OK;

            if (!modulusLength      || !keyLength      ||
                !objectClass        || !keyType        ||
                !objectClassPresent || !keyTypePresent ||
                !attrValStruct      || !ulongAttributes)
            {
                return CKR_GENERAL_ERROR;
            }

            switch (attributeType)
            {
                case CKA_MODULUS_BITS:
                    if (attributeLen != sizeof(CK_ULONG))
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }

                    attrValStruct->boolAttrVal.set(AttrValidatorBoolParams::ModulusBits);
                    *modulusLength = *reinterpret_cast<CK_ULONG*>(attributeValue);
                    ulongAttributes->insert(UlongAttributeType(attributeType, *modulusLength));
                    break;

                case CKA_VALUE_LEN:
                    if (attributeLen != sizeof(CK_ULONG))
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }

                    attrValStruct->boolAttrVal.set(AttrValidatorBoolParams::KeyLength);
                    *keyLength = *reinterpret_cast<CK_ULONG*>(attributeValue);
                    ulongAttributes->insert(UlongAttributeType(attributeType, *keyLength));
                    break;

                case CKA_CLASS:
                    if (!attributeValue || (sizeof(CK_OBJECT_CLASS) != attributeLen))
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }

                    *objectClass = *reinterpret_cast<CK_OBJECT_CLASS*>(attributeValue);
                    ulongAttributes->insert(UlongAttributeType(attributeType, *objectClass));
                    attrValStruct->objectClass = *objectClass;
                    *objectClassPresent = true;
                    break;

                case CKA_KEY_TYPE:
                    if (!attributeValue || (sizeof(CK_KEY_TYPE) != attributeLen))
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }
                    *keyType = *reinterpret_cast<CK_KEY_TYPE*>(attributeValue);
                    ulongAttributes->insert(UlongAttributeType(attributeType, *keyType));
                    *keyTypePresent = true;
                    attrValStruct->keyType = *keyType;
                    break;

                case CKA_KEY_GEN_MECHANISM: // CKA_KEY_GEN_MECHANISM can't be set during key creation.
                    rv = CKR_TEMPLATE_INCONSISTENT;
                    break;

                default:
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        static CK_RV extractStringAttributes(const CK_ATTRIBUTE_TYPE&  attributeType,
                                             const CK_VOID_PTR         attributeValue,
                                             const CK_ULONG&           attributeLen,
                                             bool*                     idPresent,
                                             AttributeValidatorStruct* attrValStruct,
                                             StringAttributeSet*       strAttributes)
        {
            CK_RV rv = CKR_OK;

            std::string id, label, rawKeyBuffer, oid;

            if (!idPresent || !attrValStruct || !strAttributes)
            {
                return CKR_GENERAL_ERROR;
            }

            switch (attributeType)
            {
                case CKA_ID:
                    *idPresent = true;
                    if (!attributeValue)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }
                    id.assign(reinterpret_cast<const char*>(attributeValue), attributeLen);
                    strAttributes->insert(StringAttributeType(attributeType, id));
                    break;

                case CKA_LABEL:
                    if (!attributeValue)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }
                    label.assign(reinterpret_cast<const char*>(attributeValue), attributeLen);
                    strAttributes->insert(StringAttributeType(attributeType, label));
                    break;

                case CKA_VALUE_KEY_BUFFER:
                    rawKeyBuffer.assign(reinterpret_cast<const char*>(attributeValue), attributeLen);
                    strAttributes->insert(StringAttributeType(attributeType, rawKeyBuffer));
                    attrValStruct->boolAttrVal.set(AttrValidatorBoolParams::RawKeyBuffer);
                    break;

                case CKA_EC_PARAMS:
                    if (attributeLen > maxEcParamsLen)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }

                    oid.assign(reinterpret_cast<const char*>(attributeValue), attributeLen);
                    strAttributes->insert(StringAttributeType(attributeType, oid));
                    attrValStruct->boolAttrVal.set(AttrValidatorBoolParams::EcParams);
                    break;

                default:
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV extractAttributesFromTemplate(const CK_ATTRIBUTE_PTR    pTemplate,
                                            const CK_ULONG&           ulCount,
                                            UlongAttributeSet*        ulongAttributes,
                                            StringAttributeSet*       strAttributes,
                                            BoolAttributeSet*         boolAttributeBitset,
                                            AttributeValidatorStruct* attrValStruct)
        {
            CK_RV             rv                 = CKR_OK;
            bool              modifiable         = true;
            bool              objectClassPresent = false;
            bool              keyTypePresent     = false;
            bool              idPresent          = false;
            CK_ULONG          modulusLength      = 0;
            CK_ULONG          keyLength          = 0;
            CK_OBJECT_CLASS   objectClass;
            CK_KEY_TYPE       keyType;
            CK_ATTRIBUTE_TYPE attributeType{};

            if (!pTemplate)
            {
                return CKR_TEMPLATE_INCOMPLETE;
            }

            if (!ulongAttributes || !strAttributes || !boolAttributeBitset || !attrValStruct)
            {
                return CKR_ARGUMENTS_BAD;
            }

            do
            {
                attrValStruct->clear();

                for (auto i = 0; i < ulCount; ++i)
                {
                    attributeType = pTemplate[i].type;

                    if (isBoolAttribute(attributeType))
                    {
                        rv = extractBoolAttributes(attributeType,
                                                   pTemplate[i].pValue, pTemplate[i].ulValueLen,
                                                   &modifiable,
                                                   boolAttributeBitset);
                        if (CKR_OK != rv)
                        {
                            break;
                        }
                    }
                    else if (isUlongAttribute(attributeType))
                    {
                        rv = extractUlongAttributes(attributeType,
                                                    pTemplate[i].pValue, pTemplate[i].ulValueLen,
                                                    &modulusLength, &keyLength,
                                                    &objectClass, &keyType,
                                                    &objectClassPresent, &keyTypePresent,
                                                    attrValStruct, ulongAttributes);
                        if (CKR_OK != rv)
                        {
                            break;
                        }
                    }
                    else if (isStringAttribute(attributeType))
                    {
                        rv = extractStringAttributes(attributeType,
                                                     pTemplate[i].pValue, pTemplate[i].ulValueLen,
                                                     &idPresent,
                                                     attrValStruct,
                                                     strAttributes);

                        if (CKR_OK != rv)
                        {
                            break;
                        }
                    }
                    else
                    {
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                    }
                }

                if (CKR_OK != rv)
                {
                    break;
                }

                if (modifiable)
                {
                    boolAttributeBitset->set(p11AttributeToBoolAttribute[CKA_MODIFIABLE]);
                }

                // Compulsory attributes to be set.
                if (!keyTypePresent || !objectClassPresent)
                {
                    rv = CKR_TEMPLATE_INCOMPLETE;
                    break;
                }

                rv = checkForIncompatibleBoolAttributes(objectClass, *boolAttributeBitset);
                if (CKR_OK != rv)
                {
                    break;
                }
            } while(false);

            if (CKR_OK != rv)
            {
                boolAttributeBitset->reset();
                ulongAttributes->clear();
                strAttributes->clear();
                attrValStruct->clear();
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getAttributesFromTemplate(const CK_ATTRIBUTE_PTR pTemplate,
                                        const CK_ULONG&        ulCount,
                                        Attributes*            attributes)
        {
            CK_RV             rv              = CKR_OK;
            CK_BBOOL          attributeSet    = CK_FALSE;
            CK_BBOOL          modifiable      = CK_TRUE;
            CK_ULONG          attributeValue  = CKM_VENDOR_DEFINED_INVALID;
            std::string       label, id;
            CK_KEY_TYPE       keyType;
            CK_OBJECT_CLASS   objectClass;
            CK_ATTRIBUTE_TYPE attributeType{};


            if (!pTemplate)
            {
                return CKR_TEMPLATE_INCOMPLETE;
            }

            if (!attributes)
            {
                return CKR_ARGUMENTS_BAD;
            }

            do
            {
                for (auto i = 0; i < ulCount; ++i)
                {
                    attributeType = pTemplate[i].type;

                    if (isBoolAttribute(attributeType))
                    {
                        rv = validateBoolAttribute(pTemplate[i].pValue, pTemplate[i].ulValueLen, &attributeSet);

                        if (CKR_OK == rv)
                        {
                            if (attributeSet)
                            {
                                // Rejecting if CKA_COPYABLE or CKA_DERIVE is set to CK_TRUE.
                                if ((CKA_COPYABLE == attributeType) || (CKA_DERIVE == attributeType))
                                {
                                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                    break;
                                }
                                else
                                {
                                    attributes->boolAttributes.set(p11AttributeToBoolAttribute[attributeType]);
                                }
                            }
                            else if (CKA_MODIFIABLE == attributeType)
                            {
                                modifiable = CK_FALSE;
                            }
                        }
                    }
                    else if (isUlongAttribute(attributeType))
                    {
                        switch (attributeType)
                        {
                            case CKA_CLASS:
                                if (!pTemplate[i].pValue ||
                                    sizeof(CK_OBJECT_CLASS) != pTemplate[i].ulValueLen)
                                {
                                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                    break;
                                }

                                objectClass = *reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue);
                                attributes->ulongAttributes.insert(UlongAttributeType(attributeType, objectClass));
                                break;

                            case CKA_KEY_TYPE:
                                if (!pTemplate[i].pValue ||
                                    sizeof(CK_KEY_TYPE) != pTemplate[i].ulValueLen)
                                {
                                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                    break;
                                }
                                keyType = *reinterpret_cast<CK_KEY_TYPE*>(pTemplate[i].pValue);
                                attributes->ulongAttributes.insert(UlongAttributeType(attributeType, keyType));
                                break;

                            case CKA_KEY_GEN_MECHANISM:
                            case CKA_MODULUS_BITS:
                                if (!pTemplate[i].pValue ||
                                    sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
                                {
                                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                    break;
                                }

                                attributeValue = *reinterpret_cast<CK_ULONG*>(pTemplate[i].pValue);
                                attributes->ulongAttributes.insert(UlongAttributeType(attributeType, attributeValue));
                                break;
                            default:
                                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                                break;
                        }

                        if (CKR_OK != rv)
                        {
                            break;
                        }
                    }
                    else if (isStringAttribute(attributeType))
                    {
                        switch (attributeType)
                        {
                            case CKA_ID:
                                if (!pTemplate[i].pValue)
                                {
                                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                    break;
                                }
                                id.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);
                                attributes->strAttributes.insert(StringAttributeType(attributeType, id));
                                break;

                            case CKA_LABEL:
                                if (!pTemplate[i].pValue)
                                {
                                    rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                    break;
                                }
                                label.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);
                                attributes->strAttributes.insert(StringAttributeType(attributeType, label));
                                break;
                            default:
                                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                                break;
                        }

                        if (CKR_OK != rv)
                        {
                            break;
                        }
                    }
                    else
                    {
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                    }
                }

                if (CKR_OK != rv)
                {
                    break;
                }

                if (modifiable)
                {
                    attributes->boolAttributes.set(p11AttributeToBoolAttribute[CKA_MODIFIABLE]);
                }
            } while(false);

            if (CKR_OK != rv)
            {
                attributes->boolAttributes.reset();
                attributes->ulongAttributes.clear();
                attributes->strAttributes.clear();
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        bool validateId(const StringAttributeSet& publicStrAttributes, const StringAttributeSet& privateStrAttributes)
        {
            auto publicStrAttrIter = std::find_if(publicStrAttributes.cbegin(), publicStrAttributes.cend(), [](const StringAttributeType& p)
                                          {
                                              return (CKA_ID == p.first);
                                          });

            auto privateStrAttrIter = std::find_if(privateStrAttributes.cbegin(), privateStrAttributes.cend(), [](const StringAttributeType& p)
                                           {
                                               return (CKA_ID == p.first);
                                           });

            if ((publicStrAttrIter != publicStrAttributes.cend()) && (privateStrAttrIter != privateStrAttributes.cend()))   // Both public and private keys have CKA_ID.
            {
                return (publicStrAttrIter->second == privateStrAttrIter->second);
            }
            else if ((publicStrAttrIter == publicStrAttributes.cend()) && (privateStrAttrIter == privateStrAttributes.cend()))  // None of public and private keys have CKA_ID.
            {
                return true;
            }
            else    // Only one of public and private keys have CKA_ID.
            {
                return false;
            }
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getAesParameters(const CK_MECHANISM_PTR pMechanism, AesCryptParams* aesCryptParams)
        {
            CK_RV rv       = CKR_OK;
            int   tagBytes = 0;

            if (!pMechanism || !aesCryptParams)
            {
                return CKR_ARGUMENTS_BAD;
            }

            if (!pMechanism->pParameter)
            {
                return CKR_MECHANISM_PARAM_INVALID;
            }

            do
            {
                switch (pMechanism->mechanism)
                {
                    case CKM_AES_CTR:
                        if (sizeof(CK_AES_CTR_PARAMS) != pMechanism->ulParameterLen)
                        {
                            rv = CKR_MECHANISM_PARAM_INVALID;
                            break;
                        }

                        aesCryptParams->counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
                        if (!isSupportedCounterBitsSize(aesCryptParams->counterBits))
                        {
                            rv = CKR_MECHANISM_PARAM_INVALID;
                            break;
                        }

                        aesCryptParams->cipherMode = BlockCipherMode::ctr;
                        aesCryptParams->iv.resize(16);
                        memcpy(&aesCryptParams->iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
                        break;
                    case CKM_AES_GCM:
                        if (pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
                        {
                            rv = CKR_MECHANISM_PARAM_INVALID;
                            break;
                        }

                        aesCryptParams->iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
                        memcpy(&aesCryptParams->iv[0],
                               CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv,
                               CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);

                        aesCryptParams->aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
                        memcpy(&aesCryptParams->aad[0],
                               CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD,
                               CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);

                        aesCryptParams->tagBits  = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
                        tagBytes = aesCryptParams->tagBits >> 3;
                        if (tagBytes < minTagSize ||
                            tagBytes > maxTagSize)
                        {
                            rv = CKR_MECHANISM_PARAM_INVALID;
                            break;
                        }

                        aesCryptParams->cipherMode = BlockCipherMode::gcm;
                        break;
                    case CKM_AES_CBC:
                        if (0 == pMechanism->ulParameterLen)
                        {
                            rv = CKR_MECHANISM_PARAM_INVALID;
                            break;
                        }

                        aesCryptParams->iv.resize(pMechanism->ulParameterLen);
                        memcpy(&aesCryptParams->iv[0],
                               pMechanism->pParameter,
                               pMechanism->ulParameterLen);

                        aesCryptParams->cipherMode = BlockCipherMode::cbc;
                        break;
                    case CKM_AES_CBC_PAD:
                        if (0 == pMechanism->ulParameterLen)
                        {
                            rv = CKR_MECHANISM_PARAM_INVALID;
                            break;
                        }

                        aesCryptParams->iv.resize(pMechanism->ulParameterLen);
                        memcpy(&aesCryptParams->iv[0],
                               pMechanism->pParameter,
                               pMechanism->ulParameterLen);

                        aesCryptParams->padding = true;
                        aesCryptParams->cipherMode = BlockCipherMode::cbc;
                        break;
                    default:
                        rv = CKR_MECHANISM_INVALID;
                        break;
                }
            } while(false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        static StringAttributeSet::iterator getStrAttrIterator(const StringAttributeSet& strAttributes, CK_ULONG attribute)
        {
            return std::find_if(strAttributes.begin(), strAttributes.end(), [=](const StringAttributeType& p)
                    {
                        return (attribute == p.first);
                    });
        }

        //---------------------------------------------------------------------------------------------
        static bool compareStringAttribute(const StringAttributeSet::iterator& strAttrIter,
                                           const StringAttributeSet&           strAttributes,
                                           const StringAttributeSet::iterator& objStrAttrIter,
                                           const StringAttributeSet&           objStrAttributes)
        {
            bool matchedAttribute = true;

            if (strAttrIter != strAttributes.cend())
            {
                // CKA_VALUE_KEY_BUFFER is not supported for FindObjects operation.
                if (CKA_VALUE_KEY_BUFFER == strAttrIter->first)
                {
                    return false;
                }

                if (objStrAttrIter != objStrAttributes.cend())
                {
                    if (strAttrIter->second != objStrAttrIter->second)
                    {
                        matchedAttribute = false;
                    }
                }
                else
                {
                    matchedAttribute = false;
                }
            }

            return matchedAttribute;
        }

        //---------------------------------------------------------------------------------------------
        static bool matchStrAttribute(const StringAttributeSet& foStrAttributes, const StringAttributeSet& objStrAttributes, CK_ULONG strAttribute)
        {
            auto strAttrIter    = getStrAttrIterator(foStrAttributes, strAttribute);
            auto objStrAttrIter = getStrAttrIterator(objStrAttributes, strAttribute);

            return compareStringAttribute(strAttrIter,    foStrAttributes,
                                          objStrAttrIter, objStrAttributes);

        }

        //---------------------------------------------------------------------------------------------
        static UlongAttributeSet::iterator getUlongAttrIterator(const UlongAttributeSet& ulongAttributes, CK_ULONG attribute)
        {
            return std::find_if(ulongAttributes.begin(), ulongAttributes.end(), [=](const UlongAttributeType& p)
                    {
                        return (attribute == p.first);
                    });
        }

        //---------------------------------------------------------------------------------------------
        static bool compareUlongAttribute(const UlongAttributeSet::iterator& ulongAttrIter,
                                          const UlongAttributeSet&           ulongAttributes,
                                          const UlongAttributeSet::iterator& objUlongAttrIter,
                                          const UlongAttributeSet&           objUlongAttributes)
        {
            bool matchedAttribute = true;

            if (ulongAttrIter != ulongAttributes.end())
            {
                // CKA_VALUE_LEN is not supported for FindObjects operation.
                if (CKA_VALUE_LEN == ulongAttrIter->first)
                {
                    return false;
                }

                if (objUlongAttrIter != objUlongAttributes.end())
                {
                    if (ulongAttrIter->second != objUlongAttrIter->second)
                    {
                        matchedAttribute = false;
                    }
                }
                else
                {
                    matchedAttribute = false;
                }
            }

            return matchedAttribute;
        }

        //---------------------------------------------------------------------------------------------
        static bool matchUlongAttribute(const UlongAttributeSet& foUlongAttributes, const UlongAttributeSet& objUlongAttributes, CK_ULONG ulongAttribute)
        {
            auto ulongAttrIter    = getUlongAttrIterator(foUlongAttributes, ulongAttribute);
            auto objUlongAttrIter = getUlongAttrIterator(objUlongAttributes, ulongAttribute);

            return compareUlongAttribute(ulongAttrIter,    foUlongAttributes,
                                         objUlongAttrIter, objUlongAttributes);
        }

        //---------------------------------------------------------------------------------------------
        bool matchAttributes(const Attributes& attributes, const ObjectParameters& objectParams)
        {
            if (attributes.boolAttributes != (attributes.boolAttributes & objectParams.boolAttributes))
            {
                return false;
            }

            for (auto ulongAttribute : supportedUlongAttr)
            {
                if (!matchUlongAttribute(attributes.ulongAttributes, objectParams.ulongAttributes, ulongAttribute))
                {
                    return false;
                }
            }

            for (auto strAttribute : supportedStrAttr)
            {
                if (!matchStrAttribute(attributes.strAttributes, objectParams.strAttributes, strAttribute))
                {
                    return false;
                }
            }

            return true;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV getAttributeValue(const CK_OBJECT_HANDLE& keyHandle,
                                const ObjectParameters& objectParams,
                                CK_ATTRIBUTE_PTR        pTemplate,
                                const CK_ULONG&         ulCount)
        {
            CK_RV             rv                 = CKR_FUNCTION_FAILED;
            bool              attributeInvalid   = false;
            bool              attributeSensitive = false;
            bool              bufferTooSmall     = false;
            bool              sizeRequest        = false;
            CK_BBOOL          attributeValue     = CK_FALSE;
            CK_ATTRIBUTE_TYPE attributeType;

            do
            {
                if (!pTemplate)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                for (auto i = 0; i < ulCount; ++i)
                {
                    attributeType = pTemplate[i].type;

                    if (!isSupportedAttribute(attributeType))
                    {
                        attributeInvalid      = true;
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        continue;
                    }

                    sizeRequest = !pTemplate[i].pValue;    // Check if this is a size request with pValue as nullptr.

                    if (isBoolAttribute(attributeType))
                    {
                        if (sizeRequest)
                        {
                            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                            continue;
                        }

                        if (pTemplate[i].ulValueLen < sizeof(CK_BBOOL))
                        {
                            bufferTooSmall        = true;
                            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            continue;
                        }

                        if (objectParams.boolAttributes.test(p11AttributeToBoolAttribute[attributeType]))
                        {
                            attributeValue = CK_TRUE;
                        }
                        else
                        {
                            attributeValue = CK_FALSE;
                        }

                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                        *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue) = attributeValue;
                    }
                    else
                    {
                        if (isUlongAttribute(attributeType))
                        {
                            if (CKA_VALUE_LEN == attributeType)
                            {
                                attributeSensitive      = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                continue;
                            }

                            auto attributeAttrIt = getUlongAttrIterator(objectParams.ulongAttributes, attributeType);
                            if (objectParams.ulongAttributes.end() == attributeAttrIt)
                            {
                                attributeInvalid = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                continue;
                            }

                            CK_ULONG attributeValue = attributeAttrIt->second;
                            CK_ULONG attributeSize  = sizeof(CK_ULONG);

                            if (sizeRequest)
                            {
                                pTemplate[i].ulValueLen = attributeSize;
                                continue;
                            }

                            if (pTemplate[i].ulValueLen < attributeSize)
                            {
                                bufferTooSmall          = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                continue;
                            }

                            pTemplate[i].ulValueLen = attributeSize;
                            *reinterpret_cast<CK_ULONG*>(pTemplate[i].pValue) = attributeValue;
                        }
                        else if (isStringAttribute(attributeType))
                        {
                            if (CKA_VALUE_KEY_BUFFER == attributeType)
                            {
                                attributeSensitive = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                continue;
                            }

                            std::string attributeValue;
                            uint32_t attributeSize = 0;

                            if (CKA_MODULUS         == attributeType ||
                                CKA_PUBLIC_EXPONENT == attributeType)
                            {
                                rv = Utils::EnclaveUtils::getRsaModulusExponent(keyHandle,
                                                                                attributeType,
                                                                                sizeRequest,
                                                                                &attributeValue,
                                                                                &attributeSize);
                                if (CKR_OK != rv)
                                {
                                    attributeInvalid = true;
                                    continue;
                                }
                            }
                            else if (CKA_EC_PARAMS == attributeType)
                            {
                                rv = Utils::EnclaveUtils::getEcParams(keyHandle,
                                                                      attributeType,
                                                                      sizeRequest,
                                                                      &attributeValue,
                                                                      &attributeSize);
                            }
                            else
                            {
                                auto attributeAttrIt = getStrAttrIterator(objectParams.strAttributes, attributeType);
                                if (objectParams.strAttributes.end() == attributeAttrIt)
                                {
                                    attributeInvalid = true;
                                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                    continue;
                                }

                                attributeValue = attributeAttrIt->second;
                                attributeSize  = attributeValue.size();
                            }

                            if (sizeRequest)
                            {
                                pTemplate[i].ulValueLen = attributeSize;
                                continue;
                            }

                            if (pTemplate[i].ulValueLen < attributeSize)
                            {
                                bufferTooSmall        = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                continue;
                            }

                            pTemplate[i].ulValueLen = attributeSize;
                            memcpy(pTemplate[i].pValue, attributeValue.data(), attributeSize);
                        }
                        else
                        {
                            attributeInvalid        = true;
                            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        }
                    }
                }

                if (bufferTooSmall)
                {
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                else if (attributeInvalid)
                {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                else if (attributeSensitive)
                {
                    rv = CKR_ATTRIBUTE_SENSITIVE;
                }
                else
                {
                    rv = CKR_OK;
                }
            } while(false);

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        CK_RV setAttributeValue(const CK_ATTRIBUTE_PTR pTemplate,
                                const CK_ULONG&        ulCount,
                                ObjectParameters*      objectParams)
        {
            CK_RV             rv = CKR_OK;
            CK_ATTRIBUTE_TYPE attributeType;
            BoolAttribute     boolKeyAttribute;

            do
            {
                if (!pTemplate || !objectParams)
                {
                    rv = CKR_ARGUMENTS_BAD;
                    break;
                }

                for (auto i = 0; i < ulCount; ++i)
                {
                    attributeType = pTemplate[i].type;

                    if (!pTemplate[i].pValue)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                    }

                    if (isBoolAttribute(attributeType))
                    {
                        if (pTemplate[i].ulValueLen != sizeof(CK_BBOOL))
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        }

                        boolKeyAttribute   = p11AttributeToBoolAttribute[attributeType];
                        CK_BBOOL boolValue = *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue);

                        if (CKA_LOCAL == attributeType &&        // Can't change CKA_LOCAL attribute.
                            (objectParams->boolAttributes[BoolAttribute::LOCAL] != boolValue))
                        {
                            rv = CKR_TEMPLATE_INCONSISTENT;
                            break;
                        }

                        if (CKA_MODIFIABLE == attributeType &&        // Can't change CKA_MODIFIABLE attribute.
                            (objectParams->boolAttributes[BoolAttribute::MODIFIABLE] != boolValue))
                        {
                            rv = CKR_TEMPLATE_INCONSISTENT;
                            break;
                        }

                        if ((CKA_PRIVATE == attributeType &&      // Can't change CKA_PRIVATE attribute.
                            (objectParams->boolAttributes[BoolAttribute::PRIVATE] != boolValue)) ||
                            (CKA_TOKEN == attributeType &&        // Can't change CKA_TOKEN attribute.
                            (objectParams->boolAttributes[BoolAttribute::TOKEN] != boolValue)))
                        {
                            rv = CKR_TEMPLATE_INCONSISTENT;
                            break;
                        }

                        if (boolValue)
                        {
                            // CKA_DERIVE and CKA_COPYABLE can't be set to CK_TRUE.
                            if ((CKA_DERIVE == attributeType) || (CKA_COPYABLE == attributeType))
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }

                            objectParams->boolAttributes.set(boolKeyAttribute);
                        }
                        else
                        {
                            objectParams->boolAttributes.reset(boolKeyAttribute);
                        }
                    }
                    else if (isUlongAttribute(attributeType))
                    {
                        rv = CKR_ATTRIBUTE_READ_ONLY;
                        break;
                    }
                    else if (isStringAttribute(attributeType))
                    {
                        if (CKA_VALUE_KEY_BUFFER == attributeType ||
                            CKA_MODULUS          == attributeType ||
                            CKA_PUBLIC_EXPONENT  == attributeType ||
                            CKA_EC_PARAMS        == attributeType)
                        {
                            rv = CKR_ATTRIBUTE_READ_ONLY;
                            break;
                        }

                        if (!pTemplate[i].pValue)
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        }

                        std::string attributeValue;
                        attributeValue.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);

                        // Delete the old attribute Value if present.
                        auto attributeAttrIt = getStrAttrIterator(objectParams->strAttributes, attributeType);
                        if (attributeAttrIt != objectParams->strAttributes.end())
                        {
                            objectParams->strAttributes.erase(attributeAttrIt);
                        }

                        // Insert the new attribute value.
                        objectParams->strAttributes.insert(StringAttributeType(attributeType, attributeValue));
                    }
                    else
                    {
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                    }
                }

                if (CKR_OK == rv)
                {
                    // Check if any incompatible boolean attributes are set.
                    auto attributeAttrIt = getUlongAttrIterator(objectParams->ulongAttributes, CKA_CLASS);
                    if (attributeAttrIt != objectParams->ulongAttributes.end())
                    {
                        CK_OBJECT_CLASS objectClass = attributeAttrIt->second;
                        rv = checkForIncompatibleBoolAttributes(objectClass, objectParams->boolAttributes);
                    }
                }
            } while(false);

            if (CKR_OK != rv)
            {
                objectParams->ulongAttributes.clear();
                objectParams->strAttributes.clear();
                objectParams->boolAttributes.reset();
            }

            return rv;
        }

        //---------------------------------------------------------------------------------------------
        bool packAttributes(const CK_SLOT_ID&         slotId,
                            const UlongAttributeSet&  ulongAttributes,
                            const StringAttributeSet& strAttributes,
                            const BoolAttributeSet&   boolAttributes,
                            std::vector<CK_ULONG>*    packedAttributes)
        {
            if (!packedAttributes)
            {
                return false;
            }

            // Pack slot id
            packedAttributes->push_back(static_cast<CK_ULONG>(slotId));

            // Pack key type
            auto keyClassAttrIt = getUlongAttrIterator(ulongAttributes, CKA_CLASS);
            if (ulongAttributes.end() == keyClassAttrIt)
            {
                return false;
            }

            auto keyTypeAttrIt = getUlongAttrIterator(ulongAttributes, CKA_KEY_TYPE);
            if (ulongAttributes.end() == keyTypeAttrIt)
            {
                return false;
            }

            KeyClassType keyClass = KeyClassType::Invalid;
            if (keyClassAttrIt->second == CKO_SECRET_KEY)
            {
                keyClass = KeyClassType::Aes;
            }
            else if (keyClassAttrIt->second == CKO_PUBLIC_KEY)
            {
                if (keyTypeAttrIt->second == CKK_RSA)
                {
                    keyClass = KeyClassType::RsaPublicKey;
                }
                else if (keyTypeAttrIt->second == CKK_EC)
                {
                    keyClass = KeyClassType::EcPublicKey;
                }
                else if (keyTypeAttrIt->second == CKK_EC_EDWARDS)
                {
                    keyClass = KeyClassType::EdPublicKey;
                }
                else
                {
                    return false;
                }
            }
            else if (keyClassAttrIt->second == CKO_PRIVATE_KEY)
            {
                if (keyTypeAttrIt->second == CKK_RSA)
                {
                    keyClass = KeyClassType::RsaPrivateKey;
                }
                else if (keyTypeAttrIt->second == CKK_EC)
                {
                    keyClass = KeyClassType::EcPrivateKey;
                }
                else if (keyTypeAttrIt->second == CKK_EC_EDWARDS)
                {
                    keyClass = KeyClassType::EdPrivateKey;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            packedAttributes->push_back(static_cast<CK_ULONG>(keyClass));

            // Pack bool attributes
            packedAttributes->push_back(static_cast<CK_ULONG>(boolAttributes.to_ulong()));

            // Pack ulong attributes
            packedAttributes->push_back(static_cast<CK_ULONG>(ulongAttributes.size()));

            std::for_each(ulongAttributes.begin(), ulongAttributes.end(), [packedAttributes](const UlongAttributeType& ulongPair)
                                                                            {
                                                                                packedAttributes->push_back(ulongPair.first);
                                                                                packedAttributes->push_back(ulongPair.second);
                                                                            });

            // Pack string attributes
            CK_ULONG strAttributeCount = strAttributes.size();
            packedAttributes->push_back(strAttributeCount);

            std::for_each(strAttributes.begin(), strAttributes.end(), [packedAttributes](const StringAttributeType& strPair)
                                                                            {
                                                                                packedAttributes->push_back(strPair.first);
                                                                                packedAttributes->push_back(static_cast<CK_ULONG>(strPair.second.size()));
                                                                                std::copy(strPair.second.begin(), strPair.second.end(), std::back_inserter(*packedAttributes));
                                                                            });
            return true;
        }

        //---------------------------------------------------------------------------------------------
        bool unpackAttributes(std::vector<CK_ULONG>& packedAttributes,
                              UlongAttributeSet*     ulongAttributes,
                              StringAttributeSet*    strAttributes,
                              BoolAttributeSet*      boolAttributes)
        {
            if (!ulongAttributes || !strAttributes || !boolAttributes)
            {
                return false;
            }

            CK_ULONG ulongSize = sizeof(CK_ULONG);
            CK_ULONG offset    = 0;

            auto getUlongValue = [&offset, &ulongSize, &packedAttributes](CK_ULONG& value)
                                 {
                                     memcpy(&value, packedAttributes.data() + offset, ulongSize);
                                     offset += 1;
                                 };

            // Unpack slotID
            CK_SLOT_ID slotId = maxSlotsSupported + 1;
            getUlongValue(slotId);

            // Unpack key type
            CK_ULONG keyClassUlong = 0;
            getUlongValue(keyClassUlong);

            // Unpack bool attributes
            CK_ULONG boolAttributesUlong = 0;
            getUlongValue(boolAttributesUlong);

            *boolAttributes = std::bitset<MAX_BOOL_ATTRIBUTES>(boolAttributesUlong);

            // Unpack ulong attributes
            CK_ULONG ulongAttributeCount = 0;
            getUlongValue(ulongAttributeCount);

            CK_ULONG attributeType  = 0;
            CK_ULONG attributeValue = 0;

            for (auto i = 0; i < ulongAttributeCount; i++)
            {
                getUlongValue(attributeType);
                getUlongValue(attributeValue);

                ulongAttributes->insert(UlongAttributeType(attributeType, attributeValue));
            }

            // Unpack string attributes
            CK_ULONG strAttributeCount = 0;
            getUlongValue(strAttributeCount);

            CK_ULONG attributeSize = 0;
            std::string strAttributeValue;
            for (auto i = 0; i < strAttributeCount; i++)
            {
                getUlongValue(attributeType);
                getUlongValue(attributeSize);

                for (auto j = 0; j < attributeSize; j++)
                {
                    getUlongValue(attributeValue);
                    strAttributeValue += static_cast<char>(attributeValue);
                }

                strAttributes->insert(StringAttributeType(attributeType, strAttributeValue));
                strAttributeValue.clear();
            }

            return true;
        }
    }
}
