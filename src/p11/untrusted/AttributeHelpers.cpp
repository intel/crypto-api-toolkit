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

#include "AttributeHelpers.h"
#include "Constants.h"

#include <string.h>
#include <map>
#include <algorithm>

namespace P11Crypto
{
    // Vector having supported attribute types.
    std::vector<CK_ATTRIBUTE_TYPE> supportedAttributes{ CKA_PRIVATE,
                                                        CKA_TOKEN,
                                                        CKA_ENCRYPT,
                                                        CKA_DECRYPT,
                                                        CKA_WRAP,
                                                        CKA_UNWRAP,
                                                        CKA_SIGN,
                                                        CKA_VERIFY,
                                                        CKA_MODIFIABLE,
                                                        CKA_COPYABLE,
                                                        CKA_DERIVE,
                                                        CKA_LOCAL,
                                                        CKA_MODULUS_BITS,
                                                        CKA_VALUE_LEN,
                                                        CKA_VALUE_KEY_BUFFER,
                                                        CKA_LABEL,
                                                        CKA_ID,
                                                        CKA_CLASS,
                                                        CKA_KEY_TYPE,
                                                        CKA_KEY_GEN_MECHANISM };

    // Vector having supported boolean attribute types.
    std::vector<CK_ATTRIBUTE_TYPE> booleanAttributes{ CKA_PRIVATE,
                                                      CKA_TOKEN,
                                                      CKA_ENCRYPT,
                                                      CKA_DECRYPT,
                                                      CKA_WRAP,
                                                      CKA_UNWRAP,
                                                      CKA_SIGN,
                                                      CKA_VERIFY,
                                                      CKA_MODIFIABLE,
                                                      CKA_COPYABLE,
                                                      CKA_DERIVE,
                                                      CKA_LOCAL };

    // Mapping supported CK_BBOOL PKCS#11 attribute type to KeyAttribute.
    std::map<const CK_ATTRIBUTE_TYPE, const KeyAttribute> p11AttributeToKeyAttribute({{ CKA_PRIVATE,    KeyAttribute::PRIVATE    },
                                                                                      { CKA_TOKEN,      KeyAttribute::TOKEN      },
                                                                                      { CKA_ENCRYPT,    KeyAttribute::ENCRYPT    },
                                                                                      { CKA_DECRYPT,    KeyAttribute::DECRYPT    },
                                                                                      { CKA_WRAP,       KeyAttribute::WRAP       },
                                                                                      { CKA_UNWRAP,     KeyAttribute::UNWRAP     },
                                                                                      { CKA_SIGN,       KeyAttribute::SIGN       },
                                                                                      { CKA_VERIFY,     KeyAttribute::VERIFY     },
                                                                                      { CKA_MODIFIABLE, KeyAttribute::MODIFIABLE },
                                                                                      { CKA_COPYABLE,   KeyAttribute::COPYABLE   },
                                                                                      { CKA_DERIVE,     KeyAttribute::DERIVE     },
                                                                                      { CKA_LOCAL,      KeyAttribute::LOCAL      } });

    // Mapping Key generation mechanism to PKCS#11 mechanism
    std::map<const KeyGenerationMechanism, const uint32_t> keyGenMechanismToP11Mechanism({{ KeyGenerationMechanism::aesGenerateKey,           CKM_AES_KEY_GEN           },
                                                                                          { KeyGenerationMechanism::aesImportRawKey,          CKM_AES_KEY_GEN           },
                                                                                          { KeyGenerationMechanism::rsaGeneratePublicKey,     CKM_RSA_PKCS_KEY_PAIR_GEN },
                                                                                          { KeyGenerationMechanism::rsaGeneratePrivateKey,    CKM_RSA_PKCS_KEY_PAIR_GEN },
                                                                                          { KeyGenerationMechanism::aesCTRUnwrapKey,          CKM_AES_CTR               },
                                                                                          { KeyGenerationMechanism::aesGCMUnwrapKey,          CKM_AES_GCM               },
                                                                                          { KeyGenerationMechanism::aesCBCUnwrapKey,          CKM_AES_CBC               },
                                                                                          { KeyGenerationMechanism::aesCBCPADUnwrapKey,       CKM_AES_CBC_PAD           },
                                                                                          { KeyGenerationMechanism::rsaUnwrapKey,             CKM_RSA_PKCS              },
                                                                                          { KeyGenerationMechanism::rsaImportPublicKey,       CKM_IMPORT_RSA_PUBLIC_KEY },
                                                                                          { KeyGenerationMechanism::aesImportPbindKey,        CKM_AES_PBIND             },
                                                                                          { KeyGenerationMechanism::rsaImportPbindPublicKey,  CKM_RSA_PBIND_IMPORT      },
                                                                                          { KeyGenerationMechanism::rsaImportPbindPrivateKey, CKM_RSA_PBIND_IMPORT      } });

    //---------------------------------------------------------------------------------------------
    AttributeHelpers::AttributeHelpers()
    {

    }

    //---------------------------------------------------------------------------------------------
    bool AttributeHelpers::isValidAttributeType(const CK_ATTRIBUTE_TYPE& attributeType)
    {
        bool result = true;

        auto it = std::find(supportedAttributes.begin(), supportedAttributes.end(), attributeType);
        if (supportedAttributes.end() == it)
        {
            result = false;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeHelpers::isBoolAttribute(const CK_ATTRIBUTE_TYPE& attributeType)
    {
        bool result = false;

        auto it = std::find(booleanAttributes.begin(), booleanAttributes.end(), attributeType);
        if (booleanAttributes.end() != it)
        {
            result = true;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeHelpers::getKeyAttributeFromP11Attribute(const CK_ATTRIBUTE_TYPE& attributeType,
                                                           KeyAttribute&            keyAttribute)
    {
        bool result = false;

        auto it = p11AttributeToKeyAttribute.find(attributeType);
        if (p11AttributeToKeyAttribute.end() != it)
        {
            keyAttribute = it->second;
            result       = true;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AttributeHelpers::validateBoolAttribute(CK_VOID_PTR     attributeValue,
                                                  const CK_ULONG& attributeLen,
                                                  CK_BBOOL&       value)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            if (!attributeValue)
            {
                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
            }
            if (sizeof(CK_BBOOL) == attributeLen)
            {
                if (CK_TRUE == *reinterpret_cast<CK_BBOOL*>(attributeValue))
                {
                    value = CK_TRUE;
                    rv    = CKR_OK;
                    break;
                }
                else if (CK_FALSE == *reinterpret_cast<CK_BBOOL*>(attributeValue))
                {
                    value = CK_FALSE;
                    rv    = CKR_OK;
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
    CK_RV validateAttributesWithMechanism(const uint32_t&               attributeBitMask,
                                          const KeyGenerationMechanism& keyGenMechanism,
                                          const CK_BBOOL&               hasSymmetricKeyLength,
                                          const CK_BBOOL&               hasImportSymmetricKeyBuffer,
                                          const CK_BBOOL&               hasModulusLength,
                                          const CK_OBJECT_CLASS&        keyClass,
                                          const CK_KEY_TYPE&            keyType)
    {
        CK_RV rv     = CKR_OK;
        bool  result = false;

        do
        {
            switch(keyGenMechanism)
            {
                case KeyGenerationMechanism::aesGenerateKey:
                    result = (CKO_SECRET_KEY == keyClass  &&
                             CKK_AES         == keyType   &&
                             hasSymmetricKeyLength        &&
                             !hasImportSymmetricKeyBuffer &&
                             !hasModulusLength);
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case KeyGenerationMechanism::aesImportRawKey:
                    result = (CKO_SECRET_KEY == keyClass &&
                             CKK_AES         == keyType  &&
                             hasImportSymmetricKeyBuffer &&
                             !hasSymmetricKeyLength      &&
                             !hasModulusLength           &&
                             !(KeyAttribute::LOCAL & attributeBitMask));
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case KeyGenerationMechanism::rsaGeneratePublicKey:
                    result = (CKO_PUBLIC_KEY == keyClass  &&
                             CKK_RSA         == keyType   &&
                             hasModulusLength             &&
                             !hasImportSymmetricKeyBuffer &&
                             !hasSymmetricKeyLength);
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case KeyGenerationMechanism::rsaGeneratePrivateKey:
                    result = (CKO_PRIVATE_KEY == keyClass &&
                             CKK_RSA          == keyType  &&
                             !hasModulusLength            &&
                             !hasImportSymmetricKeyBuffer &&
                             !hasSymmetricKeyLength);
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case KeyGenerationMechanism::rsaImportPublicKey:
                case KeyGenerationMechanism::rsaImportPbindPublicKey:
                    result = (CKO_PUBLIC_KEY == keyClass  &&
                             CKK_RSA         == keyType   &&
                             !hasModulusLength            &&
                             !hasImportSymmetricKeyBuffer &&
                             !hasSymmetricKeyLength       &&
                             !(KeyAttribute::LOCAL & attributeBitMask));
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case KeyGenerationMechanism::rsaImportPbindPrivateKey:
                    result = (CKO_PRIVATE_KEY == keyClass &&
                             CKK_RSA          == keyType  &&
                             !hasModulusLength            &&
                             !hasImportSymmetricKeyBuffer &&
                             !hasSymmetricKeyLength       &&
                             !(KeyAttribute::LOCAL & attributeBitMask));
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case KeyGenerationMechanism::aesCTRUnwrapKey:
                case KeyGenerationMechanism::aesGCMUnwrapKey:
                case KeyGenerationMechanism::aesCBCUnwrapKey:
                case KeyGenerationMechanism::aesCBCPADUnwrapKey:
                case KeyGenerationMechanism::rsaUnwrapKey:
                case KeyGenerationMechanism::aesImportPbindKey:
                    result = (CKO_SECRET_KEY == keyClass  &&
                             CKK_AES         == keyType   &&
                             !hasImportSymmetricKeyBuffer &&
                             !hasSymmetricKeyLength       &&
                             !hasModulusLength            &&
                             !(KeyAttribute::LOCAL & attributeBitMask));
                    if (!result)
                    {
                        rv = CKR_ATTRIBUTE_VALUE_INVALID;
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
    void addDefaultAttributes(uint32_t&                 keyAttributes,
                          const KeyGenerationMechanism& keyGenMechanism)
    {
        switch(keyGenMechanism)
        {
            case KeyGenerationMechanism::aesGenerateKey:
            case KeyGenerationMechanism::rsaGeneratePublicKey:
            case KeyGenerationMechanism::rsaGeneratePrivateKey:
                keyAttributes |= KeyAttribute::LOCAL;  // For all keys generated on the token, CKA_LOCAL attribute is set to CK_TRUE.
                break;
            default:
                break;
        }
    }

    //---------------------------------------------------------------------------------------------
    CK_RV checkForIncompatibleAttributes(const CK_OBJECT_CLASS& keyClass,
                                         const uint32_t&        attributeBitMask)
    {
        CK_RV rv = CKR_OK;

        do
        {
            switch(keyClass)
            {
                case CKO_SECRET_KEY:    // Can't set CKA_SIGN and CKA_VERIFY on AES Keys
                    if (KeyAttribute::SIGN   & attributeBitMask ||
                        KeyAttribute::VERIFY & attributeBitMask)
                    {
                        rv = CKR_TEMPLATE_INCONSISTENT;
                    }
                    break;
                case CKO_PUBLIC_KEY:    // Can't set CKA_DECRYPT, CKA_SIGN and CKA_UNWRAP on RSA public Keys
                    if (KeyAttribute::DECRYPT & attributeBitMask ||
                        KeyAttribute::SIGN    & attributeBitMask ||
                        KeyAttribute::UNWRAP  & attributeBitMask)
                    {
                        rv = CKR_TEMPLATE_INCONSISTENT;
                    }
                    break;
                case CKO_PRIVATE_KEY:   // Can't set CKA_ENCRYPT, CKA_VERIFY and CKA_WRAP on RSA private Keys
                    if (KeyAttribute::ENCRYPT & attributeBitMask ||
                        KeyAttribute::VERIFY  & attributeBitMask ||
                        KeyAttribute::WRAP    & attributeBitMask)
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
    CK_RV AttributeHelpers::extractAttributesFromTemplate(const KeyGenerationMechanism& keyGenMechanism,
                                                          const CK_ATTRIBUTE_PTR        pTemplate,
                                                          const CK_ULONG&               ulCount,
                                                          uint32_t&                     attributeBitmask,
                                                          std::string&                  label,
                                                          std::string&                  id,
                                                          CK_OBJECT_CLASS&              keyClass,
                                                          CK_KEY_TYPE&                  keyType)
    {
        CK_RV             rv                          = CKR_OK;
        CK_BBOOL          isTrue                      = CK_FALSE;
        CK_BBOOL          isModifiableFalse           = CK_FALSE;
        CK_BBOOL          isKeyClassPresent           = CK_FALSE;
        CK_BBOOL          isKeyTypePresent            = CK_FALSE;
        CK_BBOOL          isIdPresent                 = CK_FALSE;
        CK_BBOOL          hasSymmetricKeyLength       = CK_FALSE;
        CK_BBOOL          hasImportSymmetricKeyBuffer = CK_FALSE;
        CK_BBOOL          hasModulusLength            = CK_FALSE;
        CK_ATTRIBUTE_TYPE attributeType;

        do
        {
            if (!pTemplate)
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            attributeBitmask = 0;

            for (CK_ULONG i = 0; i < ulCount; ++i)
            {
                attributeType = pTemplate[i].type;

                if (!isValidAttributeType(attributeType))
                {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
                }

                if (CKR_OK != rv)
                {
                    break;
                }

                if (isBoolAttribute(attributeType))
                {
                    rv = validateBoolAttribute(pTemplate[i].pValue,
                                               pTemplate[i].ulValueLen,
                                               isTrue);
                    if (isTrue && (CKR_OK == rv))
                    {
                        if (CKA_COPYABLE == attributeType ||    // Rejecting if CKA_COPYABLE or CKA_DERIVE is set to CK_TRUE.
                            CKA_DERIVE   == attributeType)
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                        }
                        else
                        {
                            attributeBitmask |= p11AttributeToKeyAttribute[attributeType];
                        }
                    }
                    else if (!isTrue         &&
                             (CKR_OK == rv)  &&
                             (CKA_MODIFIABLE == attributeType))
                    {
                        isModifiableFalse = CK_TRUE;
                    }
                }
                else
                {
                    switch (attributeType)
                    {
                        case CKA_MODULUS_BITS:
                            if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            hasModulusLength = CK_TRUE;
                            break;
                        case CKA_VALUE_LEN:
                            if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            hasSymmetricKeyLength = CK_TRUE;
                            break;
                        case CKA_VALUE_KEY_BUFFER:
                            hasImportSymmetricKeyBuffer = CK_TRUE;
                            break;
                        case CKA_LABEL:
                            if (!pTemplate[i].pValue)
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            label.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);
                            break;
                        case CKA_ID:
                            isIdPresent = CK_TRUE;
                            if (!pTemplate[i].pValue)
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            id.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);
                            break;
                        case CKA_CLASS:
                            if (!pTemplate[i].pValue ||
                                sizeof(CK_OBJECT_CLASS) != pTemplate[i].ulValueLen)
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }

                            keyClass = *reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue);
                            isKeyClassPresent = CK_TRUE;
                            break;
                        case CKA_KEY_TYPE:
                            if (!pTemplate[i].pValue ||
                                sizeof(CK_KEY_TYPE) != pTemplate[i].ulValueLen)
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            keyType = *reinterpret_cast<CK_KEY_TYPE*>(pTemplate[i].pValue);
                            isKeyTypePresent = CK_TRUE;
                            break;
                        case CKA_KEY_GEN_MECHANISM: // This attribute can't be set during key creation.
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        default:
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                            break;
                    }
                }
            }

            if (CKR_OK != rv)
            {
                break;
            }

            if (!isModifiableFalse)
            {
                attributeBitmask |= KeyAttribute::MODIFIABLE; // CKA_MODIFIABLE is CK_TRUE by default, unless specified as CK_FALSE.
            }

            if (!isKeyTypePresent  ||    // Compulsory attribute to be set.
                !isKeyClassPresent)    // Compulsory attribute to be set.
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            if (isIdPresent &&
                CKK_RSA != keyType)
            {
                rv = CKR_TEMPLATE_INCONSISTENT;
                break;
            }

            rv = validateAttributesWithMechanism(attributeBitmask,
                                                 keyGenMechanism,
                                                 hasSymmetricKeyLength,
                                                 hasImportSymmetricKeyBuffer,
                                                 hasModulusLength,
                                                 keyClass,
                                                 keyType);
            if (CKR_OK != rv)
            {
                break;
            }

            rv = checkForIncompatibleAttributes(keyClass, attributeBitmask);
            if (CKR_OK != rv)
            {
                break;
            }

            addDefaultAttributes(attributeBitmask, keyGenMechanism);

        } while(false);

        if (CKR_OK != rv)
        {
            attributeBitmask = 0;
        }

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AttributeHelpers::getSymmetricKeyParameters(const CK_ATTRIBUTE_PTR pTemplate,
                                                      const CK_ULONG&        ulCount,
                                                      bool&                  importRawKey,
                                                      bool&                  generateKey,
                                                      std::vector<uint8_t>&  rawKeyBuffer,
                                                      uint32_t&              keyLength)
    {
        CK_RV rv = CKR_OK;

        do
        {
            if (!pTemplate)
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            importRawKey = false;
            generateKey  = false;

            for (CK_ULONG i = 0; i < ulCount; ++i)
            {
                switch (pTemplate[i].type)
                {
                    case CKA_VALUE_KEY_BUFFER:
                        importRawKey = true;
                        if (!pTemplate[i].pValue)
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        }

                        keyLength = pTemplate[i].ulValueLen;
                        rawKeyBuffer.clear();
                        rawKeyBuffer.resize(keyLength);
                        memcpy(&rawKeyBuffer[0], pTemplate[i].pValue, keyLength);

                        break;
                    case CKA_VALUE_LEN:
                        generateKey = true;
                        if (pTemplate[i].ulValueLen != sizeof(CK_ULONG) ||
                            !pTemplate[i].pValue)
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        }

                        keyLength = *reinterpret_cast<CK_ULONG*>(pTemplate[i].pValue);
                        break;
                    default:
                        break;
                }
            }
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AttributeHelpers::getModulusLength(const CK_ATTRIBUTE_PTR pTemplate,
                                             const CK_ULONG&        ulCount,
                                             bool&                  isModulusPresent,
                                             uint32_t&              modulusLength)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;

        do
        {
            isModulusPresent = false;
            modulusLength    = 0;

            if (!pTemplate)
            {
                rv = CKR_TEMPLATE_INCOMPLETE;
                break;
            }

            for (CK_ULONG i = 0; i < ulCount; ++i)
            {
                if (CKR_OK == rv)
                {
                    break;
                }

                switch (pTemplate[i].type)
                {
                    case CKA_MODULUS_BITS:
                        if (pTemplate[i].ulValueLen != sizeof(CK_ULONG) ||
                            !pTemplate[i].pValue)
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        }

                        modulusLength    = *reinterpret_cast<CK_ULONG*>(pTemplate[i].pValue);
                        isModulusPresent = true;

                        switch (modulusLength)
                        {
                            case rsaKeySize1024:
                            case rsaKeySize2048:
                            case rsaKeySize3072:
                            case rsaKeySize4096:
                                rv = CKR_OK;
                                break;
                            default:
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                        }
                        break;
                    default:
                        break;
                    }
                }
        } while(false);

        return rv;
    }

    //---------------------------------------------------------------------------------------------
    bool getP11MechanismFromKeyGenMechanism(const KeyGenerationMechanism& keyGenMechanism,
                                            uint32_t&                     p11Mechanism)
    {
        bool result = false;

        auto it = keyGenMechanismToP11Mechanism.find(keyGenMechanism);
        if (keyGenMechanismToP11Mechanism.end() != it)
        {
            p11Mechanism = it->second;
            result       = true;
        }

        return result;
    }

    //---------------------------------------------------------------------------------------------
    void AttributeHelpers::populateAttributes(const uint32_t&               attributeBitmask,
                                              const std::string&            label,
                                              const std::string&            id,
                                              const KeyGenerationMechanism& keyGenMechanism,
                                              const CK_OBJECT_CLASS&        keyClass,
                                              const CK_KEY_TYPE&            keyType,
                                              Attributes&                   keyAttributes)
    {
        uint32_t p11Mechanism;
        bool result = getP11MechanismFromKeyGenMechanism(keyGenMechanism, p11Mechanism);

        keyAttributes.attributeBitmask = attributeBitmask;
        keyAttributes.keyClass         = keyClass;
        keyAttributes.keyGenMechanism  = p11Mechanism;
        keyAttributes.keyType          = keyType;
        keyAttributes.label            = label;
        keyAttributes.id               = id;
    }

    //---------------------------------------------------------------------------------------------
    bool AttributeHelpers::getKeyGenMechanismFromP11SymmetricUnwrapMechanism(const CK_MECHANISM_TYPE& mechanism,
                                                                             KeyGenerationMechanism&  keyGenMechanism)
    {
        bool result = true;

        switch(mechanism)
        {
            case CKM_AES_CTR:
                keyGenMechanism = KeyGenerationMechanism::aesCTRUnwrapKey;
                break;
            case CKM_AES_GCM:
                keyGenMechanism = KeyGenerationMechanism::aesGCMUnwrapKey;
                break;
            case CKM_AES_CBC:
                keyGenMechanism = KeyGenerationMechanism::aesCBCUnwrapKey;
                break;
            case CKM_AES_CBC_PAD:
                keyGenMechanism = KeyGenerationMechanism::aesCBCPADUnwrapKey;
                break;
            default:
                result = false;
                break;
        }
        return result;
    }

    //---------------------------------------------------------------------------------------------
    CK_RV AttributeHelpers::populateTemplateFromAttributes(CK_ATTRIBUTE_PTR  pTemplate,
                                                           const CK_ULONG&   ulCount,
                                                           const Attributes& attributes)
    {
        CK_RV             rv                   = CKR_FUNCTION_FAILED;
        bool              isAttributeInvalid   = false;
        bool              isAttributeSensitive = false;
        bool              isBufferTooSmall     = false;
        bool              isAttributeValueNull = false;
        CK_BBOOL          attributeValue       = CK_FALSE;
        uint32_t          labelSize            = 0;
        uint32_t          idSize               = 0;
        CK_ULONG          keyClassSize         = sizeof(CK_OBJECT_CLASS);
        CK_ULONG          keyTypeSize          = sizeof(CK_KEY_TYPE);
        CK_ULONG          mechanismTypeSize    = sizeof(CK_MECHANISM_TYPE);
        CK_ATTRIBUTE_TYPE attributeType;
        KeyAttribute      boolKeyAttribute;

        do
        {
            if (!pTemplate)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            for (auto i = 0; i < ulCount; i++)
            {
                attributeType = pTemplate[i].type;

                if (!isValidAttributeType(attributeType))   // Check if attribute type is supported.
                {
                    isAttributeInvalid      = true;
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    continue;
                }

                if (pTemplate[i].pValue)    // Check if this is a size request with pValue as nullptr.
                {
                    isAttributeValueNull = false;
                }
                else
                {
                    isAttributeValueNull = true;
                }

                if (isBoolAttribute(attributeType))
                {
                    if (isAttributeValueNull)
                    {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                        continue;
                    }

                    if (pTemplate[i].ulValueLen < sizeof(CK_BBOOL))
                    {
                        isBufferTooSmall        = true;
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        continue;
                    }

                    boolKeyAttribute = p11AttributeToKeyAttribute[attributeType];

                    if (attributes.attributeBitmask & boolKeyAttribute)
                    {
                        attributeValue = CK_TRUE;
                    }
                    else
                    {
                        attributeValue = CK_FALSE;
                    }

                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue) = attributeValue;
                    continue;
                }
                else
                {
                    switch (attributeType)
                    {
                        case CKA_KEY_GEN_MECHANISM:
                            if (isAttributeValueNull)
                            {
                                pTemplate[i].ulValueLen = mechanismTypeSize;
                                break;
                            }

                            if (pTemplate[i].ulValueLen < mechanismTypeSize)
                            {
                                isBufferTooSmall        = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                break;
                            }

                            pTemplate[i].ulValueLen = mechanismTypeSize;
                            *reinterpret_cast<CK_MECHANISM_TYPE*>(pTemplate[i].pValue) = attributes.keyGenMechanism;
                            break;
                        case CKA_LABEL:
                            labelSize = attributes.label.size();

                            if (isAttributeValueNull)
                            {
                                pTemplate[i].ulValueLen = labelSize;
                                break;
                            }

                            if (pTemplate[i].ulValueLen < labelSize)
                            {
                                isBufferTooSmall        = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                break;
                            }

                            pTemplate[i].ulValueLen = labelSize;
                            memcpy(pTemplate[i].pValue, &attributes.label[0], labelSize);
                            break;
                        case CKA_ID:
                            idSize = attributes.id.size();

                            if (isAttributeValueNull)
                            {
                                pTemplate[i].ulValueLen = idSize;
                                break;
                            }

                            if (pTemplate[i].ulValueLen < idSize)
                            {
                                isBufferTooSmall        = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                break;
                            }

                            pTemplate[i].ulValueLen = idSize;
                            memcpy(pTemplate[i].pValue, &attributes.id[0], idSize);
                            break;
                        case CKA_CLASS:
                            if (isAttributeValueNull)
                            {
                                pTemplate[i].ulValueLen = keyClassSize;
                                break;
                            }

                            if (pTemplate[i].ulValueLen < keyClassSize)
                            {
                                isBufferTooSmall        = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                break;
                            }

                            pTemplate[i].ulValueLen = keyClassSize;
                            *reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue) = attributes.keyClass;
                            break;
                        case CKA_KEY_TYPE:
                            if (isAttributeValueNull)
                            {
                                pTemplate[i].ulValueLen = keyTypeSize;
                                break;
                            }

                            if (pTemplate[i].ulValueLen < keyTypeSize)
                            {
                                isBufferTooSmall        = true;
                                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                break;
                            }

                            pTemplate[i].ulValueLen = keyTypeSize;
                            *reinterpret_cast<CK_KEY_TYPE*>(pTemplate[i].pValue) = attributes.keyType;
                            break;
                        case CKA_MODULUS_BITS:
                        case CKA_VALUE_LEN:
                        case CKA_VALUE_KEY_BUFFER:
                            isAttributeSensitive    = true;
                            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            break;
                        default:
                            break;
                    }
                }
            }

            if (isBufferTooSmall)
            {
                rv = CKR_BUFFER_TOO_SMALL;
            }
            else if (isAttributeInvalid)
            {
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
            else if (isAttributeSensitive)
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
    CK_RV AttributeHelpers::updateAttributes(const CK_OBJECT_HANDLE& keyHandle,
                                             const CK_ATTRIBUTE_PTR  pTemplate,
                                             const CK_ULONG&         ulCount,
                                             Attributes&             attributes)
    {
        CK_RV             rv      = CKR_OK;
        uint32_t          bitMask = 0;
        CK_ATTRIBUTE_TYPE attributeType;
        std::string       label, id;
        KeyAttribute      boolKeyAttribute;
        CK_BBOOL          boolValue;

        do
        {
            if (!pTemplate)
            {
                rv = CKR_ARGUMENTS_BAD;
                break;
            }

            bitMask = attributes.attributeBitmask;
            label   = attributes.label;
            id      = attributes.id;

            for (auto i = 0; i < ulCount; i++)
            {
                attributeType = pTemplate[i].type;

                if (!isValidAttributeType(attributeType))   // Check if attribute type is supported.
                {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
                }

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

                    boolKeyAttribute = p11AttributeToKeyAttribute[attributeType];
                    boolValue        = *reinterpret_cast<CK_BBOOL*>(pTemplate[i].pValue);

                    if (CKA_LOCAL == attributeType &&        // Can't change CKA_LOCAL attribute.
                        (attributes.attributeBitmask & KeyAttribute::LOCAL) != boolValue)
                    {
                        rv = CKR_TEMPLATE_INCONSISTENT;
                        break;
                    }

                    if (CK_TRUE == boolValue)
                    {
                        if (CKA_DERIVE   == attributeType ||    // CKA_DERIVE and CKA_COPYABLE can't be set to CK_TRUE.
                            CKA_COPYABLE == attributeType)
                        {
                            rv = CKR_ATTRIBUTE_VALUE_INVALID;
                            break;
                        }

                        bitMask |= boolKeyAttribute;
                    }
                    else
                    {
                        bitMask &= ~(boolKeyAttribute);
                    }
                }
                else
                {
                    switch (attributeType)
                    {
                        case CKA_LABEL:
                            if (!pTemplate[i].pValue)
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            label.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);
                            break;
                        case CKA_ID:
                            if (!pTemplate[i].pValue)
                            {
                                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                                break;
                            }
                            id.assign(reinterpret_cast<const char*>(pTemplate[i].pValue), pTemplate[i].ulValueLen);
                            break;
                        case CKA_KEY_GEN_MECHANISM:
                        case CKA_CLASS:
                        case CKA_KEY_TYPE:
                        case CKA_MODULUS_BITS:
                        case CKA_VALUE_LEN:
                        case CKA_VALUE_KEY_BUFFER:
                            rv = CKR_ATTRIBUTE_READ_ONLY;
                            break;
                        default:
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                            break;
                    }
                }

                if (CKR_OK != rv)
                {
                    break;
                }
            }

            if (CKR_OK == rv)
            {
                rv = checkForIncompatibleAttributes(attributes.keyClass, bitMask);
            }
        } while(false);

        if (CKR_OK == rv)
        {
            attributes.attributeBitmask = bitMask;
            attributes.label            = label;
            attributes.id               = id;
        }

        return rv;
    }
}