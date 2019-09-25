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

#ifndef ATTRIBUTE_UTILS_H
#define ATTRIBUTE_UTILS_H

#include "CryptoEnclaveDefs.h"
#include "p11Defines.h"
#include "EnclaveUtils.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <set>
#include <bitset>
#include <string.h>
#include <algorithm>

namespace Utils
{
    namespace AttributeUtils
    {
        enum AttrValidatorBoolParams
        {
            KeyLength                  = 1,
            RawKeyBuffer               = 2,
            ModulusBits                = 3,
            Local                      = 4,
            EcParams                   = 5,
            AttrValidatorBoolParamsMax = 6
        };

        using BoolValAttributeType = std::bitset<AttrValidatorBoolParamsMax>;

        struct AttributeValidatorStruct
        {
            BoolValAttributeType boolAttrVal;
            CK_OBJECT_CLASS      objectClass;
            CK_KEY_TYPE          keyType;

            AttributeValidatorStruct()
            {
                clear();
            }

            ~AttributeValidatorStruct()
            {
                clear();
            }

            void clear()
            {
                boolAttrVal.reset();
                objectClass = CKO_INVALID;
                keyType     = CKK_INVALID;
            }
        };

        using AttributeTypeSet = std::set<CK_ATTRIBUTE_TYPE>;

        static AttributeTypeSet supportedStrAttr {
                                                   CKA_ID,                \
                                                   CKA_LABEL,             \
                                                   CKA_VALUE_KEY_BUFFER,  \
                                                   CKA_MODULUS,           \
                                                   CKA_PUBLIC_EXPONENT,   \
                                                   CKA_EC_PARAMS          \
                                                 };
        static AttributeTypeSet supportedboolAttr {
                                                    CKA_ENCRYPT, CKA_DECRYPT,   \
                                                    CKA_WRAP, CKA_UNWRAP,       \
                                                    CKA_SIGN, CKA_VERIFY,       \
                                                    CKA_TOKEN, CKA_PRIVATE,     \
                                                    CKA_LOCAL, CKA_MODIFIABLE,  \
                                                    CKA_DERIVE, CKA_COPYABLE    \
                                                  };
        static std::set<CK_ATTRIBUTE_TYPE> supportedUlongAttr {
                                                                CKA_CLASS,             \
                                                                CKA_KEY_TYPE,          \
                                                                CKA_KEY_GEN_MECHANISM, \
                                                                CKA_MODULUS_BITS,      \
                                                                CKA_VALUE_LEN          \
                                                              };

        // Mapping supported CK_BBOOL PKCS#11 attribute type to BoolAttribute.
        static std::map<const CK_ATTRIBUTE_TYPE, const BoolAttribute> p11AttributeToBoolAttribute({{ CKA_ENCRYPT,    BoolAttribute::ENCRYPT    },
                                                                                                   { CKA_DECRYPT,    BoolAttribute::DECRYPT    },
                                                                                                   { CKA_WRAP,       BoolAttribute::WRAP       },
                                                                                                   { CKA_UNWRAP,     BoolAttribute::UNWRAP     },
                                                                                                   { CKA_SIGN,       BoolAttribute::SIGN       },
                                                                                                   { CKA_VERIFY,     BoolAttribute::VERIFY     },
                                                                                                   { CKA_TOKEN,      BoolAttribute::TOKEN      },
                                                                                                   { CKA_PRIVATE,    BoolAttribute::PRIVATE    },
                                                                                                   { CKA_LOCAL,      BoolAttribute::LOCAL      },
                                                                                                   { CKA_MODIFIABLE, BoolAttribute::MODIFIABLE },
                                                                                                   { CKA_DERIVE,     BoolAttribute::DERIVE     },
                                                                                                   { CKA_COPYABLE,   BoolAttribute::COPYABLE   } });

        // Mapping Key generation mechanism to PKCS#11 mechanism
        static std::map<const KeyGenerationMechanism, const uint32_t> keyGenMechanismToP11Mechanism({{ KeyGenerationMechanism::aesGenerateKey,           CKM_AES_KEY_GEN           },
                                                                                                     { KeyGenerationMechanism::aesImportRawKey,          CKM_AES_KEY_GEN           },
                                                                                                     { KeyGenerationMechanism::rsaGeneratePublicKey,     CKM_RSA_PKCS_KEY_PAIR_GEN },
                                                                                                     { KeyGenerationMechanism::rsaGeneratePrivateKey,    CKM_RSA_PKCS_KEY_PAIR_GEN },
                                                                                                     { KeyGenerationMechanism::aesCTRUnwrapKey,          CKM_AES_CTR               },
                                                                                                     { KeyGenerationMechanism::aesGCMUnwrapKey,          CKM_AES_GCM               },
                                                                                                     { KeyGenerationMechanism::aesCBCUnwrapKey,          CKM_AES_CBC               },
                                                                                                     { KeyGenerationMechanism::aesCBCPADUnwrapKey,       CKM_AES_CBC_PAD           },
                                                                                                     { KeyGenerationMechanism::rsaUnwrapKey,             CKM_RSA_PKCS              },
                                                                                                     { KeyGenerationMechanism::rsaImportPublicKey,       CKM_IMPORT_RSA_PUBLIC_KEY } });

        //---------------------------------------------------------------------------------------------
        auto isSupportedSymKeyLength = [](const uint32_t& keyLength) -> bool
                                         {
                                             return (static_cast<uint16_t>(SymmetricKeySize::keyLength128) == keyLength ||
                                                     static_cast<uint16_t>(SymmetricKeySize::keyLength192) == keyLength ||
                                                     static_cast<uint16_t>(SymmetricKeySize::keyLength256) == keyLength);
                                         };

        //---------------------------------------------------------------------------------------------
        auto isSupportedAsymKeyLength = [](const uint32_t& keyLength) -> bool
                                          {
                                              return (static_cast<uint16_t>(AsymmetricKeySize::keyLength1024) == keyLength ||
                                                      static_cast<uint16_t>(AsymmetricKeySize::keyLength2048) == keyLength ||
                                                      static_cast<uint16_t>(AsymmetricKeySize::keyLength3072) == keyLength ||
                                                      static_cast<uint16_t>(AsymmetricKeySize::keyLength4096)  == keyLength);
                                          };

        //---------------------------------------------------------------------------------------------
        auto isSupportedCounterBitsSize = [](const int& counterBits) -> bool
                                            {
                                                return (counterBits >= minCounterBitsSupported) &&
                                                       (counterBits <= maxCounterBitsSupported);
                                            };

        //---------------------------------------------------------------------------------------------
        CK_RV extractAttributesFromTemplate(const CK_ATTRIBUTE_PTR    pTemplate,
                                            const CK_ULONG&           ulCount,
                                            UlongAttributeSet*        ulongAttributes,
                                            StringAttributeSet*       strAttributes,
                                            BoolAttributeSet*         boolAttributeBitset,
                                            AttributeValidatorStruct* attrValStruct);

        //---------------------------------------------------------------------------------------------
        CK_RV getAttributeValue(const CK_OBJECT_HANDLE& keyHandle,
                                const ObjectParameters& objectParams,
                                CK_ATTRIBUTE_PTR        pTemplate,
                                const CK_ULONG&         ulCount);

        //---------------------------------------------------------------------------------------------
        CK_RV setAttributeValue(const CK_ATTRIBUTE_PTR pTemplate,
                                const CK_ULONG&        ulCount,
                                ObjectParameters*      objectParams);

        //---------------------------------------------------------------------------------------------
        bool validateAesKeyGenAttributes(const KeyGenerationMechanism&   keyGenMechanism,
                                         const AttributeValidatorStruct& attrValStruct);

        //---------------------------------------------------------------------------------------------
        bool isSymmetricMechanism(const CK_MECHANISM_PTR pMechanism);

        //---------------------------------------------------------------------------------------------
        bool isAsymmetricMechanism(const CK_MECHANISM_PTR pMechanism);

        //-----------------------------------------------------------------------------------------------------
        CK_RV getAesKeyGenParameters(const UlongAttributeSet&  ulongAttributes,
                                     const StringAttributeSet& strAttributes,
                                     const BoolAttributeSet&   boolAttributes,
                                     SymmetricKeyParams*       symKeyParams);

        //---------------------------------------------------------------------------------------------
        CK_RV getRsaKeyGenParameters(const UlongAttributeSet&  ulongAttributes,
                                     const StringAttributeSet& strAttributes,
                                     const BoolAttributeSet&   boolAttributes,
                                     AsymmetricKeyParams*      asymKeyParams);

        //---------------------------------------------------------------------------------------------
        void addDefaultAttributes(const KeyGenerationMechanism& keyGenMechanism, BoolAttributeSet* boolAttributes);

        //---------------------------------------------------------------------------------------------
        bool validateRsaKeyGenAttributes(const KeyGenerationMechanism&   keyGenMechanism,
                                         const AttributeValidatorStruct& attrValStruct);

        //---------------------------------------------------------------------------------------------
        bool validateId(const StringAttributeSet& publicStrAttributes, const StringAttributeSet& privateStrAttributes);

        //---------------------------------------------------------------------------------------------
        std::vector<uint8_t> getRsaSealedKeyFromMechanism(const CK_MECHANISM_PTR pMechanism);

        //---------------------------------------------------------------------------------------------
        CK_RV getAesParameters(const CK_MECHANISM_PTR pMechanism, AesCryptParams* aesCryptParams);

        //---------------------------------------------------------------------------------------------
        CK_RV getAttributesFromTemplate(const CK_ATTRIBUTE_PTR pTemplate,
                                        const CK_ULONG&        ulCount,
                                        Attributes*            attributes);

        //---------------------------------------------------------------------------------------------
        bool matchAttributes(const Attributes& attributes, const ObjectParameters& objectParams);

        //---------------------------------------------------------------------------------------------
        bool packAttributes(const CK_SLOT_ID&         slotId,
                            const UlongAttributeSet&  ulongAttributes,
                            const StringAttributeSet& strAttributes,
                            const BoolAttributeSet&   boolAttributes,
                            std::vector<ulong>*       packedAttributes);

        //---------------------------------------------------------------------------------------------
        bool unpackAttributes(std::vector<ulong>& packedAttributes,
                              UlongAttributeSet*    ulongAttributes,
                              StringAttributeSet*   strAttributes,
                              BoolAttributeSet*     boolAttributes);

        //---------------------------------------------------------------------------------------------
        CK_RV getEcKeyGenParameters(const StringAttributeSet& strAttributes, AsymmetricKeyParams* asymKeyParams);

        //---------------------------------------------------------------------------------------------
        bool validateEcKeyGenAttributes(const KeyGenerationMechanism&   keyGenMechanism,
                                        const AttributeValidatorStruct& attrValStruct,
                                        const BoolAttributeSet&         boolAttributes);
    }
}

#endif //ATTRIBUTE_UTILS_H

