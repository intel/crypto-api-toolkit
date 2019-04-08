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

#ifndef ATTRIBUTE_HELPERS_H
#define ATTRIBUTE_HELPERS_H

#include <stdint.h>
#include <string>
#include <vector>
#include <memory>

#include "CryptoEnclaveDefs.h"
#include "Constants.h"
#include "p11Defines.h"

// Globals with file scope.
namespace P11Crypto
{
    struct Attributes
    {
        uint32_t          attributeBitmask;
        std::string       label;
        std::string       id;
        CK_MECHANISM_TYPE keyGenMechanism;
        CK_OBJECT_CLASS   keyClass;
        CK_KEY_TYPE       keyType;
    };

    class AttributeHelpers
    {
    public:

        AttributeHelpers();

        //---------------------------------------------------------------------------------------------
        CK_RV extractAttributesFromTemplate(const KeyGenerationMechanism& keyGenMechanism,
                                            const CK_ATTRIBUTE_PTR        pTemplate,
                                            const CK_ULONG&               ulCount,
                                            uint32_t&                     attributeBitmask,
                                            std::string&                  label,
                                            std::string&                  id,
                                            CK_OBJECT_CLASS&              keyClass,
                                            CK_KEY_TYPE&                  keyType);
        //---------------------------------------------------------------------------------------------
        void populateAttributes(const uint32_t&               attributeBitmask,
                                const std::string&            label,
                                const std::string&            id,
                                const KeyGenerationMechanism& keyGenMechanism,
                                const CK_OBJECT_CLASS&        keyClass,
                                const CK_KEY_TYPE&            keyType,
                                Attributes&                   keyAttributes);

        //---------------------------------------------------------------------------------------------
        CK_RV getSymmetricKeyParameters(const CK_ATTRIBUTE_PTR pTemplate,
                                        const CK_ULONG&        ulCount,
                                        bool&                  importRawKey,
                                        bool&                  generateKey,
                                        std::vector<uint8_t>&  rawKeyBuffer,
                                        uint32_t&              keyLength);

        //---------------------------------------------------------------------------------------------
        bool getKeyGenMechanismFromP11SymmetricUnwrapMechanism(const CK_MECHANISM_TYPE& mechanism,
                                                               KeyGenerationMechanism&  keyGenMechanism);

        //---------------------------------------------------------------------------------------------
        CK_RV getModulusLength(const CK_ATTRIBUTE_PTR pTemplate,
                               const CK_ULONG&        ulCount,
                               bool&                  isModulusPresent,
                               uint32_t&              modulusLength);

        //---------------------------------------------------------------------------------------------
        bool isValidAttributeType(const CK_ATTRIBUTE_TYPE& attributeType);

        //---------------------------------------------------------------------------------------------
        bool isBoolAttribute(const CK_ATTRIBUTE_TYPE& attributeType);

        //---------------------------------------------------------------------------------------------
        CK_RV validateBoolAttribute(CK_VOID_PTR     attributeValue,
                                    const CK_ULONG& attributeLen,
                                    CK_BBOOL&       value);

        //---------------------------------------------------------------------------------------------
        bool getKeyAttributeFromP11Attribute(const CK_ATTRIBUTE_TYPE& attributeType, KeyAttribute& keyAttribute);

        //---------------------------------------------------------------------------------------------
        CK_RV populateTemplateFromAttributes(CK_ATTRIBUTE_PTR  pTemplate,
                                             const CK_ULONG&   ulCount,
                                             const Attributes& attributes);

        //---------------------------------------------------------------------------------------------
        CK_RV updateAttributes(const CK_OBJECT_HANDLE& keyHandle,
                               const CK_ATTRIBUTE_PTR  pTemplate,
                               const CK_ULONG&         ulCount,
                               Attributes&             attributes);
    };
}
#endif //ATTRIBUTE_HELPERS_H

