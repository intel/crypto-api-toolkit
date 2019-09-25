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

#include "ObjectManagement.h"

//---------------------------------------------------------------------------------------------
static CK_MECHANISM_TYPE getMechanismType(CK_ATTRIBUTE_PTR pTemplate, const CK_ULONG& ulCount)
{
    CK_MECHANISM_TYPE mechanismType        = CKM_VENDOR_DEFINED_INVALID;
    bool              isObjectClassPresent = false;
    CK_ULONG          keyType;

    if (!pTemplate || !ulCount)
    {
        return mechanismType;
    }

    for (auto i = 0; !isObjectClassPresent && (i < ulCount); ++i)
    {
        switch(pTemplate[i].type)
        {
            case CKA_CLASS:
                if (!pTemplate[i].pValue)
                {
                    mechanismType = CKM_VENDOR_DEFINED_INVALID;
                    break;
                }

                isObjectClassPresent = true;
                keyType = *(reinterpret_cast<CK_OBJECT_CLASS*>(pTemplate[i].pValue));

                if (CKO_SECRET_KEY == keyType)
                {
                    mechanismType = CKM_AES_KEY_GEN;
                }
                else if (CKO_PUBLIC_KEY == keyType)
                {
                    mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;
                }
                break;
            default:
                break;
        }
    }

    return mechanismType;
}

//---------------------------------------------------------------------------------------------
CK_RV destroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        if (!gSessionCache->findObject(hKey))
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkWriteAccess(hSession, hKey);
        if (CKR_OK != rv)
        {
            break;
        }

        // Remove object from enclave cache.
        KeyType keyType = KeyType::Invalid;
        if (gSessionCache->checkKeyType(hKey, CKK_AES))
        {
            keyType = KeyType::Aes;
        }
        else if (gSessionCache->checkKeyType(hKey, CKK_RSA))
        {
            keyType = KeyType::Rsa;
        }
        else if (gSessionCache->checkKeyType(hKey, CKK_EC))
        {
            keyType = KeyType::Ec;
        }
        else if (gSessionCache->checkKeyType(hKey, CKK_EC_EDWARDS))
        {
            keyType = KeyType::Ed;
        }
        else
        {
            rv = CKR_KEY_HANDLE_INVALID;
            break;
        }

        rv = Utils::EnclaveUtils::destroyKey(hKey, keyType);

        if (CKR_OK != rv)
        {
            break;
        }

        // Remove object from session cache.
        gSessionCache->removeObject(hSession, hKey);
    } while (false);

    return rv;
}

CK_RV createObject(CK_SESSION_HANDLE    hSession,
                   CK_ATTRIBUTE_PTR     pTemplate,
                   CK_ULONG             ulCount,
                   CK_OBJECT_HANDLE_PTR phObject)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pTemplate || !ulCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (!gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        CK_MECHANISM_TYPE mechanismType = getMechanismType(pTemplate, ulCount);

        CK_MECHANISM mechanism { mechanismType, nullptr, 0 };

        if (CKM_AES_KEY_GEN == mechanismType)
        {
            rv = generateKey(hSession, &mechanism, pTemplate, ulCount, phObject);
        }
        else if (CKM_RSA_PKCS_KEY_PAIR_GEN == mechanismType)
        {
            CK_OBJECT_CLASS  rsaPrivateObjectClass  = CKO_PRIVATE_KEY;
            CK_KEY_TYPE      rsaKeyType             = CKK_RSA;
            CK_OBJECT_HANDLE privateKeyHandle       = CK_INVALID_HANDLE;
            CK_ATTRIBUTE     privateKeyAttributes[] = {{ CKA_CLASS,     &rsaPrivateObjectClass, sizeof(rsaPrivateObjectClass) },
                                                       { CKA_KEY_TYPE,  &rsaKeyType,            sizeof(rsaKeyType) } };

            rv = generateKeyPair(hSession, &mechanism,
                                 pTemplate, ulCount,
                                 privateKeyAttributes, sizeof(privateKeyAttributes) / sizeof(CK_ATTRIBUTE),
                                 phObject, &privateKeyHandle);
            if (CKR_OK == rv)
            {
                // Destroy the private key handle since C_CreateObject API gives out only one key(public) handle
                rv = destroyObject(hSession, privateKeyHandle);
            }
        }
        else
        {
            rv = CKR_TEMPLATE_INCOMPLETE;
            break;
        }
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV getAttributeValue(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE  hObject,
                        CK_ATTRIBUTE_PTR  pTemplate,
                        CK_ULONG          ulCount)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid() || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (!gSessionCache->findObject(hObject))
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkReadAccess(hSession, hObject);
        if (CKR_OK != rv)
        {
            break;
        }

        ObjectParameters objectParams;

        if (gSessionCache->getObjectParams(hObject, &objectParams))
        {
            rv = Utils::AttributeUtils::getAttributeValue(hObject, objectParams, pTemplate, ulCount);
        }
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
static CK_RV updateTokenObjectFile(const CK_SLOT_ID&       slotId,
                                   const CK_OBJECT_HANDLE& keyHandle,
                                   const ObjectParameters& objectParams)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        std::vector<CK_ULONG> packedAttributes;

        if (!Utils::AttributeUtils::packAttributes(slotId,
                                                   objectParams.ulongAttributes,
                                                   objectParams.strAttributes,
                                                   objectParams.boolAttributes,
                                                   &packedAttributes))
        {
            rv = CKR_GENERAL_ERROR;
            break;
        }

        CK_KEY_TYPE keyType = gSessionCache->getKeyType(keyHandle);

        rv = Utils::EnclaveUtils::updateTokenObject(keyHandle, keyType, packedAttributes);
        if (CKR_OK != rv)
        {
            break;
        }

    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV setAttributeValue(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE  hObject,
                        CK_ATTRIBUTE_PTR  pTemplate,
                        CK_ULONG          ulCount)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!pTemplate)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid() || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        if (!gSessionCache->findObject(hObject))
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
            break;
        }

        rv = P11Crypto::checkWriteAccess(hSession, hObject);
        if (CKR_OK != rv)
        {
            break;
        }

        ObjectParameters objectParams;
        if (!gSessionCache->getObjectParams(hObject, &objectParams))
        {
            rv = CKR_FUNCTION_FAILED;
            break;
        }

        if (!(objectParams.boolAttributes.test(BoolAttribute::MODIFIABLE)))  // Rejecting if CKA_MODIFIABLE is NOT SET.
        {
            rv = CKR_ACTION_PROHIBITED;
            break;
        }

        rv = Utils::AttributeUtils::setAttributeValue(pTemplate, ulCount, &objectParams);
        if (CKR_OK != rv)
        {
            break;
        }

        // If a session that's NOT logged in has tried to set CKA_PRIVATE as CK_TRUE, reject it.
        if (!gSessionCache->isUserLoggedIn(hSession) &&
            objectParams.boolAttributes.test(BoolAttribute::PRIVATE))
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
            break;
        }

        if (objectParams.boolAttributes.test(BoolAttribute::TOKEN))
        {
            rv = updateTokenObjectFile(slotID, hObject, objectParams);
            if (CKR_OK != rv)
            {
                break;
            }
        }

        gSessionCache->addObject(hSession, hObject, objectParams);
    } while (false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV findObjectsInit(CK_SESSION_HANDLE hSession,
                      CK_ATTRIBUTE_PTR  pTemplate,
                      CK_ULONG          ulCount)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid() || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
        if (!sessionParameters.activeOperation.test(ActiveOp::FindObjects_None))
        {
            rv = CKR_OPERATION_ACTIVE;
            break;
        }

        Attributes attributes;

        bool findAllHandles = !pTemplate;
        if (!findAllHandles)
        {
            rv = Utils::AttributeUtils::getAttributesFromTemplate(pTemplate, ulCount, &attributes);

            if (CKR_OK != rv)
            {
                /* If the search template has unsupported attributes, the findObjects operation
                   is still successfully initialized, but will not match any objects.*/
                rv = CKR_OK;

                sessionParameters.activeOperation.reset(ActiveOp::FindObjects_None);
                gSessionCache->add(hSession, sessionParameters);
                break;
            }
        }

        rv = gSessionCache->findObjectsInit(hSession, attributes, findAllHandles);
        if (CKR_OK != rv)
        {
            break;
        }
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV findObjects(CK_SESSION_HANDLE    hSession,
                  CK_OBJECT_HANDLE_PTR phObject,
                  CK_ULONG             ulMaxObjectCount,
                  CK_ULONG_PTR         pulObjectCount)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        if (!phObject || !pulObjectCount)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid() || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
        if (sessionParameters.activeOperation.test(ActiveOp::FindObjects_None))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        *pulObjectCount = gSessionCache->findObjects(hSession, phObject, ulMaxObjectCount);

        rv = CKR_OK;
    } while(false);

    return rv;
}

//---------------------------------------------------------------------------------------------
CK_RV findObjectsFinal(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_FUNCTION_FAILED;

    do
    {
        if (!isInitialized() || !gSessionCache)
        {
            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
            break;
        }

        const CK_SLOT_ID slotID = gSessionCache->getSlotId(hSession);

        P11Crypto::Slot slot(slotID);
        if (!slot.valid() || !gSessionCache->find(hSession))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        P11Crypto::Token* token = slot.getToken();
        if (!token)
        {
            rv = CKR_TOKEN_NOT_PRESENT;
            break;
        }

        SessionParameters sessionParameters = gSessionCache->getSessionParameters(hSession);
        if (sessionParameters.activeOperation.test(ActiveOp::FindObjects_None))
        {
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        gSessionCache->findObjectsFinal(hSession);

        rv = CKR_OK;
    } while(false);

    return rv;
}