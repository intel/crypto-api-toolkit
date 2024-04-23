/*
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
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

/*
 * Copyright (c) 2010 SURFnet bv
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SoftHSM.cpp

 The implementation of the SoftHSM's main class
 *****************************************************************************/

#include "config.h"
#include "access.h"
#ifndef SGXHSM
#include "SimpleConfigLoader.h"
#else
#include "Configuration.h"
#endif
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"
#include "CryptoFactory.h"
#include "AsymmetricAlgorithm.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"
#include "DerUtil.h"
#if 0 // Unsupported by Crypto API Toolkit
#include "DESKey.h"
#endif // Unsupported by Crypto API Toolkit
#include "RNG.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#if 0 // Unsupported by Crypto API Toolkit
#include "DSAParameters.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"
#endif // Unsupported by Crypto API Toolkit
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "ECParameters.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#if 0 // Unsupported by Crypto API Toolkit
#include "DHParameters.h"
#include "DHPublicKey.h"
#include "DHPrivateKey.h"
#include "GOSTPublicKey.h"
#include "GOSTPrivateKey.h"
#endif // Unsupported by Crypto API Toolkit
#include "cryptoki.h"
#include "SoftHSM.h"
#include "osmutex.h"
#include "SessionManager.h"
#include "OSAttributes.h"
#include "SessionObjectStore.h"
#include "HandleManager.h"
#include "P11Objects.h"
#include "odd.h"

#include "OSSLCryptoFactory.h"

#include "EnclaveSecureUtils.h"

#include "p11Enclave_t.h"

#include <sgx_error.h>

#include <algorithm>
#include <mbusafecrt.h>
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>

#ifdef ENABLE_MITIGATION
extern "C" void __builtin_ia32_lfence(void);
#endif

// Initialise the one-and-only instance

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
std::unique_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(nullptr);
std::unique_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(nullptr);
std::unique_ptr<SoftHSM> SoftHSM::instance(nullptr);

static CK_RV newP11Object(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType, CK_CERTIFICATE_TYPE certType, P11Object **p11object)
{
	switch(objClass) {
		case CKO_DATA:
			*p11object = new P11DataObj();
			break;
		case CKO_CERTIFICATE:
			if (certType == CKC_X_509)
				*p11object = new P11X509CertificateObj();
			else if (certType == CKC_OPENPGP)
				*p11object = new P11OpenPGPPublicKeyObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_PUBLIC_KEY:
			if (keyType == CKK_RSA)
				*p11object = new P11RSAPublicKeyObj();
#if 0 // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_DSA)
				*p11object = new P11DSAPublicKeyObj();
#endif // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_EC)
				*p11object = new P11ECPublicKeyObj();
#if 0 // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_DH)
				*p11object = new P11DHPublicKeyObj();
			else if (keyType == CKK_GOSTR3410)
				*p11object = new P11GOSTPublicKeyObj();
#endif // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_EC_EDWARDS)
				*p11object = new P11EDPublicKeyObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_PRIVATE_KEY:
			// we need to know the type too
			if (keyType == CKK_RSA)
				*p11object = new P11RSAPrivateKeyObj();
#if 0 // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_DSA)
				*p11object = new P11DSAPrivateKeyObj();
#endif // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_EC)
				*p11object = new P11ECPrivateKeyObj();
#if 0 // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_DH)
				*p11object = new P11DHPrivateKeyObj();
			else if (keyType == CKK_GOSTR3410)
				*p11object = new P11GOSTPrivateKeyObj();
#endif // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_EC_EDWARDS)
				*p11object = new P11EDPrivateKeyObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_SECRET_KEY:
			if (
#if 0 // Unsupported by Crypto API Toolkit
				(keyType == CKK_GENERIC_SECRET) ||
			    (keyType == CKK_MD5_HMAC) ||
			    (keyType == CKK_SHA_1_HMAC) ||
			    (keyType == CKK_SHA224_HMAC) ||
#endif // Unsupported by Crypto API Toolkit
			    (keyType == CKK_SHA256_HMAC) ||
			    (keyType == CKK_SHA384_HMAC) ||
			    (keyType == CKK_SHA512_HMAC))
			{
				P11GenericSecretKeyObj* key = new P11GenericSecretKeyObj();
				*p11object = key;
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_AES)
			{
				*p11object = new P11AESSecretKeyObj();
			}
#if 0 // Unsupported by Crypto API Toolkit
			else if ((keyType == CKK_DES) ||
				 (keyType == CKK_DES2) ||
				 (keyType == CKK_DES3))
			{
				P11DESSecretKeyObj* key = new P11DESSecretKeyObj();
				*p11object = key;
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_GOST28147)
			{
				*p11object = new P11GOSTSecretKeyObj();
			}
#endif // Unsupported by Crypto API Toolkit
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_DOMAIN_PARAMETERS:
#if 0 // Unsupported by Crypto API Toolkit
			if (keyType == CKK_DSA)
				*p11object = new P11DSADomainObj();
			else if (keyType == CKK_DH)
				*p11object = new P11DHDomainObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
#endif // Unsupported by Crypto API Toolkit
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID; // invalid value for a valid argument
	}
	return CKR_OK;
}

static CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR pTemplate,
				      CK_ULONG ulCount,
				      CK_OBJECT_CLASS &objClass,
				      CK_KEY_TYPE &keyType,
				      CK_CERTIFICATE_TYPE &certType,
				      CK_BBOOL &isOnToken,
				      CK_BBOOL &isPrivate,
				      bool bImplicit)
{
	bool bHasClass = false;
	bool bHasKeyType = false;
	bool bHasCertType = false;
	bool bHasPrivate = false;

	// Extract object information
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
				if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS))
				{
					objClass = *(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue;
					bHasClass = true;
				}
				break;
			case CKA_KEY_TYPE:
				if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE))
				{
					keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
					bHasKeyType = true;
				}
				break;
			case CKA_CERTIFICATE_TYPE:
				if (pTemplate[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE))
				{
					certType = *(CK_CERTIFICATE_TYPE*)pTemplate[i].pValue;
					bHasCertType = true;
				}
				break;
			case CKA_TOKEN:
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
				}
				break;
			case CKA_PRIVATE:
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
					bHasPrivate = true;
				}
				break;
			default:
				break;
		}
	}

	if (bImplicit)
	{
		return CKR_OK;
	}

	if (!bHasClass)
	{
		return CKR_TEMPLATE_INCOMPLETE;
	}

	bool bKeyTypeRequired = (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY);
	if (bKeyTypeRequired && !bHasKeyType)
	{
		 return CKR_TEMPLATE_INCOMPLETE;
	}

	if (objClass == CKO_CERTIFICATE)
	{
		if (!bHasCertType)
		{
			return CKR_TEMPLATE_INCOMPLETE;
		}
		if (!bHasPrivate)
		{
			// Change default value for certificates
			isPrivate = CK_FALSE;
		}
	}

	if (objClass == CKO_PUBLIC_KEY && !bHasPrivate)
	{
		// Change default value for public keys
		isPrivate = CK_FALSE;
	}

	return CKR_OK;
}

static CK_RV newP11Object(OSObject *object, P11Object **p11object)
{
	CK_OBJECT_CLASS objClass = object->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	if (object->attributeExists(CKA_KEY_TYPE))
		keyType = object->getUnsignedLongValue(CKA_KEY_TYPE, CKK_RSA);
	if (object->attributeExists(CKA_CERTIFICATE_TYPE))
		certType = object->getUnsignedLongValue(CKA_CERTIFICATE_TYPE, CKC_X_509);
	CK_RV rv = newP11Object(objClass,keyType,certType,p11object);
	if (rv != CKR_OK)
		return rv;
	if (!(*p11object)->init(object))
		return CKR_GENERAL_ERROR; // something went wrong that shouldn't have.
	return CKR_OK;
}

#ifdef notyet
static CK_ATTRIBUTE bsAttribute(CK_ATTRIBUTE_TYPE type, const ByteString &value)
{
	CK_ATTRIBUTE attr = {type, (CK_VOID_PTR)value.const_byte_str(), value.size() };
	return attr;
}
#endif

/*****************************************************************************
 Implementation of SoftHSM class specific functions
 *****************************************************************************/
static void resetMutexFactoryCallbacks()
{
	// Reset MutexFactory callbacks to our versions
	MutexFactory::i()->setCreateMutex(OSCreateMutex);
	MutexFactory::i()->setDestroyMutex(OSDestroyMutex);
	MutexFactory::i()->setLockMutex(OSLockMutex);
	MutexFactory::i()->setUnlockMutex(OSUnlockMutex);
}


// Return the one-and-only instance
SoftHSM* SoftHSM::i()
{
	if (!instance.get())
	{
		instance.reset(new SoftHSM());
	}

	return instance.get();
}

void SoftHSM::reset()
{
	if (instance.get())
		instance.reset();
}

// Constructor
SoftHSM::SoftHSM()
{
	isInitialised = false;
	isRemovable = false;
	sessionObjectStore = NULL;
	objectStore = NULL;
	slotManager = NULL;
	sessionManager = NULL;
	handleManager = NULL;
	resetMutexFactoryCallbacks();
}

// Destructor
SoftHSM::~SoftHSM()
{
	if (handleManager != NULL) delete handleManager;
	handleManager = NULL;
	if (sessionManager != NULL) delete sessionManager;
	sessionManager = NULL;
	if (slotManager != NULL) delete slotManager;
	slotManager = NULL;
	if (objectStore != NULL) delete objectStore;
	objectStore = NULL;
	if (sessionObjectStore != NULL) delete sessionObjectStore;
	sessionObjectStore = NULL;

    isInitialised = false;

	resetMutexFactoryCallbacks();
}

// A list with the supported mechanisms
std::map<std::string, CK_MECHANISM_TYPE> mechanisms_table;
std::list<CK_MECHANISM_TYPE> supportedMechanisms;
CK_ULONG nrSupportedMechanisms;

/*****************************************************************************
 Implementation of PKCS #11 functions
 *****************************************************************************/

// PKCS #11 initialisation function
CK_RV SoftHSM::C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_C_INITIALIZE_ARGS_PTR args;
    CK_C_INITIALIZE_ARGS l_args;

	// Check if PKCS#11 is already initialized
	if (isInitialised)
	{
		// ERROR_MSG("SoftHSM is already initialized");
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	// Do we have any arguments?
	if (pInitArgs != NULL_PTR)
	{
		if (!is_outside_enclave(pInitArgs, sizeof(CK_C_INITIALIZE_ARGS)))
		{
			return CKR_ARGUMENTS_BAD;
		}

        memcpy_s(&l_args, sizeof(CK_C_INITIALIZE_ARGS), pInitArgs, sizeof(CK_C_INITIALIZE_ARGS));

        args = &l_args;

		// Must be set to NULL_PTR in this version of PKCS#11
		if (args->pReserved != NULL_PTR)
		{
			// ERROR_MSG("pReserved must be set to NULL_PTR");
			return CKR_ARGUMENTS_BAD;
		}

		// SGXHSM does not support application provided mutex callbacks
		if (args->CreateMutex != NULL_PTR ||
			args->DestroyMutex != NULL_PTR ||
			args->LockMutex != NULL_PTR ||
			args->UnlockMutex != NULL_PTR)
		{
			return CKR_ARGUMENTS_BAD;
		}

		// Can we spawn our own threads?
		// if (args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
		// {
		//	// DEBUG_MSG("Cannot create threads if CKF_LIBRARY_CANT_CREATE_OS_THREADS is set");
		//	return CKR_NEED_TO_CREATE_THREADS;
		// }

		// Are we not supplied with mutex functions?
        // Can we use our own mutex functions?
        if (args->flags & CKF_OS_LOCKING_OK)
        {
            // Use our own mutex functions.
            resetMutexFactoryCallbacks();
            MutexFactory::i()->enable();
        }
        else
        {
            // The external application is not using threading
            MutexFactory::i()->disable();
        }
    }
	else
	{
		// No concurrent access by multiple threads
		MutexFactory::i()->disable();
	}

	// Initiate SecureMemoryRegistry
	if (SecureMemoryRegistry::i() == NULL)
	{
		// ERROR_MSG("Could not load the SecureMemoryRegistry");
		return CKR_GENERAL_ERROR;
	}

	// Build the CryptoFactory
	if (CryptoFactory::i() == NULL)
	{
		// ERROR_MSG("Could not load the CryptoFactory");
		return CKR_GENERAL_ERROR;
	}

#ifdef WITH_FIPS
	// Check the FIPS status
	if (!CryptoFactory::i()->getFipsSelfTestStatus())
	{
		// ERROR_MSG("The FIPS self test failed");
		return CKR_FIPS_SELF_TEST_FAILED;
	}
#endif

#ifndef SGXHSM
	// (Re)load the configuration
	if (!Configuration::i()->reload(SimpleConfigLoader::i()))
	{
		// ERROR_MSG("Could not load the configuration");
		return CKR_GENERAL_ERROR;
	}
    //
	// Configure the log level
	if (!setLogLevel(Configuration::i()->getString("log.level", DEFAULT_LOG_LEVEL)))
	{
		// ERROR_MSG("Could not set the log level");
		return CKR_GENERAL_ERROR;
	}
#endif
	
    // Configure object store storage backend used by all tokens.
#ifndef SGXHSM
	if (!ObjectStoreToken::selectBackend(Configuration::i()->getString("objectstore.backend", DEFAULT_OBJECTSTORE_BACKEND)))
#else
    if (!ObjectStoreToken::selectBackend(Configuration::i()->getString("objectstore.backend", "file")))
#endif
	{
		// ERROR_MSG("Could not set the storage backend");
		return CKR_GENERAL_ERROR;
	}
	
	sessionObjectStore = new SessionObjectStore();

	// Load the object store
	objectStore = new ObjectStore(Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR));
	if (!objectStore->isValid())
	{
		// WARNING_MSG("Could not load the object store");
		delete objectStore;
		objectStore = NULL;
		delete sessionObjectStore;
		sessionObjectStore = NULL;
		return CKR_GENERAL_ERROR;
	}

	// Load the enabled list of algorithms
	prepareSupportedMechanisms(mechanisms_table);

	isRemovable = Configuration::i()->getBool("slots.removable", false);

	// Load the slot manager
	slotManager = new SlotManager(objectStore);

    if (!slotManager->isValid())
    {
        delete objectStore;
        objectStore = NULL;
        delete sessionObjectStore;
        sessionObjectStore = NULL;
        delete slotManager;
        slotManager = NULL;

        return CKR_GENERAL_ERROR;
    }

	// Load the session manager
	sessionManager = new SessionManager();

	// Load the handle manager
	handleManager = new HandleManager();

	// Set the state to initialised
	isInitialised = true;

	return CKR_OK;
}

// PKCS #11 finalisation function
CK_RV SoftHSM::C_Finalize(CK_VOID_PTR pReserved)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Must be set to NULL_PTR in this version of PKCS#11
	if (pReserved != NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (handleManager != NULL) delete handleManager;
	handleManager = NULL;
	if (sessionManager != NULL) delete sessionManager;
	sessionManager = NULL;
	if (slotManager != NULL) delete slotManager;
	slotManager = NULL;
	if (objectStore != NULL) delete objectStore;
	objectStore = NULL;
	if (sessionObjectStore != NULL) delete sessionObjectStore;
	sessionObjectStore = NULL;
	CryptoFactory::reset();
	SecureMemoryRegistry::reset();

	isInitialised = false;
    supportedMechanisms.clear();

	SoftHSM::reset();
	return CKR_OK;
}

// Return information about the PKCS #11 module
CK_RV SoftHSM::C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pInfo, sizeof(CK_INFO)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_INFO info{};

	auto l_pInfo = &info;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	l_pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	l_pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	memset(l_pInfo->manufacturerID, ' ', 32);
    memcpy_s(l_pInfo->manufacturerID, sizeof(l_pInfo->manufacturerID), "SGXHSM", strlen("SGXHSM"));
	l_pInfo->flags = 0;
	memset(l_pInfo->libraryDescription, ' ', 32);
#ifdef WITH_FIPS
    memcpy_s(l_pInfo->libraryDescription, sizeof(l_pInfo->libraryDescription), "Implementation of PKCS11+FIPS", strlen("Implementation of PKCS11+FIPS"));
#else
    memcpy_s(l_pInfo->libraryDescription, sizeof(l_pInfo->libraryDescription), "Implementation of PKCS11", strlen("Implementation of PKCS11"));
#endif
	l_pInfo->libraryVersion.major = 2; //VERSION_MAJOR;
	l_pInfo->libraryVersion.minor = 5; //VERSION_MINOR;

    memcpy_s(pInfo, sizeof(CK_INFO), &info, sizeof(CK_INFO));

	return CKR_OK;
}

// Return a list of available slots
CK_RV SoftHSM::C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!validate_user_check_ptr(pulCount, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    auto ulCount = *pulCount;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

    if (pSlotList && ulCount)
    {
        if (ulCount > MAX_SLOTS)
        {
            return CKR_ARGUMENTS_BAD;
        }

        if (!validate_user_check_ptr(pSlotList, sizeof(CK_SLOT_ID) * (ulCount)))
        {
            return CKR_DEVICE_MEMORY;
        }
    }

    auto rv = slotManager->getSlotList(objectStore, tokenPresent, pSlotList, &ulCount);

    *pulCount = ulCount;

    return rv;
}

// Return information about a slot
CK_RV SoftHSM::C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    CK_SLOT_INFO info{};

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

    auto l_pInfo = &info;

	auto rv = slot->getSlotInfo(l_pInfo);
	if (rv != CKR_OK) {
		return rv;
	}

	if (isRemovable) {
		l_pInfo->flags |= CKF_REMOVABLE_DEVICE;
	}

    if (!validate_user_check_ptr(pInfo, sizeof(CK_SLOT_INFO)))
    {
        return CKR_DEVICE_MEMORY;
    }

    memcpy_s(pInfo, sizeof(CK_SLOT_INFO), &info, sizeof(CK_SLOT_INFO));

	return CKR_OK;
}

// Return information about a token in a slot
CK_RV SoftHSM::C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    CK_TOKEN_INFO info;
    auto l_pInfo = &info;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	Token* token = slot->getToken();
	if (token == NULL)
	{
		return CKR_TOKEN_NOT_PRESENT;
	}

	auto rv = token->getTokenInfo(l_pInfo);

    if (CKR_OK == rv)
    {
        if (!validate_user_check_ptr(pInfo, sizeof(CK_TOKEN_INFO)))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(pInfo, sizeof(CK_TOKEN_INFO), &info, sizeof(CK_TOKEN_INFO));
    }

    return rv;
}

void SoftHSM::prepareSupportedMechanisms(std::map<std::string, CK_MECHANISM_TYPE> &t)
{
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
	t["CKM_MD5"]			= CKM_MD5;
#endif
	t["CKM_SHA_1"]			= CKM_SHA_1;
	t["CKM_SHA224"]			= CKM_SHA224;
#endif // Unsupported by Crypto API Toolkit
	t["CKM_SHA256"]			= CKM_SHA256;
	t["CKM_SHA384"]			= CKM_SHA384;
	t["CKM_SHA512"]			= CKM_SHA512;
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
	t["CKM_MD5_HMAC"]		= CKM_MD5_HMAC;
#endif
	t["CKM_SHA_1_HMAC"]		= CKM_SHA_1_HMAC;
	t["CKM_SHA224_HMAC"]		= CKM_SHA224_HMAC;
#endif // Unsupported by Crypto API Toolkit
	t["CKM_SHA256_HMAC"]		= CKM_SHA256_HMAC;
	t["CKM_SHA384_HMAC"]		= CKM_SHA384_HMAC;
	t["CKM_SHA512_HMAC"]		= CKM_SHA512_HMAC;
	t["CKM_RSA_PKCS_KEY_PAIR_GEN"]	= CKM_RSA_PKCS_KEY_PAIR_GEN;
	t["CKM_RSA_PKCS"]		= CKM_RSA_PKCS;
	t["CKM_RSA_X_509"]		= CKM_RSA_X_509;
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
	t["CKM_MD5_RSA_PKCS"]		= CKM_MD5_RSA_PKCS;
#endif
#endif // Unsupported by Crypto API Toolkit
	t["CKM_SHA1_RSA_PKCS"]		= CKM_SHA1_RSA_PKCS;
	t["CKM_RSA_PKCS_OAEP"]		= CKM_RSA_PKCS_OAEP;
	t["CKM_SHA224_RSA_PKCS"]	= CKM_SHA224_RSA_PKCS;
	t["CKM_SHA256_RSA_PKCS"]	= CKM_SHA256_RSA_PKCS;
	t["CKM_SHA384_RSA_PKCS"]	= CKM_SHA384_RSA_PKCS;
	t["CKM_SHA512_RSA_PKCS"]	= CKM_SHA512_RSA_PKCS;
#ifdef WITH_RAW_PSS
	t["CKM_RSA_PKCS_PSS"]		= CKM_RSA_PKCS_PSS;
#endif
	t["CKM_SHA1_RSA_PKCS_PSS"]	= CKM_SHA1_RSA_PKCS_PSS;
	t["CKM_SHA224_RSA_PKCS_PSS"]	= CKM_SHA224_RSA_PKCS_PSS;
	t["CKM_SHA256_RSA_PKCS_PSS"]	= CKM_SHA256_RSA_PKCS_PSS;
	t["CKM_SHA384_RSA_PKCS_PSS"]	= CKM_SHA384_RSA_PKCS_PSS;
	t["CKM_SHA512_RSA_PKCS_PSS"]	= CKM_SHA512_RSA_PKCS_PSS;
#if 0 // Unsupported by Crypto API Toolkit
	t["CKM_GENERIC_SECRET_KEY_GEN"]	= CKM_GENERIC_SECRET_KEY_GEN;
#ifndef WITH_FIPS
	t["CKM_DES_KEY_GEN"]		= CKM_DES_KEY_GEN;
#endif
	t["CKM_DES2_KEY_GEN"]		= CKM_DES2_KEY_GEN;
	t["CKM_DES3_KEY_GEN"]		= CKM_DES3_KEY_GEN;
#ifndef WITH_FIPS
	t["CKM_DES_ECB"]		= CKM_DES_ECB;
	t["CKM_DES_CBC"]		= CKM_DES_CBC;
	t["CKM_DES_CBC_PAD"]		= CKM_DES_CBC_PAD;
	t["CKM_DES_ECB_ENCRYPT_DATA"]	= CKM_DES_ECB_ENCRYPT_DATA;
	t["CKM_DES_CBC_ENCRYPT_DATA"]	= CKM_DES_CBC_ENCRYPT_DATA;
#endif
	t["CKM_DES3_ECB"]		= CKM_DES3_ECB;
	t["CKM_DES3_CBC"]		= CKM_DES3_CBC;
	t["CKM_DES3_CBC_PAD"]		= CKM_DES3_CBC_PAD;
	t["CKM_DES3_ECB_ENCRYPT_DATA"]	= CKM_DES3_ECB_ENCRYPT_DATA;
	t["CKM_DES3_CBC_ENCRYPT_DATA"]	= CKM_DES3_CBC_ENCRYPT_DATA;
	t["CKM_DES3_CMAC"]		= CKM_DES3_CMAC;
#endif // Unsupported by Crypto API Toolkit
	t["CKM_AES_KEY_GEN"]		= CKM_AES_KEY_GEN;
#if 0 // Unsupported by Crypto API Toolkit
	t["CKM_AES_ECB"]		= CKM_AES_ECB;
#endif // Unsupported by Crypto API Toolkit
	t["CKM_AES_CBC"]		= CKM_AES_CBC;
	t["CKM_AES_CBC_PAD"]		= CKM_AES_CBC_PAD;
	t["CKM_AES_CTR"]		= CKM_AES_CTR;
#ifdef WITH_AES_GCM
	t["CKM_AES_GCM"]		= CKM_AES_GCM;
#endif
	t["CKM_AES_KEY_WRAP"]		= CKM_AES_KEY_WRAP;
#ifdef HAVE_AES_KEY_WRAP_PAD
	t["CKM_AES_KEY_WRAP_PAD"]	= CKM_AES_KEY_WRAP_PAD;
#endif
#if 0 // Unsupported by Crypto API Toolkit
	t["CKM_AES_ECB_ENCRYPT_DATA"]	= CKM_AES_ECB_ENCRYPT_DATA;
	t["CKM_AES_CBC_ENCRYPT_DATA"]	= CKM_AES_CBC_ENCRYPT_DATA;
	t["CKM_AES_CMAC"]		= CKM_AES_CMAC;
	t["CKM_DSA_PARAMETER_GEN"]	= CKM_DSA_PARAMETER_GEN;
	t["CKM_DSA_KEY_PAIR_GEN"]	= CKM_DSA_KEY_PAIR_GEN;
	t["CKM_DSA"]			= CKM_DSA;
	t["CKM_DSA_SHA1"]		= CKM_DSA_SHA1;
	t["CKM_DSA_SHA224"]		= CKM_DSA_SHA224;
	t["CKM_DSA_SHA256"]		= CKM_DSA_SHA256;
	t["CKM_DSA_SHA384"]		= CKM_DSA_SHA384;
	t["CKM_DSA_SHA512"]		= CKM_DSA_SHA512;
	t["CKM_DH_PKCS_KEY_PAIR_GEN"]	= CKM_DH_PKCS_KEY_PAIR_GEN;
	t["CKM_DH_PKCS_PARAMETER_GEN"]	= CKM_DH_PKCS_PARAMETER_GEN;
	t["CKM_DH_PKCS_DERIVE"]		= CKM_DH_PKCS_DERIVE;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
	t["CKM_EC_KEY_PAIR_GEN"]	= CKM_EC_KEY_PAIR_GEN;
	t["CKM_ECDSA"]			= CKM_ECDSA;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
#if 0 // Unsupported by Crypto API Toolkit
	t["CKM_ECDH1_DERIVE"]		= CKM_ECDH1_DERIVE;
#endif // Unsupported by Crypto API Toolkit
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
	t["CKM_GOSTR3411"]		= CKM_GOSTR3411;
	t["CKM_GOSTR3411_HMAC"]		= CKM_GOSTR3411_HMAC;
	t["CKM_GOSTR3410_KEY_PAIR_GEN"]	= CKM_GOSTR3410_KEY_PAIR_GEN;
	t["CKM_GOSTR3410"]		= CKM_GOSTR3410;
	t["CKM_GOSTR3410_WITH_GOSTR3411"] = CKM_GOSTR3410_WITH_GOSTR3411;
#endif
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_EDDSA
	t["CKM_EC_EDWARDS_KEY_PAIR_GEN"] = CKM_EC_EDWARDS_KEY_PAIR_GEN;
	t["CKM_EDDSA"]			= CKM_EDDSA;
#endif
    t["CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY"] = CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY;

    supportedMechanisms.clear();
	for (auto it = t.begin(); it != t.end(); ++it)
	{
		supportedMechanisms.push_back(it->second);
	}

	/* Check configuration for supported algorithms */
	std::string mechs = Configuration::i()->getString("token.mechanisms", "ALL");
	if (mechs != "ALL")
	{
		bool negative = (mechs[0] == '-');
		if (!negative)
		{
			/* For positive list, we remove everything */
			supportedMechanisms.clear();
		}
		size_t pos = 0, prev = 0;
		std::string token;
		do
		{
			pos = mechs.find(",", prev);
			if (pos == std::string::npos) pos = mechs.length();
			token = mechs.substr(prev, pos - prev);
			CK_MECHANISM_TYPE mechanism;
			try
			{
				mechanism = t.at(token);
				if (!negative)
					supportedMechanisms.push_back(mechanism);
				else
					supportedMechanisms.remove(mechanism);
			}
            catch (...)
            {
                // WARNING_MSG("Unknown mechanism provided: %s", token.c_str());
            }
			prev = pos + 1;
		}
		while (pos < mechs.length() && prev < mechs.length());
	}

	nrSupportedMechanisms = supportedMechanisms.size();
}

// Return the list of supported mechanisms for a given slot
CK_RV SoftHSM::C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pulCount, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    auto ulCount = *pulCount;

    if (pMechanismList && ulCount)
    {
        if (ulCount > MAX_MECHANISM_COUNT)
        {
            return CKR_ARGUMENTS_BAD;
        }

        if (!validate_user_check_ptr(pMechanismList, sizeof(CK_MECHANISM_TYPE) * ulCount))
        {
            return CKR_DEVICE_MEMORY;
        }
    }

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	if (pMechanismList == NULL_PTR)
	{
		*pulCount = nrSupportedMechanisms;

		return CKR_OK;
	}

	if (ulCount < nrSupportedMechanisms)
	{
		*pulCount = nrSupportedMechanisms;

		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = nrSupportedMechanisms;

	int i = 0;
	auto it = supportedMechanisms.cbegin();
	for (; it != supportedMechanisms.cend(); it++, i++)
	{
		pMechanismList[i] = *it;
	}

	return CKR_OK;
}

// Return more information about a mechanism for a given slot
CK_RV SoftHSM::C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    CK_MECHANISM_INFO info{};
    auto l_pInfo = &info;

	unsigned long rsaMinSize, rsaMaxSize;
#if 0 // Unsupported by Crypto API Toolkit
	unsigned long dsaMinSize, dsaMaxSize;
	unsigned long dhMinSize, dhMaxSize;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
	unsigned long ecdsaMinSize, ecdsaMaxSize;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
#if 0 // Unsupported by Crypto API Toolkit
	unsigned long ecdhMinSize = 0, ecdhMaxSize = 0;
#endif // Unsupported by Crypto API Toolkit
	unsigned long eddsaMinSize = 0, eddsaMaxSize = 0;
#endif

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa != NULL)
	{
		rsaMinSize = rsa->getMinKeySize();
		rsaMaxSize = rsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

#if 0 // Unsupported by Crypto API Toolkit

	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);
	if (dsa != NULL)
	{
		dsaMinSize = dsa->getMinKeySize();
		// Limitation in PKCS#11
		if (dsaMinSize < 512)
		{
			dsaMinSize = 512;
		}

		dsaMaxSize = dsa->getMaxKeySize();
		// Limitation in PKCS#11
		if (dsaMaxSize > 1024)
		{
			dsaMaxSize = 1024;
		}
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH);
	if (dh != NULL)
	{
		dhMinSize = dh->getMinKeySize();
		dhMaxSize = dh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
#endif // Unsupported by Crypto API Toolkit

#ifdef WITH_ECC
	AsymmetricAlgorithm* ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecdsa != NULL)
	{
		ecdsaMinSize = ecdsa->getMinKeySize();
		ecdsaMaxSize = ecdsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);

#if 0 // Unsupported by Crypto API Toolkit
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh != NULL)
	{
		ecdhMinSize = ecdh->getMinKeySize();
		ecdhMaxSize = ecdh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
#endif // Unsupported by Crypto API Toolkit
#endif

#ifdef WITH_EDDSA
	AsymmetricAlgorithm* eddsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (eddsa != NULL)
	{
		eddsaMinSize = eddsa->getMinKeySize();
		eddsaMaxSize = eddsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
#endif
	switch (type)
	{
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5:
#endif
		case CKM_SHA_1:
		case CKM_SHA224:
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_DIGEST;
			break;
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5_HMAC:
			l_pInfo->ulMinKeySize = 16;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
		case CKM_SHA_1_HMAC:
			l_pInfo->ulMinKeySize = 20;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA224_HMAC:
			l_pInfo->ulMinKeySize = 28;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA256_HMAC:
			l_pInfo->ulMinKeySize = 32;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA384_HMAC:
			l_pInfo->ulMinKeySize = 48;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA512_HMAC:
			l_pInfo->ulMinKeySize = 64;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			l_pInfo->ulMinKeySize = rsaMinSize;
			l_pInfo->ulMaxKeySize = rsaMaxSize;
			l_pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_RSA_PKCS:
			l_pInfo->ulMinKeySize = rsaMinSize;
			l_pInfo->ulMaxKeySize = rsaMaxSize;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
			break;
		case CKM_RSA_X_509:
			l_pInfo->ulMinKeySize = rsaMinSize;
			l_pInfo->ulMaxKeySize = rsaMaxSize;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT;
			break;
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
#endif
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			l_pInfo->ulMinKeySize = rsaMinSize;
			l_pInfo->ulMaxKeySize = rsaMaxSize;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_OAEP:
			l_pInfo->ulMinKeySize = rsaMinSize;
			l_pInfo->ulMaxKeySize = rsaMaxSize;
			l_pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_GENERIC_SECRET_KEY_GEN:
			l_pInfo->ulMinKeySize = 1;
			l_pInfo->ulMaxKeySize = 0x80000000;
			l_pInfo->flags = CKF_GENERATE;
			break;
#ifndef WITH_FIPS
		case CKM_DES_KEY_GEN:
#endif
		case CKM_DES2_KEY_GEN:
		case CKM_DES3_KEY_GEN:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_GENERATE;
			break;
#ifndef WITH_FIPS
		case CKM_DES_ECB:
		case CKM_DES_CBC:
		case CKM_DES_CBC_PAD:
#endif
		case CKM_DES3_ECB:
		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_DES3_CMAC:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_AES_KEY_GEN:
			l_pInfo->ulMinKeySize = 16;
			l_pInfo->ulMaxKeySize = 32;
			l_pInfo->flags = CKF_GENERATE;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_AES_ECB:
#endif // Unsupported by Crypto API Toolkit
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
#ifdef WITH_AES_GCM
		case CKM_AES_GCM:
#endif
			l_pInfo->ulMinKeySize = 16;
			l_pInfo->ulMaxKeySize = 32;
			l_pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
			break;
		case CKM_AES_KEY_WRAP:
			l_pInfo->ulMinKeySize = 16;
			l_pInfo->ulMaxKeySize = 0x80000000;
			l_pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			l_pInfo->ulMinKeySize = 1;
			l_pInfo->ulMaxKeySize = 0x80000000;
			l_pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_DES_ECB_ENCRYPT_DATA:
		case CKM_DES_CBC_ENCRYPT_DATA:
#endif
		case CKM_DES3_ECB_ENCRYPT_DATA:
		case CKM_DES3_CBC_ENCRYPT_DATA:
		case CKM_AES_ECB_ENCRYPT_DATA:
#endif // Unsupported by Crypto API Toolkit
		case CKM_AES_CBC_ENCRYPT_DATA:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_DERIVE;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_AES_CMAC:
			l_pInfo->ulMinKeySize = 16;
			l_pInfo->ulMaxKeySize = 32;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DSA_PARAMETER_GEN:
			l_pInfo->ulMinKeySize = dsaMinSize;
			l_pInfo->ulMaxKeySize = dsaMaxSize;
			l_pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			l_pInfo->ulMinKeySize = dsaMinSize;
			l_pInfo->ulMaxKeySize = dsaMaxSize;
			l_pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DSA:
		case CKM_DSA_SHA1:
		case CKM_DSA_SHA224:
		case CKM_DSA_SHA256:
		case CKM_DSA_SHA384:
		case CKM_DSA_SHA512:
			l_pInfo->ulMinKeySize = dsaMinSize;
			l_pInfo->ulMaxKeySize = dsaMaxSize;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			l_pInfo->ulMinKeySize = dhMinSize;
			l_pInfo->ulMaxKeySize = dhMaxSize;
			l_pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			l_pInfo->ulMinKeySize = dhMinSize;
			l_pInfo->ulMaxKeySize = dhMaxSize;
			l_pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DH_PKCS_DERIVE:
			l_pInfo->ulMinKeySize = dhMinSize;
			l_pInfo->ulMaxKeySize = dhMaxSize;
			l_pInfo->flags = CKF_DERIVE;
			break;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			l_pInfo->ulMinKeySize = ecdsaMinSize;
			l_pInfo->ulMaxKeySize = ecdsaMaxSize;
#define CKF_EC_COMMOM	(CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
			l_pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_EC_COMMOM;
			break;
		case CKM_ECDSA:
			l_pInfo->ulMinKeySize = ecdsaMinSize;
			l_pInfo->ulMaxKeySize = ecdsaMaxSize;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_EC_COMMOM;
			break;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_ECDH1_DERIVE:
			l_pInfo->ulMinKeySize = ecdhMinSize ? ecdhMinSize : eddsaMinSize;
			l_pInfo->ulMaxKeySize = ecdhMaxSize ? ecdhMaxSize : eddsaMaxSize;
			l_pInfo->flags = CKF_DERIVE;
			break;
#endif // Unsupported by Crypto API Toolkit
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3411:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_DIGEST;
			break;
		case CKM_GOSTR3411_HMAC:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 32;
			l_pInfo->ulMaxKeySize = 512;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_GOSTR3410:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			// Key size is not in use
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			l_pInfo->ulMinKeySize = eddsaMinSize;
			l_pInfo->ulMaxKeySize = eddsaMaxSize;
			l_pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_EDDSA:
			l_pInfo->ulMinKeySize = eddsaMinSize;
			l_pInfo->ulMaxKeySize = eddsaMaxSize;
			l_pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
		case CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY:
			l_pInfo->ulMinKeySize = 0;
			l_pInfo->ulMaxKeySize = 0;
			l_pInfo->flags = CKF_WRAP;
			break;
		default:
			// DEBUG_MSG("The selected mechanism is not supported");
			return CKR_MECHANISM_INVALID;
			break;
	}

#ifdef SGXHSM
    l_pInfo->flags |= CKF_HW;
#endif

	if (!validate_user_check_ptr(pInfo, sizeof(CK_MECHANISM_INFO)))
	{
		return CKR_DEVICE_MEMORY;
	}

    memcpy_s(pInfo, sizeof(CK_MECHANISM_INFO), l_pInfo, sizeof(CK_MECHANISM_INFO));

	return CKR_OK;
}

// Initialise the token in the specified slot
CK_RV SoftHSM::C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	// Check if any session is open with this token.
	if (sessionManager->haveSession(slotID))
	{
		return CKR_SESSION_EXISTS;
	}
    
	// Check the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
    if (pLabel == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_INCORRECT;

    // pLabel points to the 32-byte label of the token
	if (!validate_user_check_ptr(pPin, ulPinLen) ||
		!validate_user_check_ptr(pLabel, 32))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_UTF8CHAR label[32];
    memcpy_s(&label, 32, pLabel, 32);

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	ByteString soPIN(pPin, ulPinLen);

	return slot->initToken(soPIN, label);
}

// Initialise the user PIN
CK_RV SoftHSM::C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// The SO must be logged in
	if (session->getState() != CKS_RW_SO_FUNCTIONS) return CKR_USER_NOT_LOGGED_IN;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	if (!validate_user_check_ptr(pPin, ulPinLen))
	{
		return CKR_DEVICE_MEMORY;
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	ByteString userPIN(pPin, ulPinLen);

	return token->initUserPIN(userPIN);
}

// Change the PIN
CK_RV SoftHSM::C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the new PINs
	if (pOldPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pNewPin == NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (ulOldLen < MIN_PIN_LEN || ulOldLen > MAX_PIN_LEN) return CKR_PIN_INCORRECT;
	if (ulNewLen < MIN_PIN_LEN || ulNewLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	if (!validate_user_check_ptr(pOldPin, ulOldLen) ||
		!validate_user_check_ptr(pNewPin, ulNewLen))
	{
		return CKR_DEVICE_MEMORY;
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	ByteString oldPIN(pOldPin, ulOldLen);
	ByteString newPIN(pNewPin, ulNewLen);

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	switch (session->getState())
	{
		case CKS_RW_PUBLIC_SESSION:
		case CKS_RW_USER_FUNCTIONS:
			rv = token->setUserPIN(oldPIN, newPIN);
			break;
		case CKS_RW_SO_FUNCTIONS:
			rv = token->setSOPIN(oldPIN, newPIN);
			break;
		default:
			return CKR_SESSION_READ_ONLY;
	}

	return rv;
}

// Open a new session to the specified slot
CK_RV SoftHSM::C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (phSession == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Crypto API Toolkit for Intel(R) SGX does not support application and notify pointers
	if ((pApplication != NULL_PTR) || (notify != NULL_PTR))
	{
		return CKR_ARGUMENTS_BAD;
	}
	
	if ((flags & CKF_SERIAL_SESSION) == 0) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (!validate_user_check_ptr(phSession, sizeof(CK_ULONG)))
	{
		return CKR_DEVICE_MEMORY;
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	Slot* slot = slotManager->getSlot(slotID);

    CK_SESSION_HANDLE hSession;
	CK_RV rv = sessionManager->openSession(slot, flags, pApplication, notify, &hSession);
	if (rv != CKR_OK)
		return rv;

	// Get a pointer to the session object and store it in the handle manager.
	Session* session = sessionManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	*phSession = handleManager->addSession(slotID,session);

	return CKR_OK;
}

// Close the given session
CK_RV SoftHSM::C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Tell the handle manager the session has been closed.
	handleManager->sessionClosed(hSession);


	// Tell the session object store that the session has closed.
	sessionObjectStore->sessionClosed(hSession);

	// Tell the session manager the session has been closed.
	return sessionManager->closeSession(session->getHandle());
}

// Close all open sessions
CK_RV SoftHSM::C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the slot
	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL) return CKR_SLOT_ID_INVALID;

	// Get the token
	Token* token = slot->getToken();
	if (token == NULL) return CKR_TOKEN_NOT_PRESENT;

	// Tell the handle manager all sessions were closed for the given slotID.
	// The handle manager should then remove all session and object handles for this slot.
	handleManager->allSessionsClosed(slotID);

	// Tell the session object store that all sessions were closed for the given slotID.
	// The session object store should then remove all session objects for this slot.
	sessionObjectStore->allSessionsClosed(slotID);

	// Finally tell the session manager tho close all sessions for the given slot.
	// This will also trigger a logout on the associated token to occur.
	return sessionManager->closeAllSessions(slot);
}

// Retrieve information about the specified session
CK_RV SoftHSM::C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    CK_SESSION_INFO info;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo) return CKR_ARGUMENTS_BAD;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	auto rv = session->getInfo(&info);
    if (CKR_OK == rv)
    {
        if (!validate_user_check_ptr(pInfo, sizeof(CK_SESSION_INFO)))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(pInfo, sizeof(CK_SESSION_INFO), &info, sizeof(CK_SESSION_INFO));
    }
    
    return rv;

}

// Determine the state of a running operation in a session
CK_RV SoftHSM::C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pOperationState*/, CK_ULONG_PTR /*pulOperationStateLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Set the operation sate in a session
CK_RV SoftHSM::C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pOperationState*/, CK_ULONG /*ulOperationStateLen*/, CK_OBJECT_HANDLE /*hEncryptionKey*/, CK_OBJECT_HANDLE /*hAuthenticationKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Login on the token in the specified session
CK_RV SoftHSM::C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_INCORRECT;

	if (!validate_user_check_ptr(pPin, ulPinLen))
	{
		return CKR_DEVICE_MEMORY;
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	ByteString pin(pPin, ulPinLen);

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	switch (userType)
	{
		case CKU_SO:
			// There cannot exist a R/O session on this slot
			if (sessionManager->haveROSession(session->getSlot()->getSlotID())) return CKR_SESSION_READ_ONLY_EXISTS;

			// Login
			rv = token->loginSO(pin);
			break;
		case CKU_USER:
			// Login
			rv = token->loginUser(pin);
			break;
		case CKU_CONTEXT_SPECIFIC:
			// Check if re-authentication is required
			if (!session->getReAuthentication()) return CKR_OPERATION_NOT_INITIALIZED;

			// Re-authenticate
			rv = token->reAuthenticate(pin);
			if (rv == CKR_OK) session->setReAuthentication(false);
			break;
		default:
			return CKR_USER_TYPE_INVALID;
	}

	return rv;
}

// Log out of the token in the specified session
CK_RV SoftHSM::C_Logout(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Logout
	token->logout();

	// [PKCS#11 v2.40, C_Logout] When logout is successful...
	// a. Any of the application's handles to private objects become invalid.
	// b. Even if a user is later logged back into the token those handles remain invalid.
	// c. All private session objects from sessions belonging to the application are destroyed.

	// Have the handle manager remove all handles pointing to private objects for this slot.
	CK_SLOT_ID slotID = session->getSlot()->getSlotID();
	handleManager->tokenLoggedOut(slotID);
	sessionObjectStore->tokenLoggedOut(slotID);

	return CKR_OK;
}

// Create a new object on the token in the specified session using the given attribute template
CK_RV SoftHSM::C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE hObject;
    CK_OBJECT_HANDLE_PTR l_phObject = &hObject;

	if (!validate_user_check_ptr(phObject, sizeof(CK_OBJECT_HANDLE)))
	{
		return CKR_DEVICE_MEMORY;
	}

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (!validate_user_check_attribute_ptr(pTemplate, ulCount))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_ATTRIBUTE l_template[ulCount];
    memset_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> value(ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        if (l_template[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_template[i].ulValueLen;
        if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        value[i].resize(ulValueLen);
        memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
        l_template[i].pValue = value[i].data();
    }

    auto l_pTemplate = l_template;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef SGXHSM
    if (isRestrictedKeyAttributeValue(l_pTemplate, ulCount, false))
    {
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    CK_KEY_TYPE keyType = CKK_VENDOR_DEFINED;
    if (isSupportedKeyObject(l_pTemplate, ulCount, &keyType))
    {
        CK_ULONG keyLen = getKeyLength(l_pTemplate, ulCount);

        if (0 == keyLen)
        {
            return CKR_TEMPLATE_INCOMPLETE;
        }

        if (!isSupportedKeyLength(keyLen, keyType))
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        RNG* rng = CryptoFactory::i()->getRNG();
        if (!rng)
        {
            return CKR_FUNCTION_FAILED;
        }

        ByteString keyBytes;
        if (!rng->generateRandom(keyBytes, keyLen))
        {
            return CKR_FUNCTION_FAILED;
        }

        rv = this->CreateObject(hSession, l_pTemplate, ulCount, l_phObject, OBJECT_OP_CREATE_AES_KEY);
        if (CKR_OK == rv)
        {
            OSObject* osobject = (OSObject*)handleManager->getObject(hObject);
            if (!osobject || !osobject->isValid())
            {
                rv = CKR_FUNCTION_FAILED;
            }
            else if (osobject->startTransaction())
            {
                bool bOK = true;
                ByteString encryptedKeyBytes;

                // Get the session
                Session* session = (Session*)handleManager->getSession(hSession);
                if (session == NULL)
                {
                    rv = CKR_SESSION_HANDLE_INVALID;
                }
                else
                {
                    // Get the token
                    Token* token = session->getToken();
                    if (token == NULL)
                    {
                        rv = CKR_GENERAL_ERROR;
                    }
                    else
                    {
                        if (isPrivateObject(l_pTemplate, ulCount))
                        {
                            bOK = token->encrypt(keyBytes, encryptedKeyBytes);
                            if (bOK)
                            {
                                keyBytes = encryptedKeyBytes;
                            }
                        }

                        bOK = bOK && osobject->setAttribute(CKA_VALUE, keyBytes);

                        if (bOK)
                        {
                            bOK = osobject->commitTransaction();
                        }
                        else
                        {
                            osobject->abortTransaction();
                        }

                        if(!bOK)
                        {
                            rv = CKR_FUNCTION_FAILED;
                        }
                    }
                }
            }
            else
            {
                rv = CKR_FUNCTION_FAILED;
            }
        }
        if (CKR_OK != rv)
        {
            OSObject* object = (OSObject*)handleManager->getObject(hObject);
            if (object)
            {
                object->destroyObject();
            }
            handleManager->destroyObject(hObject);
            hObject = CK_INVALID_HANDLE;
        }

        *phObject = hObject;

        return rv;
    }
#endif
	rv = this->CreateObject(hSession,l_pTemplate,ulCount,l_phObject,OBJECT_OP_CREATE);

    *phObject = hObject;

    return rv;
}

// Create a copy of the object with the specified handle
CK_RV SoftHSM::C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    CK_OBJECT_HANDLE hNewObject;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phNewObject == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(phNewObject, sizeof(CK_OBJECT_HANDLE)))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (!validate_user_check_attribute_ptr(pTemplate, ulCount))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_ATTRIBUTE l_template[ulCount];
    memset_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> value(ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        if (l_template[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_template[i].ulValueLen;
        if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        value[i].resize(ulValueLen);
        memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
        l_template[i].pValue = value[i].data();
    }

    auto l_pTemplate = l_template;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	hNewObject = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL wasOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL wasPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), wasOnToken, wasPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if the object is copyable
	CK_BBOOL isCopyable = object->getBooleanValue(CKA_COPYABLE, true);
	if (!isCopyable) return CKR_ACTION_PROHIBITED;

	// Extract critical information from the template
	CK_BBOOL isOnToken = wasOnToken;
	CK_BBOOL isPrivate = wasPrivate;

	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		if ((l_pTemplate[i].type == CKA_TOKEN) && (l_pTemplate[i].ulValueLen == sizeof(CK_BBOOL)))
		{
			isOnToken = *(CK_BBOOL*)l_pTemplate[i].pValue;
			continue;
		}
		if ((l_pTemplate[i].type == CKA_PRIVATE) && (l_pTemplate[i].ulValueLen == sizeof(CK_BBOOL)))
		{
			isPrivate = *(CK_BBOOL*)l_pTemplate[i].pValue;
			continue;
		}
	}

	// Check privacy does not downgrade
	if (wasPrivate && !isPrivate) return CKR_TEMPLATE_INCONSISTENT;

	// Check write user credentials
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

    // Restrict changing CKA_TOKEN attribute while copying object
    if (isOnToken != wasOnToken)
    {
        return CKR_ACTION_PROHIBITED;
    }

	// Create the object in session or on the token
	OSObject *newobject = NULL_PTR;
	if (isOnToken)
	{
		newobject = (OSObject*) token->createObject();
	}
	else
	{
		newobject = sessionObjectStore->createObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE);
	}
	if (newobject == NULL) return CKR_GENERAL_ERROR;

	// Copy attributes from object class (CKA_CLASS=0 so the first)
	if (!newobject->startTransaction())
	{
		newobject->destroyObject();
		return CKR_FUNCTION_FAILED;
	}

	CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
	do
	{
		if (!object->attributeExists(attrType))
		{
			rv = CKR_FUNCTION_FAILED;
			break;
		}

		OSAttribute attr = object->getAttribute(attrType);

		// Upgrade privacy has to encrypt byte strings
		if (!wasPrivate && isPrivate &&
		    attr.isByteStringAttribute() &&
		    attr.getByteStringValue().size() != 0)
		{
			ByteString value;
			if (!token->encrypt(attr.getByteStringValue(), value) ||
			    !newobject->setAttribute(attrType, value))
			{
				rv = CKR_FUNCTION_FAILED;
				break;
			}
		}
		else
		{
			if (!newobject->setAttribute(attrType, attr))
			{
				rv = CKR_FUNCTION_FAILED;
				break;
			}
		}
		attrType = object->nextAttributeType(attrType);
	}
	while (attrType != CKA_CLASS);

	if (rv != CKR_OK)
	{
		newobject->abortTransaction();
	}
	else if (!newobject->commitTransaction())
	{
		rv = CKR_FUNCTION_FAILED;
	}

	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Get the new P11 object
	P11Object* newp11object = NULL;
	rv = newP11Object(newobject,&newp11object);
	if (rv != CKR_OK)
	{
        delete newp11object;
		newobject->destroyObject();
		return rv;
	}

	// Apply the template
	rv = newp11object->saveTemplate(token, isPrivate != CK_FALSE, l_pTemplate, ulCount, OBJECT_OP_COPY);
	delete newp11object;

	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Set handle
	if (isOnToken)
	{
		hNewObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, newobject);
	}
	else
	{
		hNewObject = handleManager->addSessionObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE, newobject);
	}

    *phNewObject = hNewObject;

	return CKR_OK;
}

// Destroy the specified object
CK_RV SoftHSM::C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

	// Check if the object is destroyable
	CK_BBOOL isDestroyable = object->getBooleanValue(CKA_DESTROYABLE, true);
	if (!isDestroyable) return CKR_ACTION_PROHIBITED;

#ifdef SGXHSM
        // Reset pairKeyId to 0 for RSA pair key handle
        CK_OBJECT_HANDLE rsaPairKeyHandle = getRSAPairKey(hSession, hObject);
        if (CK_INVALID_HANDLE != rsaPairKeyHandle)
        {
            OSObject* rsaPairOSobject = nullptr;
            CK_ULONG pairKeyIdVal = 0;

            rsaPairOSobject = (OSObject*)handleManager->getObject(rsaPairKeyHandle);
            if (rsaPairOSobject && rsaPairOSobject->isValid())
            {
               rsaPairOSobject->setAttribute(CKA_ASYMMETRIC_PAIR_ID, pairKeyIdVal);
            }
        }
#endif

	// Tell the handleManager to forget about the object.
	handleManager->destroyObject(hObject);

	// Destroy the object
	if (!object->destroyObject())
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

// Determine the size of the specified object
CK_RV SoftHSM::C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    auto l_pulSize = pulSize;
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (l_pulSize == NULL) return CKR_ARGUMENTS_BAD;

	if (!validate_user_check_ptr(l_pulSize, sizeof(CK_ULONG)))
	{
		return CKR_DEVICE_MEMORY;
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	*l_pulSize = CK_UNAVAILABLE_INFORMATION;

	return CKR_OK;
}

// Retrieve the specified attributes for the given object
CK_RV SoftHSM::C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL) return CKR_ARGUMENTS_BAD;

    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (!validate_user_check_attribute_ptr(pTemplate, ulCount))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_ATTRIBUTE l_template[ulCount];
    CK_ATTRIBUTE l_template1[ulCount];
    memset_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));
    memset_s(l_template1, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_template1, ulCount * sizeof(CK_ATTRIBUTE), l_template, ulCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> value(ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        auto ulValueLen = l_template[i].ulValueLen;
        if (l_template[i].pValue == nullptr)
        {
            continue;
        }

        if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        value[i].resize(ulValueLen);
        memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
        l_template[i].pValue = value[i].data();
    }

    auto l_pTemplate = l_template;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef SGXHSM
    if (isRestrictedKeyAttributeValue(l_pTemplate, ulCount, false, hObject))
    {
       return CKR_ATTRIBUTE_TYPE_INVALID;
    }
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the object handle.
    OSObject *object = (OSObject *)handleManager->getObject(hObject);
    if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		// CKR_USER_NOT_LOGGED_IN is not a valid return code for this function,
		// so we use CKR_GENERAL_ERROR.
		return CKR_GENERAL_ERROR;
	}

	// Wrap a P11Object around the OSObject so we can access the attributes in the
	// context of the object in which it is defined.
	P11Object* p11object = NULL;
	rv = newP11Object(object,&p11object);
	if (rv != CKR_OK)
    {
        delete p11object;
        return rv;
    }

	// Ask the P11Object to fill the template with attribute values.
	rv = p11object->loadTemplate(token, l_pTemplate, ulCount);
	delete p11object;

    if (CKR_OK == rv)
    {
        for (CK_ULONG i = 0; i < ulCount; i++)
        {
            auto ulValueLen = l_template[i].ulValueLen;
            pTemplate[i].ulValueLen = ulValueLen;

            if (!l_template1[i].pValue || !l_template[i].pValue)
            {
                continue;
            }

            pTemplate[i].type = l_template[i].type;
            memcpy_s(l_template1[i].pValue, ulValueLen, l_template[i].pValue, ulValueLen);
        }
    }

	return rv;
}

// Change or set the value of the specified attributes on the specified object
CK_RV SoftHSM::C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (!validate_user_check_attribute_ptr(pTemplate, ulCount))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_ATTRIBUTE l_template[ulCount];
    memset_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> value(ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        if (l_template[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_template[i].ulValueLen;
        if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        value[i].resize(ulValueLen);
        memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
        l_template[i].pValue = value[i].data();
    }

    auto l_pTemplate = l_template;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef SGXHSM
    if (isRestrictedKeyAttributeValue(l_pTemplate, ulCount, true, hObject))
    {
       return CKR_ATTRIBUTE_TYPE_INVALID;
    }
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the object handle.
	OSObject *object = (OSObject *)handleManager->getObject(hObject);
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

	// Check if the object is modifiable
	CK_BBOOL isModifiable = object->getBooleanValue(CKA_MODIFIABLE, true);
	if (!isModifiable) return CKR_ACTION_PROHIBITED;

	// Wrap a P11Object around the OSObject so we can access the attributes in the
	// context of the object in which it is defined.
	P11Object* p11object = NULL;
	rv = newP11Object(object,&p11object);
	if (rv != CKR_OK)
    {
        delete p11object;

        return rv;
    }

	// Ask the P11Object to save the template with attribute values.
	rv = p11object->saveTemplate(token, isPrivate != CK_FALSE, l_pTemplate,ulCount,OBJECT_OP_SET);
	delete p11object;
	return rv;
}

// Initialise object search in the specified session using the specified attribute template as search parameters
CK_RV SoftHSM::C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_ATTRIBUTE_PTR l_pTemplate = nullptr;
    CK_ATTRIBUTE l_template[ulCount];
    std::vector<std::vector<CK_BYTE>> value(ulCount);

    if (pTemplate || ulCount)
    {
        if (!validate_user_check_attribute_ptr(pTemplate, ulCount))
        {
            return CKR_DEVICE_MEMORY;
        }

        memset_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
        memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));

        for (CK_ULONG i = 0; i < ulCount; i++)
        {
            if (l_template[i].pValue == nullptr)
            {
                continue;
            }

            auto ulValueLen = l_template[i].ulValueLen;
            if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
            {
                return CKR_DEVICE_MEMORY;
            }

            value[i].resize(ulValueLen);
            memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
            l_template[i].pValue = value[i].data();

#ifdef SGXHSM
            if((l_template[i].type == CKA_ASYMMETRIC_PAIR_ID)) // Only from C_GenerateKeyPair or C_DestroyObject
            {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
#endif
        }

        l_pTemplate = l_template;

#ifdef ENABLE_MITIGATION
        __builtin_ia32_lfence();
#endif
    }

    return FindObjectsInit(hSession, l_pTemplate, ulCount);
}

// Continue the search for objects in the specified session
CK_RV SoftHSM::C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    std::vector<CK_OBJECT_HANDLE> hObject;
    CK_OBJECT_HANDLE_PTR l_phObject = nullptr;
    CK_ULONG ulObjectCount;

    auto l_pulObjectCount = &ulObjectCount;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulObjectCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pulObjectCount, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

	if (ulMaxObjectCount)
	{
        if (ulMaxObjectCount > MAX_OBJECT_COUNT)
        {
            return CKR_ARGUMENTS_BAD;
        }

		if (!validate_user_check_ptr(phObject, sizeof(CK_OBJECT_HANDLE) * ulMaxObjectCount))
		{
			return CKR_DEVICE_MEMORY;
		}

        hObject.resize(ulMaxObjectCount);
        l_phObject = &hObject[0];
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

    auto rv = FindObjects(hSession, l_phObject, ulMaxObjectCount, l_pulObjectCount);

    if ((CKR_OK == rv) && ulObjectCount && (ulObjectCount <= ulMaxObjectCount))
    {
        memcpy_s(phObject, ulObjectCount * sizeof(CK_OBJECT_HANDLE), &hObject[0], ulObjectCount * sizeof(CK_OBJECT_HANDLE));
    }

    *pulObjectCount = ulObjectCount;

    return rv;
}

// Finish searching for objects
CK_RV SoftHSM::C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_FIND) return CKR_OPERATION_NOT_INITIALIZED;

	session->resetOp();
	return CKR_OK;
}

// Encrypt*/Decrypt*() is for Symmetrical ciphers too
static bool isSymMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_DES_ECB:
		case CKM_DES_CBC:
		case CKM_DES_CBC_PAD:
		case CKM_DES3_ECB:
		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
		case CKM_AES_ECB:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
		case CKM_AES_GCM:
			return true;
		default:
			return false;
	}
}

// SymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::SymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for encryption
	if (!key->getBooleanValue(CKA_ENCRYPT, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	size_t counterBits = 0;
	ByteString aad;
	size_t tagBytes = 0;
	switch(pMechanism->mechanism) {
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_DES_ECB:
			algo = SymAlgo::DES;
			mode = SymMode::ECB;
			bb = 7;
			break;
		case CKM_DES_CBC:
			algo = SymAlgo::DES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_DES_CBC_PAD:
			algo = SymAlgo::DES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
#endif
		case CKM_DES3_ECB:
			algo = SymAlgo::DES3;
			mode = SymMode::ECB;
			bb = 7;
			break;
		case CKM_DES3_CBC:
			algo = SymAlgo::DES3;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_DES3_CBC_PAD:
			algo = SymAlgo::DES3;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_AES_ECB:
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_AES_CBC:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CBC_PAD:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CTR:
			algo = SymAlgo::AES;
			mode = SymMode::CTR;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
			{
				// DEBUG_MSG("CTR mode requires a counter block");
				return CKR_ARGUMENTS_BAD;
			}
			counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
			if (counterBits == 0 || counterBits > 128)
			{
				// DEBUG_MSG("Invalid ulCounterBits");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
            memcpy_s(&iv[0], 16, CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
			break;
#ifdef WITH_AES_GCM
		case CKM_AES_GCM:
			algo = SymAlgo::AES;
			mode = SymMode::GCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
			{
				// DEBUG_MSG("GCM mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
#ifdef SGXHSM
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen) && (nullptr == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv))
            {
                return CKR_ARGUMENTS_BAD;
            }
            if ((0 == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv))
            {
                return CKR_ARGUMENTS_BAD;
            }
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (nullptr == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD))
            {
                return CKR_ARGUMENTS_BAD;
            }
            if ((0 == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD))
            {
                return CKR_ARGUMENTS_BAD;
            }
#endif
			iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
#ifdef SGXHSM
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv))
            {
                memcpy_s(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
            }
#else
            memcpy_s(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
#endif
			aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
#ifdef SGXHSM
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD))
            {
                memcpy_s(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
            }
#else
            memcpy_s(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
#endif
			tagBytes = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
			if (tagBytes > 128 || tagBytes % 8 != 0)
			{
				// DEBUG_MSG("Invalid ulTagBits value");
				return CKR_ARGUMENTS_BAD;
			}
			tagBytes = tagBytes / 8;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize encryption
	if (!cipher->encryptInit(secretkey, mode, iv, padding, counterBits, aad, tagBytes))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::AsymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for encryption
    if (!key->getBooleanValue(CKA_ENCRYPT, false))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
        {
            rv = MechParamCheckRSAPKCSOAEP(pMechanism);
            if (rv != CKR_OK)
            {
                return rv;
            }

            CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
            if (params->hashAlg != CKM_SHA_1 ||
                params->mgf != CKG_MGF1_SHA1)
            {
                return CKR_ARGUMENTS_BAD;
            }

            mechanism = AsymMech::RSA_PKCS_OAEP;
            isRSA = true;
            break;
        }
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise encryption using the specified object and mechanism
CK_RV SoftHSM::C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (pMechanism == nullptr) return CKR_ARGUMENTS_BAD;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef SGXHSM
    // Check the key handle.
    OSObject *key = (OSObject*)handleManager->getObject(hKey);
    if (!key || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

    CK_BBOOL isUsedForWrapping = key->getBooleanValue(CKA_USED_FOR_WRAPPING, false);

    if(isUsedForWrapping)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
#endif

	if (isSymMechanism(l_pMechanism))
	{
		return SymEncryptInit(hSession, l_pMechanism, hKey);
	}
	else
	{
		return AsymEncryptInit(hSession, l_pMechanism, hKey);
	}
}

// SymAlgorithm version of C_Encrypt
static CK_RV SymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	CK_ULONG maxSize = ulDataLen + cipher->getTagBytes();
	if (cipher->isBlockCipher())
	{
		CK_ULONG remainder = ulDataLen % cipher->getBlockSize();
		if (cipher->getPaddingMode() == false && remainder != 0)
		{
			session->resetOp();
			return CKR_DATA_LEN_RANGE;
		}

		// Round up to block size
		if (remainder != 0)
		{
			maxSize = ulDataLen + cipher->getBlockSize() - remainder;
		}
		else if (cipher->getPaddingMode() == true)
		{
			maxSize = ulDataLen + cipher->getBlockSize();
		}
	}
	if (!cipher->checkMaximumBytes(ulDataLen))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < maxSize)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	encryptedData += encryptedFinal;
	encryptedData.resize(maxSize);

    memcpy_s(pEncryptedData, *pulEncryptedDataLen, encryptedData.byte_str(), encryptedData.size());
	*pulEncryptedDataLen = encryptedData.size();

	session->resetOp();
	return CKR_OK;
}

// AsymAlgorithm version of C_Encrypt
static CK_RV AsymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the encrypted data
	CK_ULONG size = publicKey->getOutputLength();

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < size)
	{
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;
	ByteString encryptedData;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);

	// Encrypt the data
	if (!asymCrypto->encrypt(publicKey,data,encryptedData,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (encryptedData.size() != size)
	{
		// ERROR_MSG("The size of the encrypted data differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
    memcpy_s(pEncryptedData, *pulEncryptedDataLen, encryptedData.byte_str(), size);
	*pulEncryptedDataLen = size;

	session->resetOp();
	return CKR_OK;
}

// Perform a single operation encryption operation in the specified session
CK_RV SoftHSM::C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulEncryptedDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pData, ulDataLen))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (!validate_user_check_ptr(pulEncryptedDataLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ULONG ulEncryptedDataLen = *pulEncryptedDataLen;
    auto l_pulEncryptedDataLen = &ulEncryptedDataLen;

	if (pEncryptedData && ulEncryptedDataLen)
	{
		if (!validate_user_check_ptr(pEncryptedData, ulEncryptedDataLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getSymmetricCryptoOp() != NULL)
		rv = SymEncrypt(session, pData, ulDataLen,
				  pEncryptedData, l_pulEncryptedDataLen);
	else
		rv = AsymEncrypt(session, pData, ulDataLen,
				   pEncryptedData, l_pulEncryptedDataLen);

    *pulEncryptedDataLen = ulEncryptedDataLen;

    return rv;
}

// SymAlgorithm version of C_EncryptUpdate
static CK_RV SymEncryptUpdate(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	size_t blockSize = cipher->getBlockSize();
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG maxSize = ulDataLen + remainingSize;
	if (cipher->isBlockCipher())
	{
		int nrOfBlocks = (ulDataLen + remainingSize) / blockSize;
		maxSize = nrOfBlocks * blockSize;
	}
	if (!cipher->checkMaximumBytes(ulDataLen))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	// Check data size
	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulEncryptedDataLen < maxSize)
	{
		// DEBUG_MSG("ulDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x",
		//	  ulDataLen, *pulEncryptedDataLen, blockSize, remainingSize, maxSize);
		*pulEncryptedDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	// DEBUG_MSG("ulDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x  encryptedData.size(): %#5x",
	//	  ulDataLen, *pulEncryptedDataLen, blockSize, remainingSize, maxSize, encryptedData.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulEncryptedDataLen < encryptedData.size())
	{
		session->resetOp();
		// ERROR_MSG("EncryptUpdate returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
		//	  *pulEncryptedDataLen, encryptedData.size());
		return CKR_GENERAL_ERROR;
	}

	if (encryptedData.size() > 0)
	{
            memcpy_s(pEncryptedData, *pulEncryptedDataLen, encryptedData.byte_str(), encryptedData.size());
	}
	*pulEncryptedDataLen = encryptedData.size();

	return CKR_OK;
}

// Feed data to the running encryption operation in a session
CK_RV SoftHSM::C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    CK_ULONG ulEncryptedDataLen;
    auto l_pulEncryptedDataLen = &ulEncryptedDataLen;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulEncryptedDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pData, ulDataLen))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (!validate_user_check_ptr(pulEncryptedDataLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    ulEncryptedDataLen = *pulEncryptedDataLen;

	if (pEncryptedData && ulEncryptedDataLen)
	{
		if (!validate_user_check_ptr(pEncryptedData, ulEncryptedDataLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getSymmetricCryptoOp() != NULL)
    {
		rv = SymEncryptUpdate(session, pData, ulDataLen,
				  pEncryptedData, l_pulEncryptedDataLen);
    }
	else
		return CKR_FUNCTION_NOT_SUPPORTED;

    *pulEncryptedDataLen = ulEncryptedDataLen;
    return rv;
}

// SymAlgorithm version of C_EncryptFinal
static CK_RV SymEncryptFinal(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	size_t remainingSize = cipher->getBufferSize() + cipher->getTagBytes();
	CK_ULONG size = remainingSize;
	if (cipher->isBlockCipher())
	{
		size_t blockSize = cipher->getBlockSize();
		bool isPadding = cipher->getPaddingMode();
		if ((remainingSize % blockSize) != 0 && !isPadding)
		{
			session->resetOp();
			// DEBUG_MSG("Remaining buffer size is not an integral of the block size. Block size: %#2x  Remaining size: %#2x",
			//	  blockSize, remainingSize);
			return CKR_DATA_LEN_RANGE;
		}
		// when padding: an integral of the block size that is longer than the remaining data.
		size = isPadding ? ((remainingSize + blockSize) / blockSize) * blockSize : remainingSize;
	}

	// Give required output buffer size.
	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulEncryptedDataLen < size)
	{
		// DEBUG_MSG("output buffer size: %#5x  size: %#5x",
		//	  *pulEncryptedDataLen, size);
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	// DEBUG_MSG("output buffer size: %#2x  size: %#2x  encryptedFinal.size(): %#2x",
	//	  *pulEncryptedDataLen, size, encryptedFinal.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulEncryptedDataLen < encryptedFinal.size())
	{
		session->resetOp();
		// ERROR_MSG("EncryptFinal returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
		//	  *pulEncryptedDataLen, encryptedFinal.size());
		return CKR_GENERAL_ERROR;
	}

	if (encryptedFinal.size() > 0)
	{
        memcpy_s(pEncryptedData, *pulEncryptedDataLen, encryptedFinal.byte_str(), encryptedFinal.size());
	}
	*pulEncryptedDataLen = encryptedFinal.size();

	session->resetOp();
	return CKR_OK;
}

// Finalise the encryption operation
CK_RV SoftHSM::C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pulEncryptedDataLen == nullptr) return CKR_ARGUMENTS_BAD;
    if (!validate_user_check_ptr(pulEncryptedDataLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ULONG ulEncryptedDataLen = *pulEncryptedDataLen;
    auto l_pulEncryptedDataLen = &ulEncryptedDataLen;

	if (pEncryptedData && ulEncryptedDataLen)
	{
		if (!validate_user_check_ptr(pEncryptedData, ulEncryptedDataLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT) return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getSymmetricCryptoOp() != NULL)
		rv = SymEncryptFinal(session, pEncryptedData, l_pulEncryptedDataLen);
	else
		rv = CKR_FUNCTION_NOT_SUPPORTED;

    *pulEncryptedDataLen = ulEncryptedDataLen;

    return rv;
}

// SymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::SymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for decryption
	if (!key->getBooleanValue(CKA_DECRYPT, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;


	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	size_t counterBits = 0;
	ByteString aad;
	size_t tagBytes = 0;
	switch(pMechanism->mechanism) {
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_DES_ECB:
			algo = SymAlgo::DES;
			mode = SymMode::ECB;
			bb = 7;
			break;
		case CKM_DES_CBC:
			algo = SymAlgo::DES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_DES_CBC_PAD:
			algo = SymAlgo::DES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
#endif
		case CKM_DES3_ECB:
			algo = SymAlgo::DES3;
			mode = SymMode::ECB;
			bb = 7;
			break;
		case CKM_DES3_CBC:
			algo = SymAlgo::DES3;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_DES3_CBC_PAD:
			algo = SymAlgo::DES3;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			bb = 7;
			break;
		case CKM_AES_ECB:
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_AES_CBC:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CBC_PAD:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				// DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
            memcpy_s(&iv[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CTR:
			algo = SymAlgo::AES;
			mode = SymMode::CTR;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
			{
				// DEBUG_MSG("CTR mode requires a counter block");
				return CKR_ARGUMENTS_BAD;
			}
			counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
			if (counterBits == 0 || counterBits > 128)
			{
				// DEBUG_MSG("Invalid ulCounterBits");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
            memcpy_s(&iv[0], 16, CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
			break;
#ifdef WITH_AES_GCM
		case CKM_AES_GCM:
			algo = SymAlgo::AES;
			mode = SymMode::GCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
			{
				// DEBUG_MSG("GCM mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
#ifdef SGXHSM
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen) && (nullptr == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv))
            {
                return CKR_ARGUMENTS_BAD;
            }
            if ((0 == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv))
            {
                return CKR_ARGUMENTS_BAD;
            }
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (nullptr == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD))
            {
                return CKR_ARGUMENTS_BAD;
            }
            if ((0 == CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD))
            {
                return CKR_ARGUMENTS_BAD;
            }
#endif
			iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
#ifdef SGXHSM
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv))
            {
                memcpy_s(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
            }
#else
            memcpy_s(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
#endif
			aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
#ifdef SGXHSM
            if ((0 != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen) && (nullptr != CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD))
            {
                memcpy_s(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
            }
#else
            memcpy_s(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
#endif
			tagBytes = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
			if (tagBytes > 128 || tagBytes % 8 != 0)
			{
				// DEBUG_MSG("Invalid ulTagBits value");
				return CKR_ARGUMENTS_BAD;
			}
			tagBytes = tagBytes / 8;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize decryption
	if (!cipher->decryptInit(secretkey, mode, iv, padding, counterBits, aad, tagBytes))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::AsymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for decryption
	if (!key->getBooleanValue(CKA_DECRYPT, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
        {
            rv = MechParamCheckRSAPKCSOAEP(pMechanism);
            if (rv != CKR_OK)
            {
                return rv;
            }

            CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
            if (params->hashAlg != CKM_SHA_1 ||
	            params->mgf != CKG_MGF1_SHA1)
            {
	            return CKR_ARGUMENTS_BAD;
            }

            mechanism = AsymMech::RSA_PKCS_OAEP;
            isRSA = true;
            break;
	    }
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	// Check if re-authentication is required
	if (key->getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false))
	{
		session->setReAuthentication(true);
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise decryption using the specified object
CK_RV SoftHSM::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (pMechanism == nullptr) return CKR_ARGUMENTS_BAD;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef SGXHSM
    // Check the key handle.
    OSObject *key = (OSObject*)handleManager->getObject(hKey);
    if (!key || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;
    CK_BBOOL isUsedForWrapping = key->getBooleanValue(CKA_USED_FOR_WRAPPING, false);

    if(isUsedForWrapping)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
#endif

    if (isSymMechanism(l_pMechanism))
    {
        return SymDecryptInit(hSession, l_pMechanism, hKey);
    }
    else
    {
        return AsymDecryptInit(hSession, l_pMechanism, hKey);
    }
}

// SymAlgorithm version of C_Decrypt
static CK_RV SymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	if (cipher->isBlockCipher() && ulEncryptedDataLen % cipher->getBlockSize() != 0)
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	if (!cipher->checkMaximumBytes(ulEncryptedDataLen))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (pData == NULL_PTR)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < ulEncryptedDataLen)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!cipher->decryptUpdate(encryptedData,data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Finalize decryption
	ByteString dataFinal;
	if (!cipher->decryptFinal(dataFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	data += dataFinal;
	if (data.size() > ulEncryptedDataLen)
	{
		data.resize(ulEncryptedDataLen);
	}

	if (data.size() != 0)
	{
        memcpy_s(pData, *pulDataLen, data.byte_str(), data.size());
	}
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// AsymAlgorithm version of C_Decrypt
static CK_RV AsymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the data
	CK_ULONG size = privateKey->getOutputLength();
	if (pData == NULL_PTR)
	{
		*pulDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < size)
	{
		*pulDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!asymCrypto->decrypt(privateKey,encryptedData,data,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (data.size() > size)
	{
		// ERROR_MSG("The size of the decrypted data exceeds the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	if (data.size() != 0)
	{
        memcpy_s(pData, *pulDataLen, data.byte_str(), data.size());
	}
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// Perform a single operation decryption in the given session
CK_RV SoftHSM::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pEncryptedData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulEncryptedDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pEncryptedData, ulEncryptedDataLen))
    {
        return CKR_DEVICE_MEMORY;
    }

    auto ulDataLen = *pulDataLen;
    auto l_pulDataLen = &ulDataLen;

    if (!validate_user_check_ptr(pulDataLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (pData && ulDataLen) 
	{
		if (!validate_user_check_ptr(pData, ulDataLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getSymmetricCryptoOp() != NULL)
		rv = SymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				  pData, l_pulDataLen);
	else
		rv = AsymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				   pData, l_pulDataLen);

    *pulDataLen = ulDataLen;

    return rv;
}

// SymAlgorithm version of C_DecryptUpdate
static CK_RV SymDecryptUpdate(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	size_t blockSize = cipher->getBlockSize();
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG maxSize = ulEncryptedDataLen + remainingSize;
	if (cipher->isBlockCipher())
	{
		// There must always be one block left in padding mode if next operation is DecryptFinal.
		// To guarantee that one byte is removed in padding mode when the number of blocks is calculated.
		size_t paddingAdjustByte = cipher->getPaddingMode() ? 1 : 0;
		int nrOfBlocks = (ulEncryptedDataLen + remainingSize - paddingAdjustByte) / blockSize;
		maxSize = nrOfBlocks * blockSize;
	}
	if (!cipher->checkMaximumBytes(ulEncryptedDataLen))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	// Give required output buffer size.
	if (pData == NULL_PTR)
	{
		*pDataLen = maxSize;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pDataLen < maxSize)
	{
		// DEBUG_MSG("Output buffer too short   ulEncryptedDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x",
		//	  ulEncryptedDataLen, *pDataLen, blockSize, remainingSize, maxSize);
		*pDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pEncryptedData, ulEncryptedDataLen);
	ByteString decryptedData;

	// Encrypt the data
	if (!cipher->decryptUpdate(data, decryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	// DEBUG_MSG("ulEncryptedDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x  decryptedData.size(): %#5x",
	//	  ulEncryptedDataLen, *pDataLen, blockSize, remainingSize, maxSize, decryptedData.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pDataLen < decryptedData.size())
	{
		session->resetOp();
		// ERROR_MSG("DecryptUpdate returning too much data. Length of output data buffer is %i but %i bytes was returned by the decrypt.",
		//		*pDataLen, decryptedData.size());
		return CKR_GENERAL_ERROR;
	}

	if (decryptedData.size() > 0)
	{
        memcpy_s(pData, *pDataLen, decryptedData.byte_str(), decryptedData.size());
	}
	*pDataLen = decryptedData.size();

	return CKR_OK;
}


// Feed data to the running decryption operation in a session
CK_RV SoftHSM::C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pEncryptedData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulEncryptedDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pEncryptedData, ulEncryptedDataLen))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (!validate_user_check_ptr(pDataLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    auto ulDataLen = *pDataLen;
    auto l_pDataLen = &ulDataLen;

    if (pData && ulDataLen) 
	{
		if (!validate_user_check_ptr(pData, ulDataLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getSymmetricCryptoOp() != NULL)
		rv = SymDecryptUpdate(session, pEncryptedData, ulEncryptedDataLen,
				  pData, l_pDataLen);
	else
		rv = CKR_FUNCTION_NOT_SUPPORTED;

    *pDataLen = ulDataLen;

    return rv;
}

static CK_RV SymDecryptFinal(Session* session, CK_BYTE_PTR pDecryptedData, CK_ULONG_PTR pulDecryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG size = remainingSize;
	if (cipher->isBlockCipher())
	{
		size_t blockSize = cipher->getBlockSize();
		if (remainingSize % blockSize != 0)
		{
			session->resetOp();
			// DEBUG_MSG("Remaining data length is not an integral of the block size. Block size: %#2x  Remaining size: %#2x",
			//	   blockSize, remainingSize);
			return CKR_ENCRYPTED_DATA_LEN_RANGE;
		}
		// It is at least one padding byte. If no padding the all remains will be returned.
		size_t paddingAdjustByte = cipher->getPaddingMode() ? 1 : 0;
		size = remainingSize - paddingAdjustByte;
	}

	// Give required output buffer size.
	if (pDecryptedData == NULL_PTR)
	{
		*pulDecryptedDataLen = size;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulDecryptedDataLen < size)
	{
		// DEBUG_MSG("output buffer size: %#5x  size: %#5x",
		//	  *pulDecryptedDataLen, size);
		*pulDecryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Finalize decryption
	ByteString decryptedFinal;
	if (!cipher->decryptFinal(decryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	// DEBUG_MSG("output buffer size: %#2x  size: %#2x  decryptedFinal.size(): %#2x",
	//	  *pulDecryptedDataLen, size, decryptedFinal.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulDecryptedDataLen < decryptedFinal.size())
	{
		session->resetOp();
		// ERROR_MSG("DecryptFinal returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
		//	  *pulDecryptedDataLen, decryptedFinal.size());
		return CKR_GENERAL_ERROR;
	}

	if (decryptedFinal.size() > 0)
	{
        memcpy_s(pDecryptedData, *pulDecryptedDataLen, decryptedFinal.byte_str(), decryptedFinal.size());
	}
	*pulDecryptedDataLen = decryptedFinal.size();

	session->resetOp();
	return CKR_OK;
}

// Finalise the decryption operation
CK_RV SoftHSM::C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!validate_user_check_ptr(pDataLen, sizeof(CK_ULONG)))
	{
		return CKR_DEVICE_MEMORY;
	}

    auto ulDataLen = *pDataLen;
    auto l_pDataLen = &ulDataLen;

	if (pData && ulDataLen)
	{
		if (!validate_user_check_ptr(pData, ulDataLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT) return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getSymmetricCryptoOp() != NULL)
		rv = SymDecryptFinal(session, pData, l_pDataLen);
	else
		rv = CKR_FUNCTION_NOT_SUPPORTED;

    *pDataLen = ulDataLen;

    return rv;
}

// Initialise digesting using the specified mechanism in the specified session
CK_RV SoftHSM::C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pMechanism == nullptr) return CKR_ARGUMENTS_BAD;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the mechanism
	HashAlgo::Type algo = HashAlgo::Unknown;
	switch(l_pMechanism->mechanism) {
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5:
			algo = HashAlgo::MD5;
			break;
#endif
		case CKM_SHA_1:
			algo = HashAlgo::SHA1;
			break;
		case CKM_SHA224:
			algo = HashAlgo::SHA224;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA256:
			algo = HashAlgo::SHA256;
			break;
		case CKM_SHA384:
			algo = HashAlgo::SHA384;
			break;
		case CKM_SHA512:
			algo = HashAlgo::SHA512;
			break;
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3411:
			algo = HashAlgo::GOST;
			break;
#endif
#endif // Unsupported by Crypto API Toolkit
		default:
			return CKR_MECHANISM_INVALID;
	}
	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(algo);
	if (hash == NULL) return CKR_MECHANISM_INVALID;

	// Initialize hashing
	if (hash->hashInit() == false)
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return CKR_GENERAL_ERROR;
	}

	session->setOpType(SESSION_OP_DIGEST);
	session->setDigestOp(hash);
	session->setHashAlgo(algo);

	return CKR_OK;
}

// Digest the specified data in a one-pass operation and return the resulting digest
CK_RV SoftHSM::C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pData, ulDataLen))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (!validate_user_check_ptr(pulDigestLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ULONG ulDigestLen = *pulDigestLen;

    if (pDigest && ulDigestLen)
    {
        if (!validate_user_check_ptr(pDigest, ulDigestLen))
        {
            return CKR_DEVICE_MEMORY;
        }
    }

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Return size
	CK_ULONG size = session->getDigestOp()->getHashSize();
	if (pDigest == NULL_PTR)
	{
		*pulDigestLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (ulDigestLen < size)
	{
		*pulDigestLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Digest the data
	if (session->getDigestOp()->hashUpdate(data) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the digest
	ByteString digest;
	if (session->getDigestOp()->hashFinal(digest) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (digest.size() != size)
	{
		// ERROR_MSG("The size of the digest differ from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
    memcpy_s(pDigest, ulDigestLen, digest.byte_str(), size);
	*pulDigestLen = size;

	session->resetOp();

	return CKR_OK;
}

// Update a running digest operation
CK_RV SoftHSM::C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulPartLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pPart, ulPartLen))
    {
        return CKR_DEVICE_MEMORY;
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Get the data
	ByteString data(pPart, ulPartLen);

	// Digest the data
	if (session->getDigestOp()->hashUpdate(data) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

// Update a running digest operation by digesting a secret key with the specified handle
CK_RV SoftHSM::C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
#if 0 // Unsupported by Crypto API Toolkit
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hObject);
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		// CKR_USER_NOT_LOGGED_IN is not a valid return code for this function,
		// so we use CKR_GENERAL_ERROR.
		return CKR_GENERAL_ERROR;
	}

	// Whitelist
	HashAlgo::Type algo = session->getHashAlgo();
	if (algo != HashAlgo::SHA1 &&
	    algo != HashAlgo::SHA224 &&
	    algo != HashAlgo::SHA256 &&
	    algo != HashAlgo::SHA384 &&
	    algo != HashAlgo::SHA512)
	{
		// Parano...
		if (!key->getBooleanValue(CKA_EXTRACTABLE, false))
			return CKR_KEY_INDIGESTIBLE;
		if (key->getBooleanValue(CKA_SENSITIVE, false))
			return CKR_KEY_INDIGESTIBLE;
	}

	// Get value
	if (!key->attributeExists(CKA_VALUE))
		return CKR_KEY_INDIGESTIBLE;
	ByteString keybits;
	if (isPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getByteStringValue(CKA_VALUE);
	}

	// Digest the value
	if (session->getDigestOp()->hashUpdate(keybits) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
#else
	return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

// Finalise the digest operation in the specified session and return the digest
CK_RV SoftHSM::C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pulDigestLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ULONG ulDigestLen = *pulDigestLen;

    if (pDigest && ulDigestLen)
    {
        if (!validate_user_check_ptr(pDigest, ulDigestLen))
        {
            return CKR_DEVICE_MEMORY;
        }
    }

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Return size
	CK_ULONG size = session->getDigestOp()->getHashSize();
	if (pDigest == NULL_PTR)
	{
		*pulDigestLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (ulDigestLen < size)
	{
		*pulDigestLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the digest
	ByteString digest;
	if (session->getDigestOp()->hashFinal(digest) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (digest.size() != size)
	{
		// ERROR_MSG("The size of the digest differ from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
    memcpy_s(pDigest, ulDigestLen, digest.byte_str(), size);
	*pulDigestLen = size;

	session->resetOp();

	return CKR_OK;
}

// Sign*/Verify*() is for MACs too
static bool isMacMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_MD5_HMAC:
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3411_HMAC:
#endif
		case CKM_DES3_CMAC:
		case CKM_AES_CMAC:
#endif // Unsupported by Crypto API Toolkit
			return true;
		default:
			return false;
	}
}

// MacAlgorithm version of C_SignInit
CK_RV SoftHSM::MacSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for signing
	if (!key->getBooleanValue(CKA_SIGN, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the MAC algorithm matching the mechanism
	// Also check mechanism constraints
	MacAlgo::Type algo = MacAlgo::Unknown;
	size_t bb = 8;
	size_t minSize = 0;
	switch(pMechanism->mechanism) {
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_MD5_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 16;
			algo = MacAlgo::HMAC_MD5;
			break;
#endif
		case CKM_SHA_1_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA_1_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 20;
			algo = MacAlgo::HMAC_SHA1;
			break;
		case CKM_SHA224_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA224_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 28;
			algo = MacAlgo::HMAC_SHA224;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA256_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA256_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 32;
			algo = MacAlgo::HMAC_SHA256;
			break;
		case CKM_SHA384_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA384_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 48;
			algo = MacAlgo::HMAC_SHA384;
			break;
		case CKM_SHA512_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA512_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 64;
			algo = MacAlgo::HMAC_SHA512;
			break;
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3411_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_GOST28147)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 32;
			algo = MacAlgo::HMAC_GOST;
			break;
#endif
		case CKM_DES3_CMAC:
			if (keyType != CKK_DES2 && keyType != CKK_DES3)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = MacAlgo::CMAC_DES;
			bb = 7;
			break;
		case CKM_AES_CMAC:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = MacAlgo::CMAC_AES;
			break;
#endif // Unsupported by Crypto API Toolkit
		default:
			return CKR_MECHANISM_INVALID;
	}
	MacAlgorithm* mac = CryptoFactory::i()->getMacAlgorithm(algo);
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* privkey = new SymmetricKey();

	if (getSymmetricKey(privkey, token, key) != CKR_OK)
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Adjust key bit length
	privkey->setBitLen(privkey->getKeyBits().size() * bb);

	// Check key size
	if (privkey->getBitLen() < (minSize*8))
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_KEY_SIZE_RANGE;
	}

	// Initialize signing
	if (!mac->signInit(privkey))
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(privkey);

	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignInit
CK_RV SoftHSM::AsymSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for signing
	if (!key->getBooleanValue(CKA_SIGN, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	void* param = NULL;
	size_t paramLen = 0;
	RSA_PKCS_PSS_PARAMS pssParam;
	bool bAllowMultiPartOp;
	bool isRSA = false;
#if 0 // Unsupported by Crypto API Toolkit
	bool isDSA = false;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
	bool isECDSA = false;
#endif
#ifdef WITH_EDDSA
	bool isEDDSA = false;
#endif
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
			mechanism = AsymMech::RSA_MD5_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#endif
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA1_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA1_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			{
				// ERROR_MSG("Invalid RSA-PSS parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_PKCS_PSS;
			unsigned long allowedMgf;

			switch(CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg) {
				case CKM_SHA_1:
					pssParam.hashAlg = HashAlgo::SHA1;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
					allowedMgf = CKG_MGF1_SHA1;
					break;
				case CKM_SHA224:
					pssParam.hashAlg = HashAlgo::SHA224;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
					allowedMgf = CKG_MGF1_SHA224;
					break;
				case CKM_SHA256:
					pssParam.hashAlg = HashAlgo::SHA256;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
					allowedMgf = CKG_MGF1_SHA256;
					break;
				case CKM_SHA384:
					pssParam.hashAlg = HashAlgo::SHA384;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
					allowedMgf = CKG_MGF1_SHA384;
					break;
				case CKM_SHA512:
					pssParam.hashAlg = HashAlgo::SHA512;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
					allowedMgf = CKG_MGF1_SHA512;
					break;
				default:
					// ERROR_MSG("Invalid RSA-PSS hash");
					return CKR_ARGUMENTS_BAD;
			}

			if (CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != allowedMgf) {
				// ERROR_MSG("Hash and MGF don't match");
				return CKR_ARGUMENTS_BAD;
			}

			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA1_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA1;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA224)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA256)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA384)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA512)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_DSA:
			mechanism = AsymMech::DSA;
			bAllowMultiPartOp = false;
			isDSA = true;
			break;
		case CKM_DSA_SHA1:
			mechanism = AsymMech::DSA_SHA1;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA224:
			mechanism = AsymMech::DSA_SHA224;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA256:
			mechanism = AsymMech::DSA_SHA256;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA384:
			mechanism = AsymMech::DSA_SHA384;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA512:
			mechanism = AsymMech::DSA_SHA512;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = AsymMech::ECDSA;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3410:
			mechanism = AsymMech::GOST;
			bAllowMultiPartOp = false;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			mechanism = AsymMech::GOST_GOST;
			bAllowMultiPartOp = true;
			break;
#endif
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_EDDSA
		case CKM_EDDSA:
			mechanism = AsymMech::EDDSA;
			bAllowMultiPartOp = false;
			isEDDSA = true;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#if 0 // Unsupported by Crypto API Toolki
	else if (isDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getDSAPrivateKey((DSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
    }
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPrivateKey((ECPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
#ifdef WITH_EDDSA
	else if (isEDDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getEDPrivateKey((EDPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else
	{
#ifdef WITH_GOST
#if 0 // Unsupported by Crypto API Toolkit
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::GOST);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getGOSTPrivateKey((GOSTPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
#endif // Unsupported by Crypto API Toolkit
#else
		return CKR_MECHANISM_INVALID;
#endif
    }

	// Initialize signing
	if (bAllowMultiPartOp && !asymCrypto->signInit(privateKey,mechanism,param,paramLen))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	// Check if re-authentication is required
	if (key->getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false))
	{
		session->setReAuthentication(true);
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setParameters(param, paramLen);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV SoftHSM::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (pMechanism == nullptr) return CKR_ARGUMENTS_BAD;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef DCAP_SUPPORT
    // Get the session
    Session* session = (Session*)handleManager->getSession(hSession);
    if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

    // Check if we have another operation
    if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

    // Get the token
    Token* token = session->getToken();
    if (token == NULL) return CKR_GENERAL_ERROR;

    // If the key is used for quote generation should not be used for signing
    OSObject *key = (OSObject *)handleManager->getObject(hKey);
    if (!key || !key->isValid())
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    CK_BBOOL isUsedForQuoteGeneration = key->getBooleanValue(CKA_USED_FOR_QUOTE_GENERATION, false);

    if (isUsedForQuoteGeneration)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
#endif

	if (isMacMechanism(l_pMechanism))
		return MacSignInit(hSession, l_pMechanism, hKey);
	else
		return AsymSignInit(hSession, l_pMechanism, hKey);
}

// MacAlgorithm version of C_Sign
static CK_RV MacSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Sign the data
	if (!mac->signUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		// ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
    memcpy_s(pSignature, *pulSignatureLen, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Sign
static CK_RV AsymSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	size_t paramLen;
	void* param = session->getParameters(paramLen);
	
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature;

	// Sign the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->signUpdate(data) ||
		    !asymCrypto->signFinal(signature))
		{
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
	}
	else if (!asymCrypto->sign(privateKey,data,signature,mechanism,param,paramLen))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
    // For EC, we can only check the upper bound:
    // See: https://github.com/openssl/openssl/issues/23177
    if (mechanism == AsymMech::ECDSA)
    {
        if (signature.size() > size)
        {
            // ERROR_MSG("The size of the signature differs from the size of the mechanism");
            session->resetOp();
            return CKR_GENERAL_ERROR;
        }
        size = signature.size();
    }
    else
    {
        if (signature.size() != size)
        {
            // ERROR_MSG("The size of the signature differs from the size of the mechanism");
            session->resetOp();
            return CKR_GENERAL_ERROR;
        }
    }
    memcpy_s(pSignature, *pulSignatureLen, signature.byte_str(), size);
    *pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// Sign the data in a single pass operation
CK_RV SoftHSM::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (!validate_user_check_ptr(pData, ulDataLen))
	{
		return CKR_DEVICE_MEMORY;
	}

	if (!validate_user_check_ptr(pulSignatureLen, sizeof(CK_ULONG)))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_ULONG ulSignatureLen = *pulSignatureLen;
    auto l_pulSignatureLen = &ulSignatureLen;

	if (pSignature && ulSignatureLen)
	{
		if (!validate_user_check_ptr(pSignature, ulSignatureLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getMacOp() != NULL)
		rv = MacSign(session, pData, ulDataLen,
			       pSignature, l_pulSignatureLen);
	else
		rv = AsymSign(session, pData, ulDataLen,
				pSignature, l_pulSignatureLen);

    *pulSignatureLen = ulSignatureLen;

    return rv;
}

// MacAlgorithm version of C_SignUpdate
static CK_RV MacSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!mac->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignUpdate
static CK_RV AsymSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!asymCrypto->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running signing operation with additional data
CK_RV SoftHSM::C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulPartLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pPart, ulPartLen))
    {
        return CKR_DEVICE_MEMORY;
    }

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignUpdate(session, pPart, ulPartLen);
	else
		return AsymSignUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		// ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
    memcpy_s(pSignature, *pulSignatureLen, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignFinal
static CK_RV AsymSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!asymCrypto->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		// ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
    memcpy_s(pSignature, *pulSignatureLen, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// Finalise a running signing operation and return the signature
CK_RV SoftHSM::C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pulSignatureLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ULONG ulSignatureLen = *pulSignatureLen;
    auto l_pulSignatureLen = &ulSignatureLen;

	if (pSignature && ulSignatureLen)
	{
		if (!validate_user_check_ptr(pSignature, ulSignatureLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

    CK_RV rv;
	if (session->getMacOp() != NULL)
		rv = MacSignFinal(session, pSignature, l_pulSignatureLen);
	else
		rv = AsymSignFinal(session, pSignature, l_pulSignatureLen);

    *pulSignatureLen = ulSignatureLen;

    return rv;
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pData*/, CK_ULONG /*ulDataLen*/, CK_BYTE_PTR /*pSignature*/, CK_ULONG_PTR /*pulSignatureLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// MacAlgorithm version of C_VerifyInit
CK_RV SoftHSM::MacVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for verifying
	if (!key->getBooleanValue(CKA_VERIFY, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the MAC algorithm matching the mechanism
	// Also check mechanism constraints
	MacAlgo::Type algo = MacAlgo::Unknown;
	size_t bb = 8;
	size_t minSize = 0;
	switch(pMechanism->mechanism) {
#if 0 // Unsupported by Crypto API Toolkit
#ifndef WITH_FIPS
		case CKM_MD5_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_MD5_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 16;
			algo = MacAlgo::HMAC_MD5;
			break;
#endif
		case CKM_SHA_1_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA_1_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 20;
			algo = MacAlgo::HMAC_SHA1;
			break;
		case CKM_SHA224_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA224_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 28;
			algo = MacAlgo::HMAC_SHA224;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_SHA256_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA256_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 32;
			algo = MacAlgo::HMAC_SHA256;
			break;
		case CKM_SHA384_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA384_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 48;
			algo = MacAlgo::HMAC_SHA384;
			break;
		case CKM_SHA512_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_SHA512_HMAC)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 64;
			algo = MacAlgo::HMAC_SHA512;
			break;
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3411_HMAC:
			if (keyType != CKK_GENERIC_SECRET && keyType != CKK_GOST28147)
				return CKR_KEY_TYPE_INCONSISTENT;
			minSize = 32;
			algo = MacAlgo::HMAC_GOST;
			break;
#endif
		case CKM_DES3_CMAC:
			if (keyType != CKK_DES2 && keyType != CKK_DES3)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = MacAlgo::CMAC_DES;
			bb = 7;
			break;
		case CKM_AES_CMAC:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = MacAlgo::CMAC_AES;
			break;
#endif // Unsupported by Crypto API Toolkit
		default:
			return CKR_MECHANISM_INVALID;
	}
	MacAlgorithm* mac = CryptoFactory::i()->getMacAlgorithm(algo);
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* pubkey = new SymmetricKey();

	if (getSymmetricKey(pubkey, token, key) != CKR_OK)
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Adjust key bit length
	pubkey->setBitLen(pubkey->getKeyBits().size() * bb);

	// Check key size
	if (pubkey->getBitLen() < (minSize*8))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_KEY_SIZE_RANGE;
	}

	// Initialize verifying
	if (!mac->verifyInit(pubkey))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(pubkey);

	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyInit
CK_RV SoftHSM::AsymVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for verifying
	if (!key->getBooleanValue(CKA_VERIFY, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	void* param = NULL;
	size_t paramLen = 0;
	RSA_PKCS_PSS_PARAMS pssParam;
	bool bAllowMultiPartOp;
	bool isRSA = false;
#if 0 //Unsupported by Crypto API Toolkit
	bool isDSA = false;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
	bool isECDSA = false;
#endif
#ifdef WITH_EDDSA
	bool isEDDSA = false;
#endif
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
			mechanism = AsymMech::RSA_MD5_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA1_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_PKCS_PSS;

			unsigned long expectedMgf;
			switch(CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg) {
				case CKM_SHA_1:
					pssParam.hashAlg = HashAlgo::SHA1;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
					expectedMgf = CKG_MGF1_SHA1;
					break;
				case CKM_SHA224:
					pssParam.hashAlg = HashAlgo::SHA224;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
					expectedMgf = CKG_MGF1_SHA224;
					break;
				case CKM_SHA256:
					pssParam.hashAlg = HashAlgo::SHA256;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
					expectedMgf = CKG_MGF1_SHA256;
					break;
				case CKM_SHA384:
					pssParam.hashAlg = HashAlgo::SHA384;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
					expectedMgf = CKG_MGF1_SHA384;
					break;
				case CKM_SHA512:
					pssParam.hashAlg = HashAlgo::SHA512;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
					expectedMgf = CKG_MGF1_SHA512;
					break;
				default:
					return CKR_ARGUMENTS_BAD;
			}

			if (CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != expectedMgf) {
				return CKR_ARGUMENTS_BAD;
			}

			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA1_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA1;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA224)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA256)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA384)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA512)
			{
				// ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_DSA:
			mechanism = AsymMech::DSA;
			bAllowMultiPartOp = false;
			isDSA = true;
			break;
		case CKM_DSA_SHA1:
			mechanism = AsymMech::DSA_SHA1;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA224:
			mechanism = AsymMech::DSA_SHA224;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA256:
			mechanism = AsymMech::DSA_SHA256;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA384:
			mechanism = AsymMech::DSA_SHA384;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
		case CKM_DSA_SHA512:
			mechanism = AsymMech::DSA_SHA512;
			bAllowMultiPartOp = true;
			isDSA = true;
			break;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = AsymMech::ECDSA;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3410:
			mechanism = AsymMech::GOST;
			bAllowMultiPartOp = false;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			mechanism = AsymMech::GOST_GOST;
			bAllowMultiPartOp = true;
			break;
#endif
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_EDDSA
		case CKM_EDDSA:
			mechanism = AsymMech::EDDSA;
			bAllowMultiPartOp = false;
			isEDDSA = true;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#if 0 // Unsupported by Crypto API Toolkit
	else if (isDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getDSAPublicKey((DSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
    }
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPublicKey((ECPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
#ifdef WITH_EDDSA
	else if (isEDDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getEDPublicKey((EDPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else
	{
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::GOST);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getGOSTPublicKey((GOSTPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
#else
		return CKR_MECHANISM_INVALID;
#endif
#endif // Unsupported by Crypto API Toolkit
        return CKR_MECHANISM_INVALID;
    }

	// Initialize verifying
	if (bAllowMultiPartOp && !asymCrypto->verifyInit(publicKey,mechanism,param,paramLen))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setParameters(param, paramLen);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise a verification operation using the specified key and mechanism
CK_RV SoftHSM::C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (pMechanism == nullptr) return CKR_ARGUMENTS_BAD;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

#ifdef DCAP_SUPPORT
    // Get the session
    Session* session = (Session*)handleManager->getSession(hSession);
    if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

    // Check if we have another operation
    if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

    // Get the token
    Token* token = session->getToken();
    if (token == NULL) return CKR_GENERAL_ERROR;

    // If the key is used for quote generation should not be used for verifying
    OSObject *key = (OSObject *)handleManager->getObject(hKey);
    if (!key || !key->isValid())
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    CK_BBOOL isUsedForQuoteGeneration = key->getBooleanValue(CKA_USED_FOR_QUOTE_GENERATION, false);

    if(isUsedForQuoteGeneration)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
#endif

	if (isMacMechanism(l_pMechanism))
		return MacVerifyInit(hSession, l_pMechanism, hKey);
	else
		return AsymVerifyInit(hSession, l_pMechanism, hKey);
}

// MacAlgorithm version of C_Verify
static CK_RV MacVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		// ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Verify the data
	if (!mac->verifyUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the signature
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Verify
static CK_RV AsymVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	size_t paramLen;
	void* param = session->getParameters(paramLen);
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
    // For EC, we can only check the upper bound:
    // See: https://github.com/openssl/openssl/issues/23177
    if (mechanism == AsymMech::ECDSA)
    {
        if (ulSignatureLen > size)
        {
            // ERROR_MSG("The size of the signature differs from the size of the mechanism");
            session->resetOp();
            return CKR_SIGNATURE_LEN_RANGE;
        }
        size = ulSignatureLen;
    }
    else
    {
        if (ulSignatureLen != size)
        {
            // ERROR_MSG("The size of the signature differs from the size of the mechanism");
            session->resetOp();
            return CKR_SIGNATURE_LEN_RANGE;
        }
    }

    // Get the data
    ByteString data;

    // We must allow input length <= k and therfore need to prepend the data with zeroes.
    if (mechanism == AsymMech::RSA) {
        data.wipe(size-ulDataLen);
    }

    data += ByteString(pData, ulDataLen);
    ByteString signature(pSignature, size);

	// Verify the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->verifyUpdate(data) ||
		    !asymCrypto->verifyFinal(signature))
		{
			session->resetOp();
			return CKR_SIGNATURE_INVALID;
		}
	}
	else if (!asymCrypto->verify(publicKey,data,signature,mechanism,param,paramLen))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Perform a single pass verification operation
CK_RV SoftHSM::C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulDataLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pData, ulDataLen))
    {
        return CKR_DEVICE_MEMORY;
    }

	if (ulSignatureLen)
	{
		if (!validate_user_check_ptr(pSignature, ulSignatureLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerify(session, pData, ulDataLen,
				 pSignature, ulSignatureLen);
	else
		return AsymVerify(session, pData, ulDataLen,
				  pSignature, ulSignatureLen);
}

// MacAlgorithm version of C_VerifyUpdate
static CK_RV MacVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!mac->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyUpdate
static CK_RV AsymVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!asymCrypto->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running verification operation with additional data
CK_RV SoftHSM::C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulPartLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!validate_user_check_ptr(pPart, ulPartLen))
    {
        return CKR_DEVICE_MEMORY;
    }

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyUpdate(session, pPart, ulPartLen);
	else
		return AsymVerifyUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		// ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyFinal
static CK_RV AsymVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		// ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!asymCrypto->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Finalise the verification operation and check the signature
CK_RV SoftHSM::C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulSignatureLen)
	{
		if (!validate_user_check_ptr(pSignature, ulSignatureLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyFinal(session, pSignature, ulSignatureLen);
	else
		return AsymVerifyFinal(session, pSignature, ulSignatureLen);
}

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV SoftHSM::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part verification operation and recover the signed data
CK_RV SoftHSM::C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pSignature*/, CK_ULONG /*ulSignatureLen*/, CK_BYTE_PTR /*pData*/, CK_ULONG_PTR /*pulDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part encryption and digesting operation
CK_RV SoftHSM::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG_PTR /*pulEncryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and digesting operation
CK_RV SoftHSM::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pDecryptedPart*/, CK_ULONG_PTR /*pulDecryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part signing and encryption operation
CK_RV SoftHSM::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG_PTR /*pulEncryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and verification operation
CK_RV SoftHSM::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG /*ulEncryptedPartLen*/, CK_BYTE_PTR /*pPart*/, CK_ULONG_PTR /*pulPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generate a secret key or a domain parameter set using the specified mechanism
CK_RV SoftHSM::C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_OBJECT_HANDLE hKey;
    auto l_phKey = &hKey;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (nullptr == pTemplate && 0 != ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(phKey, sizeof(CK_OBJECT_HANDLE)))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (ulCount && !validate_user_check_attribute_ptr(pTemplate, ulCount))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_ATTRIBUTE l_template[ulCount];
    memset_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), 0x00, ulCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> value(ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        if (l_template[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_template[i].ulValueLen;
        if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        value[i].resize(ulValueLen);
        memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
        l_template[i].pValue = value[i].data();
    }

    auto l_pTemplate = l_template;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DSA and DH parameters
	// and symmetric ciphers
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	switch (l_pMechanism->mechanism)
	{
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_DSA_PARAMETER_GEN:
			objClass = CKO_DOMAIN_PARAMETERS;
			keyType = CKK_DSA;
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			objClass = CKO_DOMAIN_PARAMETERS;
			keyType = CKK_DH;
			break;
#ifndef WITH_FIPS
		case CKM_DES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES;
			break;
#endif
		case CKM_DES2_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES2;
			break;
		case CKM_DES3_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES3;
			break;
#endif // Unsupported by Crypto API Toolkit
		case CKM_AES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_AES;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_GENERIC_SECRET_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_GENERIC_SECRET;
			break;
#endif // Unsupported by Crypto API Toolkit
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Extract information from the template that is needed to create the object.
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = true;
	extractObjectInformation(l_pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_DOMAIN_PARAMETERS)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (l_pMechanism->mechanism == CKM_DSA_PARAMETER_GEN &&
	    (objClass != CKO_DOMAIN_PARAMETERS || keyType != CKK_DSA))
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DH_PKCS_PARAMETER_GEN &&
	    (objClass != CKO_DOMAIN_PARAMETERS || keyType != CKK_DH))
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES))
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DES2_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES2))
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DES3_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES3))
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_AES))
		return CKR_TEMPLATE_INCONSISTENT;
#if 0 // Unsupported by Crypto API Toolkit
	if (l_pMechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_GENERIC_SECRET))
		return CKR_TEMPLATE_INCONSISTENT;
#endif // Unsupported by Crypto API Toolkit

	// Check authorization
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

#if 0 // Unsupported by Crypto API Toolkit
	// Generate DSA domain parameters
	if (l_pMechanism->mechanism == CKM_DSA_PARAMETER_GEN)
	{
		rv = this->generateDSAParameters(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}

	// Generate DH domain parameters
	if (l_pMechanism->mechanism == CKM_DH_PKCS_PARAMETER_GEN)
	{
		rv = this->generateDHParameters(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}

	// Generate DES secret key
	if (l_pMechanism->mechanism == CKM_DES_KEY_GEN)
	{
		rv = this->generateDES(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}

	// Generate DES2 secret key
	if (l_pMechanism->mechanism == CKM_DES2_KEY_GEN)
	{
		rv = this->generateDES2(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}

	// Generate DES3 secret key
	if (l_pMechanism->mechanism == CKM_DES3_KEY_GEN)
	{
		rv = this->generateDES3(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}
#endif // Unsupported by Crypto API Toolkit

	// Generate AES secret key
	if (l_pMechanism->mechanism == CKM_AES_KEY_GEN)
	{
		rv = this->generateAES(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}

#if 0 // Unsupported by Crypto API Toolkit
	// Generate generic secret key
	if (l_pMechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN)
	{
		rv = this->generateGeneric(hSession, l_pTemplate, ulCount, l_phKey, isOnToken, isPrivate);
        *phKey = hKey;
        return rv;
	}
#endif // Unsupported by Crypto API Toolkit

	return CKR_GENERAL_ERROR;
}

// Generate a key-pair using the specified mechanism
CK_RV SoftHSM::C_GenerateKeyPair
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
    CK_OBJECT_HANDLE hPublicKey;
    auto l_phPublicKey = &hPublicKey;

    CK_OBJECT_HANDLE hPrivateKey;
    auto l_phPrivateKey = &hPrivateKey;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (nullptr == pPublicKeyTemplate && 0 != ulPublicKeyAttributeCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (nullptr == pPrivateKeyTemplate && 0 != ulPrivateKeyAttributeCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (phPublicKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phPrivateKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(phPublicKey, sizeof(CK_OBJECT_HANDLE)))
    {
        return CKR_DEVICE_MEMORY;
    }

	if (ulPublicKeyAttributeCount)
	{
        if (ulPublicKeyAttributeCount > CKA_MAX_ATTRIBUTES)
        {
            return CKR_ARGUMENTS_BAD;
        }

		if (!validate_user_check_attribute_ptr(pPublicKeyTemplate, ulPublicKeyAttributeCount))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

    if (!validate_user_check_ptr(phPrivateKey, sizeof(CK_OBJECT_HANDLE)))
    {
        return CKR_DEVICE_MEMORY;
    }

	if (ulPrivateKeyAttributeCount)
	{
        if (ulPrivateKeyAttributeCount > CKA_MAX_ATTRIBUTES)
        {
            return CKR_ARGUMENTS_BAD;
        }

		if (!validate_user_check_attribute_ptr(pPrivateKeyTemplate, ulPrivateKeyAttributeCount))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

    CK_ATTRIBUTE l_PublicKeyTemplate[ulPublicKeyAttributeCount];
    memset_s(l_PublicKeyTemplate, ulPublicKeyAttributeCount * sizeof(CK_ATTRIBUTE), 0x00, ulPublicKeyAttributeCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_PublicKeyTemplate, ulPublicKeyAttributeCount * sizeof(CK_ATTRIBUTE), pPublicKeyTemplate, ulPublicKeyAttributeCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> publicValue(ulPublicKeyAttributeCount);

    for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
    {
        if (l_PublicKeyTemplate[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_PublicKeyTemplate[i].ulValueLen;
		if (!validate_user_check_ptr(l_PublicKeyTemplate[i].pValue, ulValueLen))
		{
			return CKR_DEVICE_MEMORY;
		}

        publicValue[i].resize(ulValueLen);
        memcpy_s(publicValue[i].data(), ulValueLen, l_PublicKeyTemplate[i].pValue, ulValueLen);
        l_PublicKeyTemplate[i].pValue = publicValue[i].data();
    }

    auto l_pPublicKeyTemplate= l_PublicKeyTemplate;

    CK_ATTRIBUTE l_PrivateKeyTemplate[ulPrivateKeyAttributeCount];
    memset_s(l_PrivateKeyTemplate, ulPrivateKeyAttributeCount * sizeof(CK_ATTRIBUTE), 0x00, ulPrivateKeyAttributeCount * sizeof(CK_ATTRIBUTE));
    memcpy_s(l_PrivateKeyTemplate, ulPrivateKeyAttributeCount * sizeof(CK_ATTRIBUTE), pPrivateKeyTemplate, ulPrivateKeyAttributeCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> privateValue(ulPrivateKeyAttributeCount);

    for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++)
    {
        if (l_PrivateKeyTemplate[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_PrivateKeyTemplate[i].ulValueLen;
		if (!validate_user_check_ptr(l_PrivateKeyTemplate[i].pValue, ulValueLen))
		{
			return CKR_DEVICE_MEMORY;
		}

        privateValue[i].resize(ulValueLen);
        memcpy_s(privateValue[i].data(), ulValueLen, l_PrivateKeyTemplate[i].pValue, ulValueLen);
        l_PrivateKeyTemplate[i].pValue = privateValue[i].data();
    }

    auto l_pPrivateKeyTemplate= l_PrivateKeyTemplate;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept RSA, DSA, EC and DH key pair generation.
	CK_KEY_TYPE keyType;
	switch (l_pMechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			keyType = CKK_RSA;
			break;
#if 0 // Unsupported by Crypto API Toolkit
		case CKM_DSA_KEY_PAIR_GEN:
			keyType = CKK_DSA;
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			keyType = CKK_DH;
			break;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			keyType = CKK_EC;
			break;
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			keyType = CKK_GOSTR3410;
			break;
#endif
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			keyType = CKK_EC_EDWARDS;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	CK_CERTIFICATE_TYPE dummy;

	// Extract information from the public key template that is needed to create the object.
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL ispublicKeyToken = CK_FALSE;
	CK_BBOOL ispublicKeyPrivate = CK_FALSE;
	bool isPublicKeyImplicit = true;
	extractObjectInformation(l_pPublicKeyTemplate, ulPublicKeyAttributeCount, publicKeyClass, keyType, dummy, ispublicKeyToken, ispublicKeyPrivate, isPublicKeyImplicit);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (publicKeyClass != CKO_PUBLIC_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (l_pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DSA_KEY_PAIR_GEN && keyType != CKK_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN && keyType != CKK_DH)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN && keyType != CKK_GOSTR3410)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;

	// Extract information from the private key template that is needed to create the object.
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isprivateKeyToken = CK_FALSE;
	CK_BBOOL isprivateKeyPrivate = CK_TRUE;
	bool isPrivateKeyImplicit = true;
	extractObjectInformation(l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount, privateKeyClass, keyType, dummy, isprivateKeyToken, isprivateKeyPrivate, isPrivateKeyImplicit);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (privateKeyClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (l_pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DSA_KEY_PAIR_GEN && keyType != CKK_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN && keyType != CKK_DH)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN && keyType != CKK_GOSTR3410)
		return CKR_TEMPLATE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), ispublicKeyToken || isprivateKeyToken, ispublicKeyPrivate || isprivateKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

	// Generate RSA keys
	if (l_pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
	{
			rv = this->generateRSA(hSession,
								   l_pPublicKeyTemplate, ulPublicKeyAttributeCount,
								   l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
								   l_phPublicKey, l_phPrivateKey,
								   ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
#ifdef SGXHSM
			if (rv == CKR_OK)
			{
				OSObject* osobject = nullptr;
                CK_ULONG pairKeyIdVal = 0;

                if (SGX_SUCCESS != sgx_read_rand(reinterpret_cast<unsigned char*>(&pairKeyIdVal), sizeof(pairKeyIdVal)))
                {
                    return CKR_GENERAL_ERROR;
                }

                OSAttribute pairKeyId(pairKeyIdVal);

				osobject = (OSObject*)handleManager->getObject(hPublicKey);
				if (osobject == NULL_PTR || !osobject->isValid()) {
					rv = CKR_FUNCTION_FAILED;
				} else if (osobject->startTransaction()) {
					bool bOK = true;

					// pair key attribute to prevent wrapped key decrypt via C_Decrypt
                    bOK = bOK && osobject->setAttribute(CKA_ASYMMETRIC_PAIR_ID, pairKeyId);

					if (bOK)
						bOK = osobject->commitTransaction();
					else
						osobject->abortTransaction();

					if (!bOK)
					{
						rv = CKR_FUNCTION_FAILED;
						if (hPublicKey != CK_INVALID_HANDLE)
						{
							OSObject* obj = (OSObject*)handleManager->getObject(hPublicKey);
							handleManager->destroyObject(hPublicKey);
							if (obj) obj->destroyObject();
							hPublicKey = CK_INVALID_HANDLE;
						}

						if (hPrivateKey != CK_INVALID_HANDLE)
						{
							OSObject* obj = (OSObject*)handleManager->getObject(hPrivateKey);
							handleManager->destroyObject(hPrivateKey);
							if (obj) obj->destroyObject();
							hPrivateKey = CK_INVALID_HANDLE;
						}
					}
				}

				osobject = (OSObject*)handleManager->getObject(hPrivateKey);
				if (osobject == NULL_PTR || !osobject->isValid()) {
					rv = CKR_FUNCTION_FAILED;
				} else if (osobject->startTransaction()) {
					bool bOK = true;

					// pair key attribute to prevent wrapped key decrypt via C_Decrypt
                    bOK = bOK && osobject->setAttribute(CKA_ASYMMETRIC_PAIR_ID, pairKeyId);

					if (bOK)
						bOK = osobject->commitTransaction();
					else
						osobject->abortTransaction();

					if (!bOK)
					{
						rv = CKR_FUNCTION_FAILED;
						if (hPublicKey != CK_INVALID_HANDLE)
						{
							OSObject* obj = (OSObject*)handleManager->getObject(hPublicKey);
							handleManager->destroyObject(hPublicKey);
							if (obj) obj->destroyObject();
							hPublicKey = CK_INVALID_HANDLE;
						}

						if (hPrivateKey != CK_INVALID_HANDLE)
						{
							OSObject* obj = (OSObject*)handleManager->getObject(hPrivateKey);
							handleManager->destroyObject(hPrivateKey);
							if (obj) obj->destroyObject();
							hPrivateKey = CK_INVALID_HANDLE;
						}
					}
				}
			}
#endif
            *phPublicKey = hPublicKey;
            *phPrivateKey = hPrivateKey;
            return rv;
	}

#if 0 // Unsupported by Crypto API Toolkit
	// Generate DSA keys
	if (l_pMechanism->mechanism == CKM_DSA_KEY_PAIR_GEN)
	{
		rv = this->generateDSA(hSession,
								 l_pPublicKeyTemplate, ulPublicKeyAttributeCount,
								 l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
								 l_phPublicKey, l_phPrivateKey,
								 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
        *phPublicKey = hPublicKey;
        *phPrivateKey = hPrivateKey;
        return rv;

	}
#endif // Unsupported by Crypto API Toolkit

	// Generate EC keys
	if (l_pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN)
	{
        rv = this->generateEC(hSession,
								l_pPublicKeyTemplate, ulPublicKeyAttributeCount,
								l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
								l_phPublicKey, l_phPrivateKey,
								ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
        *phPublicKey = hPublicKey;
        *phPrivateKey = hPrivateKey;
        return rv;
	}

#if 0 // Unsupported by Crypto API Toolkit
	// Generate DH keys
	if (l_pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN)
	{
        rv = this->generateDH(hSession,
									 l_pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 l_phPublicKey, l_phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
        *phPublicKey = hPublicKey;
        *phPrivateKey = hPrivateKey;
        return rv;
	}

	// Generate GOST keys
	if (l_pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN)
	{
        rv = this->generateGOST(hSession,
								  l_pPublicKeyTemplate, ulPublicKeyAttributeCount,
								  l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
							   	  l_phPublicKey, l_phPrivateKey,
								  ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
        *phPublicKey = hPublicKey;
        *phPrivateKey = hPrivateKey;
        return rv;
	}
#endif // Unsupported by Crypto API Toolkit

	// Generate EDDSA keys
	if (l_pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN)
	{
        rv = this->generateED(hSession,
							    l_pPublicKeyTemplate, ulPublicKeyAttributeCount,
							    l_pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
							    l_phPublicKey, l_phPrivateKey,
							    ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
        *phPublicKey = hPublicKey;
        *phPrivateKey = hPrivateKey;
        return rv;
	}

	return CKR_GENERAL_ERROR;
}

// Internal: Wrap blob using symmetric key
CK_RV SoftHSM::WrapKeySym
(
	CK_MECHANISM_PTR pMechanism,
	Token* token,
	OSObject* wrapKey,
	ByteString& keydata,
	ByteString& wrapped
)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;
#ifdef HAVE_AES_KEY_WRAP
	CK_ULONG wrappedlen = keydata.size();

	// [PKCS#11 v2.40, 2.14.3 AES Key Wrap]
	// A key whose length is not a multiple of the AES Key Wrap block
	// size (8 bytes) will be zero padded to fit.
	CK_ULONG alignment = wrappedlen % 8;
	if (alignment != 0)
	{
		keydata.resize(wrappedlen + 8 - alignment);
		memset(&keydata[wrappedlen], 0, 8 - alignment);
		wrappedlen = keydata.size();
	}
#endif
	switch(pMechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			if ((wrappedlen < 16) || ((wrappedlen % 8) != 0))
				return CKR_KEY_SIZE_RANGE;
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* wrappingkey = new SymmetricKey();

	if (getSymmetricKey(wrappingkey, token, wrapKey) != CKR_OK)
	{
		cipher->recycleKey(wrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	wrappingkey->setBitLen(wrappingkey->getKeyBits().size() * bb);

	// Wrap the key
	if (!cipher->wrapKey(wrappingkey, mode, keydata, wrapped))
	{
		cipher->recycleKey(wrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	cipher->recycleKey(wrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return CKR_OK;
}

// Internal: Wrap blob using asymmetric key
CK_RV SoftHSM::WrapKeyAsym
(
	CK_MECHANISM_PTR pMechanism,
	Token* token,
	OSObject* wrapKey,
	ByteString& keydata,
	ByteString& wrapped
)
{
	const size_t bb = 8;
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mech = AsymMech::Unknown;

	CK_ULONG modulus_length;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			if (!wrapKey->attributeExists(CKA_MODULUS_BITS))
				return CKR_GENERAL_ERROR;
			modulus_length = wrapKey->getUnsignedLongValue(CKA_MODULUS_BITS, 0);
			// adjust key bit length
			modulus_length /= bb;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mech = AsymMech::RSA_PKCS;
			// RFC 3447 section 7.2.1
			if (keydata.size() > modulus_length - 11)
				return CKR_KEY_SIZE_RANGE;
			break;

		case CKM_RSA_PKCS_OAEP:
			mech = AsymMech::RSA_PKCS_OAEP;
			// SHA-1 is the only supported option
			// PKCS#11 2.40 draft 2 section 2.1.8: input length <= k-2-2hashLen
			if (keydata.size() > modulus_length - 2 - 2 * 160 / 8)
				return CKR_KEY_SIZE_RANGE;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* cipher = CryptoFactory::i()->getAsymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	PublicKey* publicKey = cipher->newPublicKey();
	if (publicKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (getRSAPublicKey((RSAPublicKey*)publicKey, token, wrapKey) != CKR_OK)
			{
				cipher->recyclePublicKey(publicKey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	// Wrap the key
	if (!cipher->wrapKey(publicKey, keydata, wrapped, mech))
	{
		cipher->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	cipher->recyclePublicKey(publicKey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);

	return CKR_OK;
}


// Wrap the specified key using the specified wrapping key and mechanism
CK_RV SoftHSM::C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulWrappedKeyLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pulWrappedKeyLen, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ULONG ulWrappedKeyLen = *pulWrappedKeyLen;
    auto l_pulWrappedKeyLen = &ulWrappedKeyLen;

	if (pWrappedKey && ulWrappedKeyLen)
	{
		if (!validate_user_check_ptr(pWrappedKey, ulWrappedKeyLen))
		{
			return CKR_DEVICE_MEMORY;
		}
	}

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	CK_RV rv;
	// Check the mechanism, only accept advanced AES key wrapping and RSA
	switch(l_pMechanism->mechanism)
	{
        case CKM_AES_CTR:
#ifdef WITH_AES_GCM
        case CKM_AES_GCM:
#endif
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY_INTERNAL:
            break;
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
#endif
		case CKM_RSA_PKCS:
			// Does not handle optional init vector
			if (l_pMechanism->pParameter != NULL_PTR ||
                l_pMechanism->ulParameterLen != 0)
			return CKR_ARGUMENTS_BAD;
			break;
		case CKM_RSA_PKCS_OAEP:
        {
            rv = MechParamCheckRSAPKCSOAEP(l_pMechanism);
            if (rv != CKR_OK)
            {
                return rv;
            }

            CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)l_pMechanism->pParameter;
            if (params->hashAlg != CKM_SHA_1 ||
                params->mgf != CKG_MGF1_SHA1)
            {
                return CKR_ARGUMENTS_BAD;
            }
            break;
	    }
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

    if(l_pMechanism->mechanism == CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY_INTERNAL)
    {
        // Wrapping key Id must be null for RSA quote + public key export
        if (hWrappingKey || !l_pulWrappedKeyLen)
        {
            return CKR_ARGUMENTS_BAD;
        }
#ifdef DCAP_SUPPORT
        OSObject *key = (OSObject *)handleManager->getObject(hKey);
        if (!key || !key->isValid())
        {
            return CKR_KEY_HANDLE_INVALID;
        }

        // If the key is used for quote generation it should not be used again
        CK_BBOOL isUsedForQuoteGeneration = key->getBooleanValue(CKA_USED_FOR_QUOTE_GENERATION, false);

        if(isUsedForQuoteGeneration)
        {
            return CKR_KEY_HANDLE_INVALID;
        }

        CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
        if (isKeyOnToken)
        {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        rv = exportQuoteWithRsaPublicKey(hSession,
                                         hKey,
                                         l_pMechanism,
                                         pWrappedKey,
                                         l_pulWrappedKeyLen);

        *pulWrappedKeyLen = ulWrappedKeyLen;

        if (pWrappedKey)
        {
            bool bOK = true;
            bOK = bOK && key->setAttribute(CKA_USED_FOR_QUOTE_GENERATION, true);
            if (!bOK)
            {
                memset_s(pWrappedKey, ulWrappedKeyLen, 0x00, ulWrappedKeyLen);
                rv = CKR_FUNCTION_FAILED;
                return rv;
            }

            bOK = bOK && key->setAttribute(CKA_USED_FOR_WRAPPING, true);
            if (!bOK)
            {
                memset_s(pWrappedKey, ulWrappedKeyLen, 0x00, ulWrappedKeyLen);
                rv = CKR_FUNCTION_FAILED;
                return rv;
            }

            CK_OBJECT_HANDLE privateKeyHandle = getRSAPairKey(hSession, hKey);
            if (CK_INVALID_HANDLE == privateKeyHandle)
            {
                memset_s(pWrappedKey, ulWrappedKeyLen, 0x00, ulWrappedKeyLen);
                return CKR_KEY_HANDLE_INVALID;
            }

            // Get the OS Object related to the private key
            OSObject *privateKey = (OSObject*)handleManager->getObject(privateKeyHandle);
            if (nullptr == privateKey || !privateKey->isValid())
            {
                memset_s(pWrappedKey, ulWrappedKeyLen, 0x00, ulWrappedKeyLen);
                return CKR_OBJECT_HANDLE_INVALID;
            }

            bOK = bOK && privateKey->setAttribute(CKA_USED_FOR_QUOTE_GENERATION, true);
            if (!bOK)
            {
                memset_s(pWrappedKey, ulWrappedKeyLen, 0x00, ulWrappedKeyLen);
                rv = CKR_FUNCTION_FAILED;
            }

            bOK = bOK && privateKey->setAttribute(CKA_USED_FOR_WRAPPING, true);
            if (!bOK)
            {
                memset_s(pWrappedKey, ulWrappedKeyLen, 0x00, ulWrappedKeyLen);
                rv = CKR_FUNCTION_FAILED;
            }
        }
#else
        rv = CKR_MECHANISM_INVALID;
#endif
    }
    else
    {
#ifdef DISABLE_TOKEN_KEY_WRAP
        // Fail wrapping a token key if public key hash is not embedded in build.
        OSObject *hKeyObject = (OSObject *)handleManager->getObject(hKey);
        if (hKeyObject == NULL_PTR || !hKeyObject->isValid())
        {
            return CKR_KEY_HANDLE_INVALID;
        }

        if (hKeyObject->getBooleanValue(CKA_TOKEN, false))
        {
            return CKR_ACTION_PROHIBITED;
        }
        else // Allow wrapping session key only when --enable-session-key-wrap is passed during build
        {
#ifndef SESSION_KEY_WRAP_SUPPORT
            return CKR_ACTION_PROHIBITED;
#endif
        }
#endif
        // Check the wrapping key handle.
        OSObject *wrapKey = (OSObject *)handleManager->getObject(hWrappingKey);
        if (wrapKey == NULL_PTR || !wrapKey->isValid()) return CKR_WRAPPING_KEY_HANDLE_INVALID;

        CK_BBOOL isWrapKeyOnToken = wrapKey->getBooleanValue(CKA_TOKEN, false);
        CK_BBOOL isWrapKeyPrivate = wrapKey->getBooleanValue(CKA_PRIVATE, true);

        if (isWrapKeyOnToken)
        {
            return CKR_WRAPPING_KEY_HANDLE_INVALID;
        }

#ifdef DCAP_SUPPORT
        // If the key is used for quote generation should not be used for wrapping
        CK_BBOOL isUsedForQuoteGeneration = wrapKey->getBooleanValue(CKA_USED_FOR_QUOTE_GENERATION, false);

        if(isUsedForQuoteGeneration)
        {
            return CKR_WRAPPING_KEY_HANDLE_INVALID;
        }
#endif
        // Check user credentials for the wrapping key
        rv = haveRead(session->getState(), isWrapKeyOnToken, isWrapKeyPrivate);
        if (rv != CKR_OK)
        {
            if (rv == CKR_USER_NOT_LOGGED_IN)
            {
                // INFO_MSG("User is not authorized");
            }

            return rv;
        }

        // Check wrapping key class and type
        if ((l_pMechanism->mechanism == CKM_AES_KEY_WRAP || l_pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if ((l_pMechanism->mechanism == CKM_RSA_PKCS || l_pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PUBLIC_KEY)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if (l_pMechanism->mechanism == CKM_AES_KEY_WRAP && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if (l_pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if ((l_pMechanism->mechanism == CKM_RSA_PKCS || l_pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if (l_pMechanism->mechanism == CKM_AES_CTR && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if (l_pMechanism->mechanism == CKM_AES_GCM && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if (l_pMechanism->mechanism == CKM_AES_CBC && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        if (l_pMechanism->mechanism == CKM_AES_CBC_PAD && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

        // Check if the wrapping key can be used for wrapping
        if (wrapKey->getBooleanValue(CKA_WRAP, false) == false)
            return CKR_KEY_FUNCTION_NOT_PERMITTED;

        // Check if the specified mechanism is allowed for the wrapping key
        if (!isMechanismPermitted(wrapKey, l_pMechanism))
            return CKR_MECHANISM_INVALID;

        // Check the to be wrapped key handle.
        OSObject *key = (OSObject *)handleManager->getObject(hKey);
        if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

        CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
        CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

        // Check user credentials for the to be wrapped key
        rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
        if (rv != CKR_OK)
        {
            if (rv == CKR_USER_NOT_LOGGED_IN)
            {
                // INFO_MSG("User is not authorized");
            }

            return rv;
        }

        // Check if the to be wrapped key can be wrapped
        if (key->getBooleanValue(CKA_EXTRACTABLE, false) == false)
            return CKR_KEY_UNEXTRACTABLE;
        if (key->getBooleanValue(CKA_WRAP_WITH_TRUSTED, false) && wrapKey->getBooleanValue(CKA_TRUSTED, false) == false)
            return CKR_KEY_NOT_WRAPPABLE;

        // Check the class
        CK_OBJECT_CLASS keyClass = key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
        if (keyClass != CKO_SECRET_KEY && keyClass != CKO_PRIVATE_KEY)
            return CKR_KEY_NOT_WRAPPABLE;
        // CKM_RSA_PKCS and CKM_RSA_PKCS_OAEP can be used only on SECRET keys: PKCS#11 2.40 draft 2 section 2.1.6 PKCS #1 v1.5 RSA & section 2.1.8 PKCS #1 RSA OAEP
        if ((l_pMechanism->mechanism == CKM_RSA_PKCS || l_pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && keyClass != CKO_SECRET_KEY)
            return CKR_KEY_NOT_WRAPPABLE;

        // Verify the wrap template attribute
        if (wrapKey->attributeExists(CKA_WRAP_TEMPLATE))
        {
            OSAttribute attr = wrapKey->getAttribute(CKA_WRAP_TEMPLATE);

            if (attr.isAttributeMapAttribute())
            {
                typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

                const attrmap_type& map = attr.getAttributeMapValue();

                for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
                {
                    if (!key->attributeExists(it->first))
                    {
                        return CKR_KEY_NOT_WRAPPABLE;
                    }

                    OSAttribute keyAttr = key->getAttribute(it->first);
                    ByteString v1, v2;
                    if (!keyAttr.peekValue(v1) || !it->second.peekValue(v2) || (v1 != v2))
                    {
                        return CKR_KEY_NOT_WRAPPABLE;
                    }
                }
            }
        }

        // Get the key data to encrypt
        ByteString keydata;
        if (keyClass == CKO_SECRET_KEY)
        {
            if (isKeyPrivate)
            {
                bool bOK = token->decrypt(key->getByteStringValue(CKA_VALUE), keydata);
                if (!bOK) return CKR_GENERAL_ERROR;
            }
            else
            {
                keydata = key->getByteStringValue(CKA_VALUE);
            }
        }
        else
        {
            CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
            AsymAlgo::Type alg = AsymAlgo::Unknown;
            switch (keyType) {
                case CKK_RSA:
                    alg = AsymAlgo::RSA;
                    break;
#if 0 // Unsupported by Crypto API Toolkit
                case CKK_DSA:
                    alg = AsymAlgo::DSA;
                    break;
                case CKK_DH:
                    alg = AsymAlgo::DH;
                    break;
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
                case CKK_EC:
                    // can be ecdh too but it doesn't matter
                    alg = AsymAlgo::ECDSA;
                    break;
#endif
#ifdef WITH_EDDSA
                // Not yet
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
                case CKK_GOSTR3410:
                    alg = AsymAlgo::GOST;
                    break;
#endif
#endif // Unsupported by Crypto API Toolkit
                default:
                    return CKR_KEY_NOT_WRAPPABLE;
            }
            AsymmetricAlgorithm* asymCrypto = NULL;
            PrivateKey* privateKey = NULL;
            asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(alg);
            if (asymCrypto == NULL)
                return CKR_GENERAL_ERROR;
            privateKey = asymCrypto->newPrivateKey();
            if (privateKey == NULL)
            {
                CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
                return CKR_HOST_MEMORY;
            }
            switch (keyType) {
                case CKK_RSA:
                    rv = getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key);
                    break;
#if 0 //Unsupported Crypto API Toolkit
                case CKK_DSA:
                    rv = getDSAPrivateKey((DSAPrivateKey*)privateKey, token, key);
                    break;
                case CKK_DH:
                    rv = getDHPrivateKey((DHPrivateKey*)privateKey, token, key);
                    break;
#endif //Unsupported Crypto API Toolkit
#ifdef WITH_ECC
                case CKK_EC:
                    rv = getECPrivateKey((ECPrivateKey*)privateKey, token, key);
                    break;
#endif
#if 0 //Unsupported Crypto API Toolkit
#ifdef WITH_GOST
                case CKK_GOSTR3410:
                    rv = getGOSTPrivateKey((GOSTPrivateKey*)privateKey, token, key);
                    break;
#endif
#endif //Unsupported Crypto API Toolkit
            }
            if (rv != CKR_OK)
            {
                asymCrypto->recyclePrivateKey(privateKey);
                CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
                return CKR_GENERAL_ERROR;
            }
            keydata = privateKey->PKCS8Encode();
            asymCrypto->recyclePrivateKey(privateKey);
            CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
        }
        if (keydata.size() == 0)
            return CKR_KEY_NOT_WRAPPABLE;

        keyClass = wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
#ifdef SGXHSM
        if (keyClass == CKO_SECRET_KEY                  &&
            (l_pMechanism->mechanism  == CKM_AES_CTR      ||
             l_pMechanism->mechanism  == CKM_AES_GCM      ||
             l_pMechanism->mechanism  == CKM_AES_CBC      ||
             l_pMechanism->mechanism  == CKM_AES_CBC_PAD))
        {
            if (!pWrappedKey)
            {
                rv = SoftHSM::SymEncryptInit(hSession, l_pMechanism, hWrappingKey);
                if (rv != CKR_OK)
                {
                    session->resetOp();
                    return rv;
                }

                rv = SymEncrypt(session, (CK_BYTE_PTR) keydata.const_byte_str(), keydata.size(), NULL_PTR, l_pulWrappedKeyLen);

                session->resetOp();

                *pulWrappedKeyLen = ulWrappedKeyLen;

                return rv;
            }

            rv = SoftHSM::SymEncryptInit(hSession, l_pMechanism, hWrappingKey);
            if (rv != CKR_OK)
            {
                session->resetOp();
                return rv;
            }

            rv = SymEncrypt(session, (CK_BYTE_PTR) keydata.const_byte_str(), keydata.size(), pWrappedKey, l_pulWrappedKeyLen);
            if (rv != CKR_OK)
            {
                session->resetOp();
            }

            wrapKey->setAttribute(CKA_USED_FOR_WRAPPING, true);
        }
        else
        {
#endif
            ByteString wrapped;
            if (keyClass == CKO_SECRET_KEY)
            {
                rv = SoftHSM::WrapKeySym(l_pMechanism, token, wrapKey, keydata, wrapped);
            }
            else
            {
                rv = SoftHSM::WrapKeyAsym(l_pMechanism, token, wrapKey, keydata, wrapped);
#ifdef SGXHSM
                if (rv == CKR_OK)
                {
                    if (wrapKey->startTransaction())
                    {
                        bool bOK = true;
                        bOK = bOK && wrapKey->setAttribute(CKA_USED_FOR_WRAPPING, true);

                        if (bOK)
                        {
                            bOK = wrapKey->commitTransaction();
                        }
                        else
                        {
                            wrapKey->abortTransaction();
                            wrapped.wipe();
                            rv = CKR_FUNCTION_FAILED;
                            return rv;
                        }
                    }

                    CK_ULONG pairKeyId = wrapKey->getUnsignedLongValue(CKA_ASYMMETRIC_PAIR_ID, 0);

                    if (pairKeyId != 0)
                    {
                        CK_ATTRIBUTE pTemplate[] = { { CKA_ASYMMETRIC_PAIR_ID, &pairKeyId, sizeof(pairKeyId) },
                                                   };

                        rv = FindObjectsInit(hSession, &pTemplate[0], 1);
                        if (rv != CKR_OK)
                        {
                            wrapped.wipe();
                            return rv;
                        }

                        CK_OBJECT_HANDLE hObjects[2];
                        CK_ULONG ulObjectCount = 0;

                        //Finding corresponding private key handle having same pair key id
                        //Only two objects (RSA public key and corresponding private key)
                        //are having same pair id key which is generated randomly
                        rv = FindObjects(hSession, &hObjects[0], 2, &ulObjectCount);
                        if (rv != CKR_OK)
                        {
                            wrapped.wipe();
                            return rv;
                        }

                        if (ulObjectCount != 2)
                        {
                            wrapped.wipe();
                            rv = CKR_FUNCTION_FAILED;
                            return rv;
                        }

                        CK_OBJECT_HANDLE privateKeyHandle = CK_INVALID_HANDLE;

                        for (CK_ULONG i = 0 ; i < ulObjectCount ; i++)
                        {
                            if (hObjects[i] != hWrappingKey)
                            {
                                privateKeyHandle = hObjects[i];
                                break;
                            }
                        }

                        if (CK_INVALID_HANDLE == privateKeyHandle)
                        {
                            wrapped.wipe();
                            return CKR_KEY_HANDLE_INVALID;
                        }

                        // Get the OS Object related to the private key
                        OSObject *privateKey = (OSObject*)handleManager->getObject(privateKeyHandle);
                        rv = C_FindObjectsFinal(hSession);
                        if (privateKey == NULL_PTR || !privateKey->isValid())
                        {
                            wrapped.wipe();
                            return CKR_OBJECT_HANDLE_INVALID;
                        }

                        if (privateKey->startTransaction())
                        {
                            bool bOK = true;
                            bOK = bOK && privateKey->setAttribute(CKA_USED_FOR_WRAPPING, true);

                            if (bOK)
                            {
                                bOK = privateKey->commitTransaction();
                            }
                            else
                            {
                                privateKey->abortTransaction();
                            }

                            if (!bOK)
                            {
                                wrapped.wipe();
                                rv = CKR_FUNCTION_FAILED;
                            }
                        }
                    }
                }
#endif
            }

            if (rv != CKR_OK)
            {
                wrapped.wipe();
                return rv;
            }

            if (pWrappedKey != NULL)
            {
                if (ulWrappedKeyLen >= wrapped.size())
                {
                    memcpy_s(pWrappedKey, ulWrappedKeyLen, wrapped.byte_str(), wrapped.size());
                }
                else
                {
                    rv = CKR_BUFFER_TOO_SMALL;
                }
            }

            *pulWrappedKeyLen = wrapped.size();
#ifdef SGXHSM
        }
#endif
    }

    return rv;
}

// Internal: Unwrap blob using symmetric key
CK_RV SoftHSM::UnwrapKeySym
(
	CK_MECHANISM_PTR pMechanism,
	ByteString& wrapped,
	Token* token,
	OSObject* unwrapKey,
	ByteString& keydata
)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* unwrappingkey = new SymmetricKey();

	if (getSymmetricKey(unwrappingkey, token, unwrapKey) != CKR_OK)
	{
		cipher->recycleKey(unwrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	unwrappingkey->setBitLen(unwrappingkey->getKeyBits().size() * bb);

	// Unwrap the key
	CK_RV rv = CKR_OK;
	if (!cipher->unwrapKey(unwrappingkey, mode, wrapped, keydata))
		rv = CKR_GENERAL_ERROR;
	cipher->recycleKey(unwrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return rv;
}

// Internal: Unwrap blob using asymmetric key
CK_RV SoftHSM::UnwrapKeyAsym
(
	CK_MECHANISM_PTR pMechanism,
	ByteString& wrapped,
	Token* token,
	OSObject* unwrapKey,
	ByteString& keydata,
    const CK_MECHANISM_TYPE hashAlgo
)
{
	// Get the symmetric algorithm matching the mechanism
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mode = AsymMech::Unknown;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS;
			break;

		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS_OAEP;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	AsymmetricAlgorithm* cipher = CryptoFactory::i()->getAsymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	PrivateKey* unwrappingkey = cipher->newPrivateKey();
	if (unwrappingkey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (getRSAPrivateKey((RSAPrivateKey*)unwrappingkey, token, unwrapKey) != CKR_OK)
			{
				cipher->recyclePrivateKey(unwrappingkey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	// Unwrap the key
	CK_RV rv = CKR_OK;
    if (!cipher->unwrapKey(unwrappingkey, wrapped, keydata, mode, hashAlgo))
		rv = CKR_GENERAL_ERROR;
	cipher->recyclePrivateKey(unwrappingkey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
	return rv;
}

#ifndef DISABLE_TOKEN_KEY_WRAP
static std::string getDigest(const ByteString& dataToHash)
{
    std::string digest;
    ByteString hash;
    HashAlgorithm* hashAlgo = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA384);

    if (hashAlgo &&
        hashAlgo->hashInit() &&
        hashAlgo->hashUpdate(dataToHash) &&
        hashAlgo->hashFinal(hash))
    {
        char hex[3];
        for (size_t i = 0; i < hash.size(); i++)
        {
            snprintf(hex, 3, "%02x", hash[i]);
            digest += hex;
        }
    }

    CryptoFactory::i()->recycleHashAlgorithm(hashAlgo);
    return digest;
}

static CK_RV verifyRsaPublicKeyDigest(const ByteString& modulus, ByteString& exponent)
{
    ByteString hexExponent;
    char hex[3];

    for (size_t i = 0; i < exponent.size(); i++)
    {
        snprintf(hex, 3, "%02x", exponent[i]);
        hexExponent += hex[0];
        hexExponent += hex[1];
    }

    // Trim initial zero if present.
    if (hexExponent[0] == '0')
    {
        hexExponent = hexExponent.substr(1,hexExponent.size());
    }

    ByteString dataToHash = modulus + hexExponent;
    std::string hexDigest = getDigest(dataToHash);
    if (hexDigest.empty())
    {
        return CKR_GENERAL_ERROR;
    }

    std::string hashFromBuild{PUBKEY_HASH};
    if (hexDigest != hashFromBuild)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV verifySignature(const ByteString& modulus,
                             const ByteString& exponent,
                             const ByteString& wrappedKey,
                             const ByteString& signature,
                             const size_t&     pssParamsLen)
{
    RSA_PKCS_PSS_PARAMS pssParam{HashAlgo::SHA384, AsymRSAMGF::MGF1_SHA384, pssParamsLen};
    void* param     = &pssParam;
    size_t paramLen = sizeof(pssParam);
    AsymMech::Type mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
    PublicKey* publicKey;

    AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
    if (!rsa)
    {
        return CKR_GENERAL_ERROR;
    }

    ByteString serialisedPublicKey = modulus.serialise() + exponent.serialise();
    if (!rsa->reconstructPublicKey(&publicKey, serialisedPublicKey))
    {
        rsa->recyclePublicKey(publicKey);
        CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
        return CKR_ARGUMENTS_BAD;
    }

    if (!publicKey)
    {
        CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
        return CKR_GENERAL_ERROR;
    }

    if (!rsa->verifyInit(publicKey, mechanism, param, paramLen))
    {
        rsa->recyclePublicKey(publicKey);
        CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
        return CKR_MECHANISM_INVALID;
    }

    if (!rsa->verifyUpdate(wrappedKey) ||
        !rsa->verifyFinal(signature))
    {
        rsa->recyclePublicKey(publicKey);
        CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
        return CKR_SIGNATURE_INVALID;
    }

    rsa->recyclePublicKey(publicKey);
    CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

    return CKR_OK;
}

static inline bool validateUnwrapParams(const CK_UNWRAP_KEY_PARAMS params, const CK_ULONG& ulDataLen)
{
    const CK_ULONG modulusLenAllowed = 384, minLength = 0xFF, maxLength = 0xFFFF;

    if (ulDataLen < minLength || ulDataLen > maxLength ||
        !params.pMechanism ||
        !params.pMechanism->pParameter ||
        params.pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
        params.pMechanism->mechanism != CKM_SHA384_RSA_PKCS_PSS ||
        CK_RSA_PKCS_PSS_PARAMS_PTR(params.pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
        CK_RSA_PKCS_PSS_PARAMS_PTR(params.pMechanism->pParameter)->mgf != CKG_MGF1_SHA384 ||
        params.modulusLen != modulusLenAllowed ||
        params.exponentLen > maxLength||
        params.signatureLen > maxLength ||
        params.wrappedKeyLen > maxLength)
    {
        return false;
    }

    return true;
}

static bool extractSignatureIngredients(const CK_BYTE_PTR pData,
                                        const CK_ULONG&   ulDataLen,
                                        ByteString&       modulus,
                                        ByteString&       exponent,
                                        ByteString&       signature,
                                        ByteString&       wrappedKey,
                                        size_t&           pssParamsLen)
{
    CK_UNWRAP_KEY_PARAMS params;
    size_t paramsLen = sizeof(params);

    memcpy_s(&params, paramsLen, pData, paramsLen);
    if (!validateUnwrapParams(params, ulDataLen))
    {
        return false;
    }

    pssParamsLen = CK_RSA_PKCS_PSS_PARAMS_PTR(params.pMechanism->pParameter)->sLen;

    modulus.resize(params.modulusLen);
    exponent.resize(params.exponentLen);
    signature.resize(params.signatureLen);
    wrappedKey.resize(params.wrappedKeyLen);

    CK_ULONG offset = paramsLen;
    memcpy_s(modulus.byte_str(), modulus.size(), pData + offset, params.modulusLen);
    offset += params.modulusLen;
    memcpy_s(exponent.byte_str(), exponent.size(), pData + offset, params.exponentLen);
    offset += params.exponentLen;
    memcpy_s(signature.byte_str(), signature.size(), pData + offset, params.signatureLen);
    offset += params.signatureLen;
    memcpy_s(wrappedKey.byte_str(), wrappedKey.size(), pData + offset, params.wrappedKeyLen);

    return true;
}

static CK_RV verifyAndExtractWrappedKey(const CK_BYTE_PTR pData, const CK_ULONG& ulDataLen, ByteString& wrappedKey)
{
    ByteString modulus, exponent, signature;
    size_t pssParamsLen;

    if(!extractSignatureIngredients(pData, ulDataLen, modulus, exponent, signature, wrappedKey, pssParamsLen))
    {
        return CKR_ARGUMENTS_BAD;
    }

    // Verify digest
    CK_RV rv = verifyRsaPublicKeyDigest(modulus, exponent);
    if (CKR_OK != rv)
    {
        return rv;
    }

    // Verify signature
    return verifySignature(modulus, exponent, wrappedKey, signature, pssParamsLen);
}
#endif

// Unwrap the specified key using the specified unwrapping key
CK_RV SoftHSM::C_UnwrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR hKey
)
{
    CK_OBJECT_HANDLE lhKey;
    auto l_hKey = &lhKey;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pWrappedKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
    if (ulWrappedKeyLen == 0) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (hKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (!validate_user_check_ptr(pWrappedKey, ulWrappedKeyLen))
    {
        return CKR_DEVICE_MEMORY;
    }

    if (ulCount > CKA_MAX_ATTRIBUTES)
    {
        return CKR_ARGUMENTS_BAD;
    }

	if (!validate_user_check_attribute_ptr(pTemplate, ulCount))
	{
		return CKR_DEVICE_MEMORY;
	}

    if (!validate_user_check_ptr(hKey, sizeof(CK_ULONG)))
    {
        return CKR_DEVICE_MEMORY;
    }

    CK_ATTRIBUTE l_template[ulCount];
    memcpy_s(l_template, ulCount * sizeof(CK_ATTRIBUTE), pTemplate, ulCount * sizeof(CK_ATTRIBUTE));

    std::vector<std::vector<CK_BYTE>> value(ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        if (l_template[i].pValue == nullptr)
        {
            continue;
        }

        auto ulValueLen = l_template[i].ulValueLen;
        if (!validate_user_check_ptr(l_template[i].pValue, ulValueLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        value[i].resize(ulValueLen);
        memcpy_s(value[i].data(), ulValueLen, l_template[i].pValue, ulValueLen);
        l_template[i].pValue = value[i].data();
    }

    auto l_pTemplate = l_template;

	if (!validate_user_check_mechanism_ptr(pMechanism, 1))
	{
		return CKR_DEVICE_MEMORY;
	}

    CK_MECHANISM l_mechanism;
    memcpy_s(&l_mechanism, sizeof(CK_MECHANISM), pMechanism, sizeof(CK_MECHANISM));

    auto ulParameterLen = l_mechanism.ulParameterLen;

    if (ulParameterLen > CKM_MAX_PARAMETER_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE parameter[ulParameterLen];
    if (l_mechanism.pParameter != nullptr)
    {
        if (!validate_user_check_ptr(l_mechanism.pParameter, ulParameterLen))
        {
            return CKR_DEVICE_MEMORY;
        }

        memcpy_s(&parameter[0], ulParameterLen, l_mechanism.pParameter, ulParameterLen);
        l_mechanism.pParameter = &parameter[0];
    }
    auto l_pMechanism = &l_mechanism;

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

    ByteString wrappedKey;
	CK_RV rv = CKR_GENERAL_ERROR;
#ifdef DISABLE_TOKEN_KEY_WRAP
    wrappedKey.resize(ulWrappedKeyLen);
    memcpy_s(wrappedKey.byte_str(), wrappedKey.size(), pWrappedKey, ulWrappedKeyLen);
#else
    rv = verifyAndExtractWrappedKey(pWrappedKey, ulWrappedKeyLen, wrappedKey);
    if (rv != CKR_OK)
    {
        return rv;
    }
#endif

    CK_ULONG wrappedKeyLen = wrappedKey.size();

	// Check the mechanism
	switch(l_pMechanism->mechanism)
	{
        case CKM_AES_CTR:
#ifdef WITH_AES_GCM		
        case CKM_AES_GCM:
#endif
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD: 
            break;
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			if ((wrappedKeyLen < 24) || ((wrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (l_pMechanism->pParameter != NULL_PTR ||
                l_pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			if ((wrappedKeyLen < 16) || ((wrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (l_pMechanism->pParameter != NULL_PTR ||
                l_pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
		case CKM_RSA_PKCS:
			// Input length checks needs to be done later when unwrapping key is known
			break;
		case CKM_RSA_PKCS_OAEP:
            {
                rv = MechParamCheckRSAPKCSOAEP(l_pMechanism, CK_TRUE);
                if (rv != CKR_OK)
                {
                    return rv;
                }

                CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)l_pMechanism->pParameter;
                CK_MECHANISM_TYPE hashAlgo = params->hashAlg;
                CK_RSA_PKCS_MGF_TYPE mgf = params->mgf;
                CK_RSA_PKCS_MGF_TYPE allowedMgf;

                switch (hashAlgo)
                {
                    case CKM_SHA_1:
                        allowedMgf = CKG_MGF1_SHA1;
                        break;
                    case CKM_SHA256:
                        allowedMgf = CKG_MGF1_SHA256;
                        break;
                    case CKM_SHA384:
                        allowedMgf = CKG_MGF1_SHA384;
                        break;
                    default:
                        return CKR_ARGUMENTS_BAD;
                }

                if (mgf != allowedMgf)
                {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
            }
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the unwrapping key handle.
	OSObject *unwrapKey = (OSObject *)handleManager->getObject(hUnwrappingKey);
	if (unwrapKey == NULL_PTR || !unwrapKey->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isUnwrapKeyOnToken = unwrapKey->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isUnwrapKeyPrivate = unwrapKey->getBooleanValue(CKA_PRIVATE, true);

    if (isUnwrapKeyOnToken)
    {
        return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    }
	// Check user credentials
	rv = haveRead(session->getState(), isUnwrapKeyOnToken, isUnwrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check unwrapping key class and type
	if ((l_pMechanism->mechanism == CKM_AES_KEY_WRAP || l_pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_KEY_WRAP && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((l_pMechanism->mechanism == CKM_RSA_PKCS || l_pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((l_pMechanism->mechanism == CKM_RSA_PKCS || l_pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_CTR && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_GCM && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_CBC && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (l_pMechanism->mechanism == CKM_AES_CBC_PAD && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

	// Check if the unwrapping key can be used for unwrapping
	if (unwrapKey->getBooleanValue(CKA_UNWRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the unwrap key
	if (!isMechanismPermitted(unwrapKey, l_pMechanism))
		return CKR_MECHANISM_INVALID;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = false;
	rv = extractObjectInformation(l_pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		// ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	// Key type will be handled at object creation

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

	// Build unwrapped key template
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (l_pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = l_pTemplate[i];
		}
	}

	// Apply the unwrap template
	if (unwrapKey->attributeExists(CKA_UNWRAP_TEMPLATE))
	{
		OSAttribute unwrapAttr = unwrapKey->getAttribute(CKA_UNWRAP_TEMPLATE);

		if (unwrapAttr.isAttributeMapAttribute())
		{
			typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

			const attrmap_type& map = unwrapAttr.getAttributeMapValue();

			for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
			{
				CK_ATTRIBUTE* attr = NULL;
				for (CK_ULONG i = 0; i < secretAttribsCount; ++i)
				{
					if (it->first == secretAttribs[i].type)
					{
						if (attr != NULL)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						attr = &secretAttribs[i];
						ByteString value;
						it->second.peekValue(value);
						if (attr->ulValueLen != value.size())
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						if (memcmp(attr->pValue, value.const_byte_str(), value.size()) != 0)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
					}
				}
				if (attr == NULL)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
			}
		}
	}

	lhKey = CK_INVALID_HANDLE;

	// Unwrap the key
	ByteString keydata;
    if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_SECRET_KEY &&
        (l_pMechanism->mechanism  == CKM_AES_CTR    ||
         l_pMechanism->mechanism  == CKM_AES_GCM    ||
         l_pMechanism->mechanism  == CKM_AES_CBC    ||
         l_pMechanism->mechanism  == CKM_AES_CBC_PAD))
    
    {
        rv = SoftHSM::SymDecryptInit(hSession, l_pMechanism, hUnwrappingKey);
        if (rv != CKR_OK)
        {
            return rv;
        }

        CK_ULONG ulDataLen = 0;
        rv = SymDecrypt(session, wrappedKey.byte_str(), wrappedKeyLen, NULL_PTR, &ulDataLen);
        if (rv != CKR_OK)
        {
            return rv;
        }

        keydata.resize(ulDataLen);
        rv = SymDecrypt(session, wrappedKey.byte_str(), wrappedKeyLen, keydata.byte_str(), &ulDataLen);
        if (rv != CKR_OK)
        {
            return rv;
        }

        keydata.resize(ulDataLen);
    }
    else
    {
        ByteString wrapped(wrappedKey.byte_str(), wrappedKeyLen);
        if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_SECRET_KEY)
        {	 
            rv = UnwrapKeySym(l_pMechanism, wrapped, token, unwrapKey, keydata);
        }
        else if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_PRIVATE_KEY)
        {
            CK_MECHANISM_TYPE hashAlgo = CKM_SHA_1;
            if (CKM_RSA_PKCS_OAEP == l_mechanism.mechanism)
            {
                CK_RSA_PKCS_OAEP_PARAMS_PTR param = (CK_RSA_PKCS_OAEP_PARAMS_PTR)parameter;
                hashAlgo = param->hashAlg;
            }

            rv = UnwrapKeyAsym(l_pMechanism, wrapped, token, unwrapKey, keydata, hashAlgo);
#ifdef DCAP_SUPPORT
            if (CKR_OK == rv)
            {
                // If the key is used for quote generation should be used for only one unwrap operation
                // Destroying the public key from session
                CK_BBOOL isUsedForQuoteGeneration = unwrapKey->getBooleanValue(CKA_USED_FOR_QUOTE_GENERATION, false);

                if (isUsedForQuoteGeneration)
                {
                    // get public key
                    CK_OBJECT_HANDLE publicKeyHandle = getRSAPairKey(hSession, hUnwrappingKey);
                    if (CK_INVALID_HANDLE == publicKeyHandle)
                    {
                        return CKR_KEY_HANDLE_INVALID;
                    }

                    // destroying public key
                    C_DestroyObject(hSession, publicKeyHandle);
                }
            }
#endif
        }
        else
        {
            rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
        }
    }

	if (rv != CKR_OK)
    {
		return rv;
    }

	// Create the secret object using C_CreateObject
	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, l_hKey, OBJECT_OP_UNWRAP);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(lhKey);
		if (osobject == NULL_PTR || !osobject->isValid())
        {
            return CKR_FUNCTION_FAILED;
        }
		if (osobject->startTransaction())
		{
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);

			// Common Secret Key Attributes
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

			// Secret Attributes
			if (objClass == CKO_SECRET_KEY)
			{
				ByteString value;
				if (isPrivate)
					token->encrypt(keydata, value);
				else
					value = keydata;
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			}
			else if (keyType == CKK_RSA)
			{
				bOK = bOK && setRSAPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#if 0 // Unsupported by Crypto API Toolkit
			else if (keyType == CKK_DSA)
			{
				bOK = bOK && setDSAPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
			else if (keyType == CKK_DH)
			{
				bOK = bOK && setDHPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif // Unsupported by Crypto API Toolkit
#ifdef WITH_ECC
			else if (keyType == CKK_EC)
			{
				bOK = bOK && setECPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
#if 0 // Unsupported by Crypto API Toolkit
#ifdef WITH_GOST
			else if (keyType == CKK_GOSTR3410)
			{
				bOK = bOK && setGOSTPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
#endif // Unsupported by Crypto API Toolkit
			else
				bOK = false;

			if (bOK)
            {
				bOK = osobject->commitTransaction();
            }
			else
            {
				osobject->abortTransaction();
            }

			if (!bOK)
            {
				rv = CKR_FUNCTION_FAILED;
            }
		}
		else
        {
			rv = CKR_FUNCTION_FAILED;
        }
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (lhKey != CK_INVALID_HANDLE)
		{
			OSObject* obj = (OSObject*)handleManager->getObject(lhKey);
			handleManager->destroyObject(lhKey);
			if (obj) obj->destroyObject();
			lhKey = CK_INVALID_HANDLE;
		}
	}
    else
    {
        // Destroy the key used for unwrapping.
        C_DestroyObject(hSession, hUnwrappingKey);
    }

    *hKey = lhKey;

	return rv;
}

// Derive a key from the specified base key
CK_RV SoftHSM::C_DeriveKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
)
{
#if 0 // Unsupported by Crypto API Toolkit
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DH and ECDH derive
	switch (pMechanism->mechanism)
	{
		case CKM_DH_PKCS_DERIVE:
#if defined(WITH_ECC) || defined(WITH_EDDSA)
		case CKM_ECDH1_DERIVE:
#endif
#ifndef WITH_FIPS
		case CKM_DES_ECB_ENCRYPT_DATA:
		case CKM_DES_CBC_ENCRYPT_DATA:
#endif
		case CKM_DES3_ECB_ENCRYPT_DATA:
		case CKM_DES3_CBC_ENCRYPT_DATA:
		case CKM_AES_ECB_ENCRYPT_DATA:
		case CKM_AES_CBC_ENCRYPT_DATA:
			break;

		default:
			// ERROR_MSG("Invalid mechanism");
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hBaseKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}

		return rv;
	}

	// Check if key can be used for derive
	if (!key->getBooleanValue(CKA_DERIVE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism))
		return CKR_MECHANISM_INVALID;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = false;
	rv = extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		// ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (keyType != CKK_GENERIC_SECRET &&
	    keyType != CKK_DES &&
	    keyType != CKK_DES2 &&
	    keyType != CKK_DES3 &&
	    keyType != CKK_AES)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

	// Derive DH secret
	if (pMechanism->mechanism == CKM_DH_PKCS_DERIVE)
	{
		// Check key class and type
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_DH)
			return CKR_KEY_TYPE_INCONSISTENT;

		return this->deriveDH(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
	}

#if defined(WITH_ECC) || defined(WITH_EDDSA)
	// Derive ECDH secret
	if (pMechanism->mechanism == CKM_ECDH1_DERIVE)
	{
		// Check key class and type
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
#ifdef WITH_ECC
		else if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC)
			return this->deriveECDH(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
#endif
#ifdef WITH_EDDSA
		else if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC_EDWARDS)
			return this->deriveEDDSA(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
#endif
		else
			return CKR_KEY_TYPE_INCONSISTENT;
	}
#endif

	// Derive symmetric secret
	if (pMechanism->mechanism == CKM_DES_ECB_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_DES_CBC_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_DES3_ECB_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_DES3_CBC_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA)
	{
		// Check key class and type
		CK_KEY_TYPE baseKeyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_DES_ECB_ENCRYPT_DATA &&
		    baseKeyType != CKK_DES)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_DES_CBC_ENCRYPT_DATA &&
		    baseKeyType != CKK_DES)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_DES3_ECB_ENCRYPT_DATA &&
		    baseKeyType != CKK_DES2 && baseKeyType != CKK_DES3)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_DES3_CBC_ENCRYPT_DATA &&
		    baseKeyType != CKK_DES2 && baseKeyType != CKK_DES3)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA &&
		    baseKeyType != CKK_AES)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA &&
		    baseKeyType != CKK_AES)
			return CKR_KEY_TYPE_INCONSISTENT;

		return this->deriveSymmetric(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
	}

	return CKR_MECHANISM_INVALID;
#else
    return CKR_FUNCTION_NOT_SUPPORTED;
#endif // Unsupported by Crypto API Toolkit
}

#if 0 // Unsupported by Crypto API Toolkit
// Seed the random number generator with new data
CK_RV SoftHSM::C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSeed == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	// Seed the RNG
	ByteString seed(pSeed, ulSeedLen);
	rng->seed(seed);
	return CKR_OK;
}
#endif // Unsupported by Crypto API Toolkit

// Generate the specified amount of random data
CK_RV SoftHSM::C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pRandomData == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (ulRandomLen)
	{
        if (ulRandomLen > CKM_MAX_CRYPTO_OP_INPUT_LEN)
        {
            return CKR_ARGUMENTS_BAD;
        }

        if (!validate_user_check_ptr(pRandomData, ulRandomLen))
        {
            return CKR_DEVICE_MEMORY;
        }
	}

#ifdef ENABLE_MITIGATION
    __builtin_ia32_lfence();
#endif

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	// Generate random data
	ByteString randomData;
	if (!rng->generateRandom(randomData, ulRandomLen)) return CKR_GENERAL_ERROR;

	// Return random data
	if (ulRandomLen != 0)
	{
        memcpy_s(pRandomData, ulRandomLen, randomData.byte_str(), ulRandomLen);
	}

	return CKR_OK;
}

#if 0 // Unsupported by Crypto API Toolkit
// Legacy function
CK_RV SoftHSM::C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_PARALLEL;
}

// Legacy function
CK_RV SoftHSM::C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_PARALLEL;
}

// Wait or poll for a slot event on the specified slot
CK_RV SoftHSM::C_WaitForSlotEvent(CK_FLAGS /*flags*/, CK_SLOT_ID_PTR /*pSlot*/, CK_VOID_PTR /*pReserved*/)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
#endif // Unsupported by Crypto API Toolkit

#if 0 // Unsupported by Crypto API Toolkit
CK_RV SoftHSM::generateGeneric
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		// INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Check keyLen
	if (keyLen < 1 || keyLen > 0x8000000)
	{
		// INFO_MSG("bad generic key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Generate the secret key
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	ByteString key;
	if (!rng->generateRandom(key, keyLen)) return CKR_GENERAL_ERROR;

        CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = pTemplate[i];
				break;
		}
	}

	if (rv == CKR_OK)
		rv = CreateObject(hSession, keyAttribs, keyAttribsCount, phKey, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_GENERIC_SECRET_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// Generic Secret Key Attributes
			ByteString value;
			ByteString kcv;
			SymmetricKey symKey;
			symKey.setKeyBits(key);
			symKey.setBitLen(keyLen);
			if (isPrivate)
			{
				token->encrypt(symKey.getKeyBits(), value);
				token->encrypt(symKey.getKeyCheckValue(), kcv);
			}
			else
			{
				value = symKey.getKeyBits();
				kcv = symKey.getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif // Unsupported by Crypto API Toolkit

// Generate an AES secret key
CK_RV SoftHSM::generateAES
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		// INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// keyLen must be 16, 24, or 32
	if (keyLen != 16 && keyLen != 24 && keyLen != 32)
	{
		// INFO_MSG("bad AES key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Generate the secret key
	AESKey* key = new AESKey(keyLen * 8);
	SymmetricAlgorithm* aes = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (aes == NULL)
	{
		// ERROR_MSG("Could not get SymmetricAlgorithm");
		delete key;
		return CKR_GENERAL_ERROR;
	}
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL)
	{
		// ERROR_MSG("Could not get RNG");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}
	if (!aes->generateKey(*key, rng))
	{
		// ERROR_MSG("Could not generate AES secret key");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_AES_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// AES Secret Key Attributes
			ByteString value;
			ByteString kcv;
			if (isPrivate)
			{
				token->encrypt(key->getKeyBits(), value);
				token->encrypt(key->getKeyCheckValue(), kcv);
			}
			else
			{
				value = key->getKeyBits();
				kcv = key->getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	aes->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(aes);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

#if 0 // Unsupported by Crypto API Toolkit

// Generate a DES secret key
CK_RV SoftHSM::generateDES
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Generate the secret key
	DESKey* key = new DESKey(56);
	SymmetricAlgorithm* des = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::DES);
	if (des == NULL)
	{
		// ERROR_MSG("Could not get SymmetricAlgorithm");
		delete key;
		return CKR_GENERAL_ERROR;
	}
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL)
	{
		// ERROR_MSG("Could not get RNG");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}
	if (!des->generateKey(*key, rng))
	{
		// ERROR_MSG("Could not generate DES secret key");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// DES Secret Key Attributes
			ByteString value;
			ByteString kcv;
			if (isPrivate)
			{
				token->encrypt(key->getKeyBits(), value);
				token->encrypt(key->getKeyCheckValue(), kcv);
			}
			else
			{
				value = key->getKeyBits();
				kcv = key->getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	des->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(des);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES2 secret key
CK_RV SoftHSM::generateDES2
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Generate the secret key
	DESKey* key = new DESKey(112);
	SymmetricAlgorithm* des = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::DES3);
	if (des == NULL)
	{
		// ERROR_MSG("Could not get SymmetricAlgorith");
		delete key;
		return CKR_GENERAL_ERROR;
	}
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL)
	{
		// ERROR_MSG("Could not get RNG");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}
	if (!des->generateKey(*key, rng))
	{
		// ERROR_MSG("Could not generate DES secret key");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES2;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES2_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// DES Secret Key Attributes
			ByteString value;
			ByteString kcv;
			if (isPrivate)
			{
				token->encrypt(key->getKeyBits(), value);
				token->encrypt(key->getKeyCheckValue(), kcv);
			}
			else
			{
				value = key->getKeyBits();
				kcv = key->getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	des->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(des);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES3 secret key
CK_RV SoftHSM::generateDES3
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Generate the secret key
	DESKey* key = new DESKey(168);
	SymmetricAlgorithm* des = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::DES3);
	if (des == NULL)
	{
		// ERROR_MSG("Could not get SymmetricAlgorithm");
		delete key;
		return CKR_GENERAL_ERROR;
	}
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL)
	{
		// ERROR_MSG("Could not get RNG");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}
	if (!des->generateKey(*key, rng))
	{
		// ERROR_MSG("Could not generate DES secret key");
		des->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(des);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES3;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES3_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// DES Secret Key Attributes
			ByteString value;
			ByteString kcv;
			if (isPrivate)
			{
				token->encrypt(key->getKeyBits(), value);
				token->encrypt(key->getKeyCheckValue(), kcv);
			}
			else
			{
				value = key->getKeyBits();
				kcv = key->getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	des->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(des);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif // Unsupported by Crypto API Toolkit

// Generate an RSA key pair
CK_RV SoftHSM::generateRSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate
)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: bitlen and public exponent
	size_t bitLen = 0;
	ByteString exponent("010001");
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_MODULUS_BITS:
				if (pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_MODULUS_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
				break;
			case CKA_PUBLIC_EXPONENT:
				exponent = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// CKA_MODULUS_BITS must be specified to be able to generate a key pair.
	if (bitLen == 0) {
		// INFO_MSG("Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	RSAParameters p;
	p.setE(exponent);
	p.setBitLength(bitLen);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa == NULL)
		return CKR_GENERAL_ERROR;
	if (!rsa->generateKeyPair(&kp, &p))
	{
		// ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return CKR_GENERAL_ERROR;
	}

	RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
	RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_RSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PUBLIC_EXPONENT:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// RSA Public Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getN(), modulus);
					token->encrypt(pub->getE(), publicExponent);
				}
				else
				{
					modulus = pub->getN();
					publicExponent = pub->getE();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_RSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// RSA Private Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				ByteString privateExponent;
				ByteString prime1;
				ByteString prime2;
				ByteString exponent1;
				ByteString exponent2;
				ByteString coefficient;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getN(), modulus);
					token->encrypt(priv->getE(), publicExponent);
					token->encrypt(priv->getD(), privateExponent);
					token->encrypt(priv->getP(), prime1);
					token->encrypt(priv->getQ(), prime2);
					token->encrypt(priv->getDP1(), exponent1);
					token->encrypt(priv->getDQ1(), exponent2);
					token->encrypt(priv->getPQ(), coefficient);
				}
				else
				{
					modulus = priv->getN();
					publicExponent = priv->getE();
					privateExponent = priv->getD();
					prime1 = priv->getP();
					prime2 = priv->getQ();
					exponent1 =  priv->getDP1();
					exponent2 = priv->getDQ1();
					coefficient = priv->getPQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_1, prime1);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_2, prime2);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_1,exponent1);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_2, exponent2);
				bOK = bOK && osobject->setAttribute(CKA_COEFFICIENT, coefficient);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	rsa->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

#if 0 // Unsupported by Crypto API Toolkit
// Generate a DSA key pair
CK_RV SoftHSM::generateDSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_PRIME:
				prime = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_SUBPRIME:
				subprime = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_BASE:
				generator = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (prime.size() == 0 || subprime.size() == 0 || generator.size() == 0) {
		// INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	DSAParameters p;
	p.setP(prime);
	p.setQ(subprime);
	p.setG(generator);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);
	if (dsa == NULL) return CKR_GENERAL_ERROR;
	if (!dsa->generateKeyPair(&kp, &p))
	{
		// ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return CKR_GENERAL_ERROR;
	}

	DSAPublicKey* pub = (DSAPublicKey*) kp->getPublicKey();
	DSAPrivateKey* priv = (DSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_DSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// DSA Public Key Attributes
				ByteString value;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getY(), value);
				}
				else
				{
					value = pub->getY();
				}
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_DSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// DSA Private Key Attributes
				ByteString bPrime;
				ByteString bSubprime;
				ByteString bGenerator;
				ByteString bValue;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getP(), bPrime);
					token->encrypt(priv->getQ(), bSubprime);
					token->encrypt(priv->getG(), bGenerator);
					token->encrypt(priv->getX(), bValue);
				}
				else
				{
					bPrime = priv->getP();
					bSubprime = priv->getQ();
					bGenerator = priv->getG();
					bValue = priv->getX();
				}
				bOK = bOK && osobject->setAttribute(CKA_PRIME, bPrime);
				bOK = bOK && osobject->setAttribute(CKA_SUBPRIME, bSubprime);
				bOK = bOK && osobject->setAttribute(CKA_BASE, bGenerator);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, bValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	dsa->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DSA domain parameter set
CK_RV SoftHSM::generateDSAParameters
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t bitLen = 0;
	size_t qLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_PRIME_BITS:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_SUB_PRIME_BITS:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_SUB_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				qLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_PRIME_BITS must be specified
	if (bitLen == 0)
	{
		// INFO_MSG("Missing CKA_PRIME_BITS in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// No real choice for CKA_SUB_PRIME_BITS
	if ((qLen != 0) &&
	    (((bitLen >= 2048) && (qLen != 256)) ||
	     ((bitLen < 2048) && (qLen != 160))))
	{
		// INFO_MSG("CKA_SUB_PRIME_BITS is ignored");
	}


	// Generate domain parameters
	AsymmetricParameters* p = NULL;
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);
	if (dsa == NULL) return CKR_GENERAL_ERROR;
	if (!dsa->generateParameters(&p, (void *)bitLen))
	{
		// ERROR_MSG("Could not generate parameters");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return CKR_GENERAL_ERROR;
	}

	DSAParameters* params = (DSAParameters*) p;

	CK_RV rv = CKR_OK;

	// Create the domain parameter object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_DOMAIN_PARAMETERS;
	CK_KEY_TYPE keyType = CKK_DSA;
	CK_ATTRIBUTE paramsAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG paramsAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - paramsAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			paramsAttribs[paramsAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, paramsAttribs, paramsAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_PARAMETER_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// DSA Domain Parameters Attributes
			ByteString prime;
			ByteString subprime;
			ByteString generator;
			if (isPrivate)
			{
				token->encrypt(params->getP(), prime);
				token->encrypt(params->getQ(), subprime);
				token->encrypt(params->getG(), generator);
			}
			else
			{
				prime = params->getP();
				subprime = params->getQ();
				generator = params->getG();
			}
			bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
			bOK = bOK && osobject->setAttribute(CKA_SUBPRIME, subprime);
			bOK = bOK && osobject->setAttribute(CKA_BASE, generator);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	dsa->recycleParameters(p);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	// Remove parameters that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* osparams = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (osparams) osparams->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif // Unsupported by Crypto API Toolkit

// Generate an EC key pair
CK_RV SoftHSM::generateEC
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		// INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		// ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	ECPublicKey* pub = (ECPublicKey*) kp->getPublicKey();
	ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_EC;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EC Public Key Attributes
				ByteString point;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getQ(), point);
				}
				else
				{
					point = pub->getQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, point);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EC Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getEC(), group);
					token->encrypt(priv->getD(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getD();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	ec->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate an EDDSA key pair
CK_RV SoftHSM::generateED
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		// INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		// ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	EDPublicKey* pub = (EDPublicKey*) kp->getPublicKey();
	EDPrivateKey* priv = (EDPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_EC_EDWARDS;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_EDWARDS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EDDSA Public Key Attributes
				ByteString value;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getA(), value);
				}
				else
				{
					value = pub->getA();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC_EDWARDS;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_EDWARDS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EDDSA Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getEC(), group);
					token->encrypt(priv->getK(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getK();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	ec->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

#if 0 // Unsupported by Crypto API Toolkit
// Generate a DH key pair
CK_RV SoftHSM::generateDH
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString prime;
	ByteString generator;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_PRIME:
				prime = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_BASE:
				generator = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (prime.size() == 0 || generator.size() == 0) {
		// INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Extract optional bit length
	size_t bitLen = 0;
	for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++)
	{
		switch (pPrivateKeyTemplate[i].type)
		{
			case CKA_VALUE_BITS:
				bitLen = *(CK_ULONG*)pPrivateKeyTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// Set the parameters
	DHParameters p;
	p.setP(prime);
	p.setG(generator);
	p.setXBitLength(bitLen);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH);
	if (dh == NULL) return CKR_GENERAL_ERROR;
	if (!dh->generateKeyPair(&kp, &p))
	{
		// ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	DHPublicKey* pub = (DHPublicKey*) kp->getPublicKey();
	DHPrivateKey* priv = (DHPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_DH;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// DH Public Key Attributes
				ByteString value;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getY(), value);
				}
				else
				{
					value = pub->getY();
				}
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_DH;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// DH Private Key Attributes
				ByteString bPrime;
				ByteString bGenerator;
				ByteString bValue;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getP(), bPrime);
					token->encrypt(priv->getG(), bGenerator);
					token->encrypt(priv->getX(), bValue);
				}
				else
				{
					bPrime = priv->getP();
					bGenerator = priv->getG();
					bValue = priv->getX();
				}
				bOK = bOK && osobject->setAttribute(CKA_PRIME, bPrime);
				bOK = bOK && osobject->setAttribute(CKA_BASE, bGenerator);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, bValue);

				if (bitLen == 0)
				{
					bOK = bOK && osobject->setAttribute(CKA_VALUE_BITS, (unsigned long)priv->getX().bits());
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	dh->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DH domain parameter set
CK_RV SoftHSM::generateDHParameters
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t bitLen = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_PRIME_BITS:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_PRIME_BITS must be specified
	if (bitLen == 0)
	{
		// INFO_MSG("Missing CKA_PRIME_BITS in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Generate domain parameters
	AsymmetricParameters* p = NULL;
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH);
	if (dh == NULL) return CKR_GENERAL_ERROR;
	if (!dh->generateParameters(&p, (void *)bitLen))
	{
		// ERROR_MSG("Could not generate parameters");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	DHParameters* params = (DHParameters*) p;

	CK_RV rv = CKR_OK;

	// Create the domain parameter object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_DOMAIN_PARAMETERS;
	CK_KEY_TYPE keyType = CKK_DH;
	CK_ATTRIBUTE paramsAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG paramsAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - paramsAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
		default:
			paramsAttribs[paramsAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, paramsAttribs, paramsAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_PARAMETER_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// DH Domain Parameters Attributes
			ByteString prime;
			ByteString generator;
			if (isPrivate)
			{
				token->encrypt(params->getP(), prime);
				token->encrypt(params->getG(), generator);
			}
			else
			{
				prime = params->getP();
				generator = params->getG();
			}
			bOK = bOK && osobject->setAttribute(CKA_PRIME, prime);
			bOK = bOK && osobject->setAttribute(CKA_BASE, generator);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	dh->recycleParameters(p);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	// Remove parameters that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* osparams = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (osparams) osparams->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a GOST key pair
CK_RV SoftHSM::generateGOST
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString param_3410;
	ByteString param_3411;
	ByteString param_28147;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_GOSTR3410_PARAMS:
				param_3410 = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_GOSTR3411_PARAMS:
				param_3411 = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			case CKA_GOST28147_PARAMS:
				param_28147 = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (param_3410.size() == 0 || param_3411.size() == 0) {
		// INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(param_3410);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* gost = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::GOST);
	if (gost == NULL) return CKR_GENERAL_ERROR;
	if (!gost->generateKeyPair(&kp, &p))
	{
		// ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
		return CKR_GENERAL_ERROR;
	}

	GOSTPublicKey* pub = (GOSTPublicKey*) kp->getPublicKey();
	GOSTPrivateKey* priv = (GOSTPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_GOSTR3410;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EC Public Key Attributes
				ByteString point;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getQ(), point);
				}
				else
				{
					point = pub->getQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_VALUE, point);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_GOSTR3410;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// GOST Private Key Attributes
				ByteString value;
				ByteString param_a;
				ByteString param_b;
				ByteString param_c;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getD(), value);
					token->encrypt(priv->getEC(), param_a);
					token->encrypt(param_3411, param_b);
					token->encrypt(param_28147, param_c);
				}
				else
				{
					value = priv->getD();
					param_a = priv->getEC();
					param_b = param_3411;
					param_c = param_28147;
				}
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
				bOK = bOK && osobject->setAttribute(CKA_GOSTR3410_PARAMS, param_a);
				bOK = bOK && osobject->setAttribute(CKA_GOSTR3411_PARAMS, param_b);
				bOK = bOK && osobject->setAttribute(CKA_GOST28147_PARAMS, param_c);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				  rv = CKR_FUNCTION_FAILED;
		}
	}

	// Clean up
	gost->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);

	// Remove keys that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}

		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Derive a DH secret
CK_RV SoftHSM::deriveDH
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if (pMechanism->pParameter == NULL_PTR) return CKR_MECHANISM_PARAM_INVALID;
	if (pMechanism->ulParameterLen == 0) return CKR_MECHANISM_PARAM_INVALID;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				// INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			if (byteLen == 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must be set");
				return CKR_TEMPLATE_INCOMPLETE;
			}
			break;
#ifndef WITH_FIPS
		case CKK_DES:
			if (byteLen != 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must not be set");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			byteLen = 8;
			break;
#endif
		case CKK_DES2:
			if (byteLen != 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must not be set");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			byteLen = 16;
			break;
		case CKK_DES3:
			if (byteLen != 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must not be set");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			byteLen = 24;
			break;
		case CKK_AES:
			if (byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the DH algorithm handler
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH);
	if (dh == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = dh->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_HOST_MEMORY;
	}
	if (getDHPrivateKey((DHPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		dh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	ByteString mechParameters;
	mechParameters.resize(pMechanism->ulParameterLen);
    memcpy_s(&mechParameters[0], pMechanism->ulParameterLen, pMechanism->pParameter, pMechanism->ulParameterLen);
	PublicKey* publicKey = dh->newPublicKey();
	if (publicKey == NULL)
	{
		dh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_HOST_MEMORY;
	}
	if (getDHPublicKey((DHPublicKey*)publicKey, (DHPrivateKey*)privateKey, mechParameters) != CKR_OK)
	{
		dh->recyclePrivateKey(privateKey);
		dh->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!dh->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	dh->recyclePrivateKey(privateKey);
	dh->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			if (byteLen > secretValue.size())
			{
				// INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Fix the odd parity for DES
				if (keyType == CKK_DES ||
				    keyType == CKK_DES2 ||
				    keyType == CKK_DES3)
				{
					for (size_t i = 0; i < secretValue.size(); i++)
					{
						secretValue[i] = odd_parity[secretValue[i]];
					}
				}

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_DES:
					case CKK_DES2:
					case CKK_DES3:
						secret->setBitLen(byteLen * 7);
						plainKCV = ((DESKey*)secret)->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	dh->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Derive an ECDH secret
#ifdef WITH_ECC
CK_RV SoftHSM::deriveECDH
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		// DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf != CKD_NULL)
	{
		// DEBUG_MSG("kdf must be CKD_NULL");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR))
	{
		// DEBUG_MSG("there must be no shared data");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		// DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				// INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	// byteLen == 0 impiles return max size the ECC can derive
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			break;
#ifndef WITH_FIPS
		case CKK_DES:
			if (byteLen != 0 && byteLen != 8)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0 or 8");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 8;
			break;
#endif
		case CKK_DES2:
			if (byteLen != 0 && byteLen != 16)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0 or 16");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 16;
			break;
		case CKK_DES3:
			if (byteLen != 0 && byteLen != 24)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0 or 24");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 24;
			break;
		case CKK_AES:
			if (byteLen != 0 && byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0, 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the ECDH algorithm handler
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = ecdh->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECPrivateKey((ECPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
    memcpy_s(&publicData[0],
             CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen,
             CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
             CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = ecdh->newPublicKey();
	if (publicKey == NULL)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECDHPublicKey((ECPublicKey*)publicKey, (ECPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		ecdh->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!ecdh->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	ecdh->recyclePrivateKey(privateKey);
	ecdh->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			// For generic and AES keys:
			// default to return max size available.
			if (byteLen == 0)
			{
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						byteLen = secretValue.size();
						break;
					case CKK_AES:
						if (secretValue.size() >= 32)
							byteLen = 32;
						else if (secretValue.size() >= 24)
							byteLen = 24;
						else
							byteLen = 16;
				}
			}

			if (byteLen > secretValue.size())
			{
				// INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Fix the odd parity for DES
				if (keyType == CKK_DES ||
				    keyType == CKK_DES2 ||
				    keyType == CKK_DES3)
				{
					for (size_t i = 0; i < secretValue.size(); i++)
					{
						secretValue[i] = odd_parity[secretValue[i]];
					}
				}

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_DES:
					case CKK_DES2:
					case CKK_DES3:
						secret->setBitLen(byteLen * 7);
						plainKCV = ((DESKey*)secret)->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	ecdh->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif

// Derive an ECDH secret using Montgomery curves
#ifdef WITH_EDDSA
CK_RV SoftHSM::deriveEDDSA
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		// DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf != CKD_NULL)
	{
		// DEBUG_MSG("kdf must be CKD_NULL");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR))
	{
		// DEBUG_MSG("there must be no shared data");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		// DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				// INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	// byteLen == 0 impiles return max size the ECC can derive
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			break;
#ifndef WITH_FIPS
		case CKK_DES:
			if (byteLen != 0 && byteLen != 8)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0 or 8");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 8;
			break;
#endif
		case CKK_DES2:
			if (byteLen != 0 && byteLen != 16)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0 or 16");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 16;
			break;
		case CKK_DES3:
			if (byteLen != 0 && byteLen != 24)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0 or 24");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 24;
			break;
		case CKK_AES:
			if (byteLen != 0 && byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 0, 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the EDDSA algorithm handler
	AsymmetricAlgorithm* eddsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (eddsa == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = eddsa->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_HOST_MEMORY;
	}
	if (getEDPrivateKey((EDPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		eddsa->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
    memcpy_s(&publicData[0],
             CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen,
             CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
             CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = eddsa->newPublicKey();
	if (publicKey == NULL)
	{
		eddsa->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_HOST_MEMORY;
	}
	if (getEDDHPublicKey((EDPublicKey*)publicKey, (EDPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		eddsa->recyclePrivateKey(privateKey);
		eddsa->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!eddsa->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	eddsa->recyclePrivateKey(privateKey);
	eddsa->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			// For generic and AES keys:
			// default to return max size available.
			if (byteLen == 0)
			{
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						byteLen = secretValue.size();
						break;
					case CKK_AES:
						if (secretValue.size() >= 32)
							byteLen = 32;
						else if (secretValue.size() >= 24)
							byteLen = 24;
						else
							byteLen = 16;
				}
			}

			if (byteLen > secretValue.size())
			{
				// INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Fix the odd parity for DES
				if (keyType == CKK_DES ||
				    keyType == CKK_DES2 ||
				    keyType == CKK_DES3)
				{
					for (size_t i = 0; i < secretValue.size(); i++)
					{
						secretValue[i] = odd_parity[secretValue[i]];
					}
				}

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_DES:
					case CKK_DES2:
					case CKK_DES3:
						secret->setBitLen(byteLen * 7);
						plainKCV = ((DESKey*)secret)->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	eddsa->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif

// Derive an symmetric secret
CK_RV SoftHSM::deriveSymmetric
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if (pMechanism->pParameter == NULL_PTR)
	{
		// DEBUG_MSG("pParameter must be supplied");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	ByteString data;

	if ((pMechanism->mechanism == CKM_DES_ECB_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_DES3_ECB_ENCRYPT_DATA) &&
	    pMechanism->ulParameterLen == sizeof(CK_KEY_DERIVATION_STRING_DATA))
	{
		CK_BYTE_PTR pData = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->pData;
		CK_ULONG ulLen = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->ulLen;
		if (ulLen == 0 || pData == NULL_PTR)
		{
			// DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (ulLen % 8 != 0)
		{
			// DEBUG_MSG("The data must be a multiple of 8 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(ulLen);
        memcpy_s(&data[0],
                 ulLen,
                 pData,
                 ulLen);
	}
	else if ((pMechanism->mechanism == CKM_DES_CBC_ENCRYPT_DATA ||
		 pMechanism->mechanism == CKM_DES3_CBC_ENCRYPT_DATA) &&
		 pMechanism->ulParameterLen == sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS))
	{
		CK_BYTE_PTR pData = CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->pData;
		CK_ULONG length = CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->length;
		if (length == 0 || pData == NULL_PTR)
		{
			// DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (length % 8 != 0)
		{
			// DEBUG_MSG("The data must be a multiple of 8 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(length);
        memcpy_s(&data[0],
                 length,
                 pData,
                 length);
	}
	else if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA &&
		 pMechanism->ulParameterLen == sizeof(CK_KEY_DERIVATION_STRING_DATA))
	{
		CK_BYTE_PTR pData = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->pData;
		CK_ULONG ulLen = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->ulLen;
		if (ulLen == 0 || pData == NULL_PTR)
		{
			// DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (ulLen % 16 != 0)
		{
			// DEBUG_MSG("The data must be a multiple of 16 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(ulLen);
        memcpy_s(&data[0],
                 ulLen,
                 pData,
                 ulLen);
	}
	else if ((pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA) &&
		 pMechanism->ulParameterLen == sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS))
	{
		CK_BYTE_PTR pData = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->pData;
		CK_ULONG length = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->length;
		if (length == 0 || pData == NULL_PTR)
		{
			// DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (length % 16 != 0)
		{
			// DEBUG_MSG("The data must be a multiple of 16 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(length);
        memcpy_s(&data[0],
                 length,
                 pData,
                 length);
	}
	else
	{
		// DEBUG_MSG("pParameter is invalid");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				// INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					// INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					// INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			if (byteLen == 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must be set");
				return CKR_TEMPLATE_INCOMPLETE;
			}
			break;
#ifndef WITH_FIPS
		case CKK_DES:
			if (byteLen != 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must not be set");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			byteLen = 8;
			break;
#endif
		case CKK_DES2:
			if (byteLen != 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must not be set");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			byteLen = 16;
			break;
		case CKK_DES3:
			if (byteLen != 0)
			{
				// INFO_MSG("CKA_VALUE_LEN must not be set");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			byteLen = 24;
			break;
		case CKK_AES:
			if (byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				// INFO_MSG("CKA_VALUE_LEN must be 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
#ifndef WITH_FIPS
		case CKM_DES_ECB_ENCRYPT_DATA:
			algo = SymAlgo::DES;
			mode = SymMode::ECB;
			bb = 7;
			break;
		case CKM_DES_CBC_ENCRYPT_DATA:
			algo = SymAlgo::DES;
			mode = SymMode::CBC;
			bb = 7;
			iv.resize(8);
            memcpy_s(&iv[0],
                     8,
                     &(CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->iv[0]),
                     8);
			break;
#endif
		case CKM_DES3_ECB_ENCRYPT_DATA:
			algo = SymAlgo::DES3;
			mode = SymMode::ECB;
			bb = 7;
			break;
		case CKM_DES3_CBC_ENCRYPT_DATA:
			algo = SymAlgo::DES3;
			mode = SymMode::CBC;
			bb = 7;
			iv.resize(8);
            memcpy_s(&iv[0],
                   8,
                   &(CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->iv[0]),
                   8);
			break;
		case CKM_AES_ECB_ENCRYPT_DATA:
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC_ENCRYPT_DATA:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			iv.resize(16);
            memcpy_s(&iv[0],
                   16,
                   &(CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->iv[0]),
                   16);
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Check the key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL_PTR || !baseKey->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, baseKey) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize encryption
	if (!cipher->encryptInit(secretkey, mode, iv, padding))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	// Get the data
	ByteString secretValue;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, secretValue))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}
	cipher->recycleKey(secretkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	secretValue += encryptedFinal;

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	CK_RV rv = CKR_OK;
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			if (byteLen > secretValue.size())
			{
				// INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the trailing end
				if (byteLen < secretValue.size())
					secretValue.resize(byteLen);

				// Fix the odd parity for DES
				if (keyType == CKK_DES ||
				    keyType == CKK_DES2 ||
				    keyType == CKK_DES3)
				{
					for (size_t i = 0; i < secretValue.size(); i++)
					{
						secretValue[i] = odd_parity[secretValue[i]];
					}
				}

				// Get the KCV
				SymmetricKey* secret = new SymmetricKey();
				secret->setKeyBits(secretValue);
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_DES:
					case CKK_DES2:
					case CKK_DES3:
						secret->setBitLen(byteLen * 7);
						plainKCV = ((DESKey*)secret)->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}
				delete secret;

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif // Unsupported by Crypto API Toolkit

CK_RV SoftHSM::CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject, int op)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	Session* session = (Session*)handleManager->getSession(hSession);
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	bool isImplicit = false;
	CK_RV rv = extractObjectInformation(pTemplate,ulCount,objClass,keyType,certType, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		// ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Check user credentials
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
		{
			// INFO_MSG("User is not authorized");
		}
		if (rv == CKR_SESSION_READ_ONLY)
		{
			// INFO_MSG("Session is read-only");
		}

		return rv;
	}

	// Change order of attributes
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE attribs[maxAttribs];
	CK_ATTRIBUTE saveAttribs[maxAttribs];
	CK_ULONG attribsCount = 0;
	CK_ULONG saveAttribsCount = 0;
	if (ulCount > maxAttribs)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}
	for (CK_ULONG i=0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CHECK_VALUE:
				saveAttribs[saveAttribsCount++] = pTemplate[i];
				break;
			default:
				attribs[attribsCount++] = pTemplate[i];
		}
	}
	for (CK_ULONG i=0; i < saveAttribsCount; i++)
	{
        if (attribsCount >= maxAttribs)
        {
            return CKR_GENERAL_ERROR;
        }
		attribs[attribsCount++] = saveAttribs[i];
	}

	P11Object* p11object = NULL;
	rv = newP11Object(objClass,keyType,certType,&p11object);
	if (rv != CKR_OK)
		return rv;

	// Create the object in session or on the token
	OSObject *object = NULL_PTR;
	if (isOnToken)
	{
		object = (OSObject*) token->createObject();
	}
	else
	{
		object = sessionObjectStore->createObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE);
	}

	if (object == NULL || !p11object->init(object))
	{
		delete p11object;
		return CKR_GENERAL_ERROR;
	}

	rv = p11object->saveTemplate(token, isPrivate != CK_FALSE, attribs,attribsCount,op);
	delete p11object;
	if (rv != CKR_OK)
		return rv;

    if (op == OBJECT_OP_CREATE
#ifdef SGXHSM
        || op == OBJECT_OP_CREATE_AES_KEY
#endif
       )
	{
		if (objClass == CKO_PUBLIC_KEY &&
		    (!object->startTransaction() ||
		    !object->setAttribute(CKA_LOCAL, false) ||
		    !object->commitTransaction()))
		{
			return CKR_GENERAL_ERROR;
		}

		if ((objClass == CKO_SECRET_KEY || objClass == CKO_PRIVATE_KEY) &&
		    (!object->startTransaction() ||
		    !object->setAttribute(CKA_LOCAL, false) ||
		    !object->setAttribute(CKA_ALWAYS_SENSITIVE, false) ||
		    !object->setAttribute(CKA_NEVER_EXTRACTABLE, false) ||
		    !object->commitTransaction()))
		{
			return CKR_GENERAL_ERROR;
		}
	}

	if (isOnToken)
	{
		*phObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, object);
	} else {
		*phObject = handleManager->addSessionObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE, object);
	}

	return CKR_OK;
}

CK_RV SoftHSM::getRSAPrivateKey(RSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIVATE_EXPONENT), privateExponent);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME_1), prime1);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME_2), prime2);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EXPONENT_1), exponent1);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EXPONENT_2), exponent2);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_COEFFICIENT), coefficient);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getByteStringValue(CKA_MODULUS);
		publicExponent = key->getByteStringValue(CKA_PUBLIC_EXPONENT);
		privateExponent = key->getByteStringValue(CKA_PRIVATE_EXPONENT);
		prime1 = key->getByteStringValue(CKA_PRIME_1);
		prime2 = key->getByteStringValue(CKA_PRIME_2);
		exponent1 =  key->getByteStringValue(CKA_EXPONENT_1);
		exponent2 = key->getByteStringValue(CKA_EXPONENT_2);
		coefficient = key->getByteStringValue(CKA_COEFFICIENT);
	}

	privateKey->setN(modulus);
	privateKey->setE(publicExponent);
	privateKey->setD(privateExponent);
	privateKey->setP(prime1);
	privateKey->setQ(prime2);
	privateKey->setDP1(exponent1);
	privateKey->setDQ1(exponent2);
	privateKey->setPQ(coefficient);

	return CKR_OK;
}

CK_RV SoftHSM::getRSAPublicKey(RSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// RSA Public Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getByteStringValue(CKA_MODULUS);
		publicExponent = key->getByteStringValue(CKA_PUBLIC_EXPONENT);
	}

	publicKey->setN(modulus);
	publicKey->setE(publicExponent);

	return CKR_OK;
}

#if 0 //Unsupported by Crypto API Toolkit
CK_RV SoftHSM::getDSAPrivateKey(DSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// DSA Private Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME), prime);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_SUBPRIME), subprime);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_BASE), generator);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key->getByteStringValue(CKA_PRIME);
		subprime = key->getByteStringValue(CKA_SUBPRIME);
		generator = key->getByteStringValue(CKA_BASE);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setP(prime);
	privateKey->setQ(subprime);
	privateKey->setG(generator);
	privateKey->setX(value);

	return CKR_OK;
}

CK_RV SoftHSM::getDSAPublicKey(DSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// DSA Public Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME), prime);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_SUBPRIME), subprime);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_BASE), generator);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key->getByteStringValue(CKA_PRIME);
		subprime = key->getByteStringValue(CKA_SUBPRIME);
		generator = key->getByteStringValue(CKA_BASE);
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setP(prime);
	publicKey->setQ(subprime);
	publicKey->setG(generator);
	publicKey->setY(value);

	return CKR_OK;
}
#endif //Unsupported by Crypto API Toolkit

CK_RV SoftHSM::getECPrivateKey(ECPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setEC(group);
	privateKey->setD(value);

	return CKR_OK;
}

CK_RV SoftHSM::getECPublicKey(ECPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Public Key Attributes
	ByteString group;
	ByteString point;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_POINT), point);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		point = key->getByteStringValue(CKA_EC_POINT);
	}

	publicKey->setEC(group);
	publicKey->setQ(point);

	return CKR_OK;
}

CK_RV SoftHSM::getEDPrivateKey(EDPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EDDSA Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setEC(group);
	privateKey->setK(value);

	return CKR_OK;
}

CK_RV SoftHSM::getEDPublicKey(EDPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Public Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_POINT), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_EC_POINT);
	}

	publicKey->setEC(group);
	publicKey->setA(value);

	return CKR_OK;
}

#if 0 //Unsupported by Crypto API Toolkit
CK_RV SoftHSM::getDHPrivateKey(DHPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// DH Private Key Attributes
	ByteString prime;
	ByteString generator;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME), prime);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_BASE), generator);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key->getByteStringValue(CKA_PRIME);
		generator = key->getByteStringValue(CKA_BASE);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setP(prime);
	privateKey->setG(generator);
	privateKey->setX(value);

	return CKR_OK;
}

CK_RV SoftHSM::getDHPublicKey(DHPublicKey* publicKey, DHPrivateKey* privateKey, ByteString& pubParams)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setP(privateKey->getP());
	publicKey->setG(privateKey->getG());

	// Set value
	publicKey->setY(pubParams);

	return CKR_OK;
}

CK_RV SoftHSM::getECDHPublicKey(ECPublicKey* publicKey, ECPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	ByteString data = getECDHPubData(pubData);
	publicKey->setQ(data);

	return CKR_OK;
}

CK_RV SoftHSM::getEDDHPublicKey(EDPublicKey* publicKey, EDPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	ByteString data = getECDHPubData(pubData);
	publicKey->setA(data);

	return CKR_OK;
}

// ECDH pubData can be in RAW or DER format.
// Need to convert RAW as SoftHSM uses DER.
ByteString SoftHSM::getECDHPubData(ByteString& pubData)
{
	size_t len = pubData.size();
	size_t controlOctets = 2;
	if (len == 32 || len == 65 || len == 97 || len == 133)
	{
		// Raw: Length matches the public key size of:
		// EDDSA: X25519
		// ECDSA: P-256, P-384, or P-521
		controlOctets = 0;
	}
	else if (len < controlOctets || pubData[0] != 0x04)
	{
		// Raw: Too short or does not start with 0x04
		controlOctets = 0;
	}
	else if (pubData[1] < 0x80)
	{
		// Raw: Length octet does not match remaining data length
		if (pubData[1] != (len - controlOctets)) controlOctets = 0;
	}
	else
	{
		size_t lengthOctets = pubData[1] & 0x7F;
		controlOctets += lengthOctets;

		if (controlOctets >= len)
		{
			// Raw: Too short
			controlOctets = 0;
		}
		else
		{
			ByteString length(&pubData[2], lengthOctets);

			if (length.long_val() != (len - controlOctets))
			{
				// Raw: Length octets does not match remaining data length
				controlOctets = 0;
			}
		}
	}

	// DER format
	if (controlOctets != 0) return pubData;

	return DERUTIL::raw2Octet(pubData);
}

CK_RV SoftHSM::getGOSTPrivateKey(GOSTPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// GOST Private Key Attributes
	ByteString value;
	ByteString param;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_GOSTR3410_PARAMS), param);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
		param = key->getByteStringValue(CKA_GOSTR3410_PARAMS);
	}

	privateKey->setD(value);
	privateKey->setEC(param);

	return CKR_OK;
}

CK_RV SoftHSM::getGOSTPublicKey(GOSTPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// GOST Public Key Attributes
	ByteString point;
	ByteString param;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), point);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_GOSTR3410_PARAMS), param);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		point = key->getByteStringValue(CKA_VALUE);
		param = key->getByteStringValue(CKA_GOSTR3410_PARAMS);
	}

	publicKey->setQ(point);
	publicKey->setEC(param);

	return CKR_OK;
}
#endif //Unsupported by Crypto API Toolkit

CK_RV SoftHSM::getSymmetricKey(SymmetricKey* skey, Token* token, OSObject* key)
{
	if (skey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	ByteString keybits;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getByteStringValue(CKA_VALUE);
	}

	skey->setKeyBits(keybits);

	return CKR_OK;
}

bool SoftHSM::setRSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa == NULL)
		return false;
	PrivateKey* priv = rsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		rsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isPrivate)
	{
		token->encrypt(((RSAPrivateKey*)priv)->getN(), modulus);
		token->encrypt(((RSAPrivateKey*)priv)->getE(), publicExponent);
		token->encrypt(((RSAPrivateKey*)priv)->getD(), privateExponent);
		token->encrypt(((RSAPrivateKey*)priv)->getP(), prime1);
		token->encrypt(((RSAPrivateKey*)priv)->getQ(), prime2);
		token->encrypt(((RSAPrivateKey*)priv)->getDP1(), exponent1);
		token->encrypt(((RSAPrivateKey*)priv)->getDQ1(), exponent2);
		token->encrypt(((RSAPrivateKey*)priv)->getPQ(), coefficient);
	}
	else
	{
		modulus = ((RSAPrivateKey*)priv)->getN();
		publicExponent = ((RSAPrivateKey*)priv)->getE();
		privateExponent = ((RSAPrivateKey*)priv)->getD();
		prime1 = ((RSAPrivateKey*)priv)->getP();
		prime2 = ((RSAPrivateKey*)priv)->getQ();
		exponent1 =  ((RSAPrivateKey*)priv)->getDP1();
		exponent2 = ((RSAPrivateKey*)priv)->getDQ1();
		coefficient = ((RSAPrivateKey*)priv)->getPQ();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_MODULUS, modulus);
	bOK = bOK && key->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
	bOK = bOK && key->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
	bOK = bOK && key->setAttribute(CKA_PRIME_1, prime1);
	bOK = bOK && key->setAttribute(CKA_PRIME_2, prime2);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_1,exponent1);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_2, exponent2);
	bOK = bOK && key->setAttribute(CKA_COEFFICIENT, coefficient);

	rsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	return bOK;
}

#if 0 //Unsupported by Crypto API Toolkit
bool SoftHSM::setDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* dsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA);
	if (dsa == NULL)
		return false;
	PrivateKey* priv = dsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		dsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);
		return false;
	}
	// DSA Private Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((DSAPrivateKey*)priv)->getP(), prime);
		token->encrypt(((DSAPrivateKey*)priv)->getQ(), subprime);
		token->encrypt(((DSAPrivateKey*)priv)->getG(), generator);
		token->encrypt(((DSAPrivateKey*)priv)->getX(), value);
	}
	else
	{
		prime = ((DSAPrivateKey*)priv)->getP();
		subprime = ((DSAPrivateKey*)priv)->getQ();
		generator = ((DSAPrivateKey*)priv)->getG();
		value = ((DSAPrivateKey*)priv)->getX();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PRIME, prime);
	bOK = bOK && key->setAttribute(CKA_SUBPRIME, subprime);
	bOK = bOK && key->setAttribute(CKA_BASE, generator);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	dsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dsa);

	return bOK;
}

bool SoftHSM::setDHPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* dh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH);
	if (dh == NULL)
		return false;
	PrivateKey* priv = dh->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		dh->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);
		return false;
	}
	// DH Private Key Attributes
	ByteString prime;
	ByteString generator;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((DHPrivateKey*)priv)->getP(), prime);
		token->encrypt(((DHPrivateKey*)priv)->getG(), generator);
		token->encrypt(((DHPrivateKey*)priv)->getX(), value);
	}
	else
	{
		prime = ((DHPrivateKey*)priv)->getP();
		generator = ((DHPrivateKey*)priv)->getG();
		value = ((DHPrivateKey*)priv)->getX();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PRIME, prime);
	bOK = bOK && key->setAttribute(CKA_BASE, generator);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	dh->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(dh);

	return bOK;
}
#endif //Unsupported by Crypto API Toolkit

bool SoftHSM::setECPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* ecc = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecc == NULL)
		return false;
	PrivateKey* priv = ecc->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		ecc->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((ECPrivateKey*)priv)->getEC(), group);
		token->encrypt(((ECPrivateKey*)priv)->getD(), value);
	}
	else
	{
		group = ((ECPrivateKey*)priv)->getEC();
		value = ((ECPrivateKey*)priv)->getD();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	ecc->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);

	return bOK;
}

#if 0 //Unsupported by Crypto API Toolkit
bool SoftHSM::setGOSTPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* gost = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::GOST);
	if (gost == NULL)
		return false;
	PrivateKey* priv = gost->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		gost->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);
		return false;
	}
	// GOST Private Key Attributes
	ByteString value;
	ByteString param_a;
	if (isPrivate)
	{
		token->encrypt(((GOSTPrivateKey*)priv)->getD(), value);
		token->encrypt(((GOSTPrivateKey*)priv)->getEC(), param_a);
	}
	else
	{
		value = ((GOSTPrivateKey*)priv)->getD();
		param_a = ((GOSTPrivateKey*)priv)->getEC();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_VALUE, value);
	bOK = bOK && key->setAttribute(CKA_GOSTR3410_PARAMS, param_a);

	gost->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(gost);

	return bOK;
}
#endif //Unsupported by Crypto API Toolkit

CK_RV SoftHSM::MechParamCheckRSAPKCSOAEP(CK_MECHANISM_PTR pMechanism, const CK_BBOOL fromUnwrapKey)
{
	// This is a programming error
	if (pMechanism->mechanism != CKM_RSA_PKCS_OAEP) {
		// ERROR_MSG("MechParamCheckRSAPKCSOAEP called on wrong mechanism");
		return CKR_GENERAL_ERROR;
	}

	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
	{
		// ERROR_MSG("pParameter must be of type CK_RSA_PKCS_OAEP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}
    CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
	if (params->source != CKZ_DATA_SPECIFIED)
	{
		// ERROR_MSG("source must be CKZ_DATA_SPECIFIED");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pSourceData != NULL)
	{
		// ERROR_MSG("pSourceData must be NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->ulSourceDataLen != 0)
	{
		// ERROR_MSG("ulSourceDataLen must be 0");
		return CKR_ARGUMENTS_BAD;
	}
	return CKR_OK;
}

bool SoftHSM::isMechanismPermitted(OSObject* key, CK_MECHANISM_PTR pMechanism)
{
	std::list<CK_MECHANISM_TYPE> mechs = supportedMechanisms;
	/* First check if the algorithm is enabled in the global configuration */
	auto it = std::find(mechs.begin(), mechs.end(), pMechanism->mechanism);
	if (it == mechs.end())
		return false;

	OSAttribute attribute = key->getAttribute(CKA_ALLOWED_MECHANISMS);
	std::set<CK_MECHANISM_TYPE> allowed = attribute.getMechanismTypeSetValue();

	if (allowed.empty()) {
		return true;
	}

	return allowed.find(pMechanism->mechanism) != allowed.end();
}

#ifdef DCAP_SUPPORT
CK_RV SoftHSM::exportQuoteWithRsaPublicKey(const CK_SESSION_HANDLE& hSession,
                                           const CK_OBJECT_HANDLE&  hKey,
                                           const CK_MECHANISM_PTR   pMechanism,
                                           CK_BYTE_PTR              outBuffer,
                                           CK_ULONG_PTR             outBufferLength)
{
    CK_RV rv = CKR_FUNCTION_FAILED;
    uint32_t offset = 0;

    if (!pMechanism || !pMechanism->pParameter  || !outBufferLength ||
        (sizeof(CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL) != pMechanism->ulParameterLen))
    {
        return CKR_ARGUMENTS_BAD;
    }

    CK_ULONG origOutBufferLength = *outBufferLength;

    sgx_target_info_t targetInfo{0};
    memcpy_s(&targetInfo,
             sizeof(sgx_target_info_t),
             &CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL_PTR(pMechanism->pParameter)->targetInfo,
             sizeof(sgx_target_info_t));

    CK_ULONG publicKeyLength = origOutBufferLength;

    rv = getPublicKey(hSession, hKey, outBuffer, publicKeyLength);

    if (CKR_OK != rv)
    {
        *outBufferLength = 0;
        return rv;
    }

    *outBufferLength = publicKeyLength;

    auto quoteLength = CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL_PTR(pMechanism->pParameter)->quoteLength;
    *outBufferLength += quoteLength;

    if (!outBuffer)
    {
        return CKR_OK;
    }

    if (origOutBufferLength < *outBufferLength)
    {
        return CKR_BUFFER_TOO_SMALL;
    }

    offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);

    auto publicKeyDataSize = publicKeyLength - sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
    auto digestInputLength = publicKeyDataSize + NONCE_LENGTH;
    std::vector<CK_BYTE> digestInput(digestInputLength, 0);

    memcpy_s(&digestInput[0], digestInputLength, outBuffer + offset, publicKeyDataSize);
    static_assert((NONCE_LENGTH) <= 256, "Maximum NONCE length should be <= 256");
    memcpy_s(&digestInput[0] + publicKeyDataSize, digestInputLength - publicKeyDataSize, \
             CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL_PTR(pMechanism->pParameter)->nonce, NONCE_LENGTH);

    rv = appendQuote(hSession,
                     &targetInfo,
                     &digestInput[0],
                     digestInputLength,
                     outBuffer + publicKeyLength,
                     quoteLength);

    if (CKR_OK != rv)
    {
        memset(outBuffer, 0, *outBufferLength);
        *outBufferLength = 0;
        return rv;
    }

    return rv;
}

CK_RV SoftHSM::getPublicKey(const CK_SESSION_HANDLE& hSession,
                            const CK_OBJECT_HANDLE&  hKey,
                            CK_BYTE_PTR              outBuffer,
                            CK_ULONG&                outBufferLength)
{
    CK_RV status = CKR_FUNCTION_FAILED;
    CK_ULONG modulusSize = 0;
    CK_ULONG exponentSize = 0;

    CK_RSA_PUBLIC_KEY_PARAMS rsaPublicKeyParams{};

    // Check the key handle.
    OSObject *key = (OSObject *)handleManager->getObject(hKey);
    if ((key == NULL_PTR) || !key->isValid())
    {
        return CKR_KEY_HANDLE_INVALID;
    }

    CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
    CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

    // Get the session
    Session* session = (Session*)handleManager->getSession(hSession);
    if (session == NULL)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Check user credentials for the key
    status = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
    if (status != CKR_OK)
    {
        return status;
    }

    // Get the token
    Token* token = session->getToken();
    if (token == NULL) return CKR_GENERAL_ERROR;

    AsymmetricAlgorithm* asymCrypto = NULL;
    PublicKey* publicKey = NULL;

    asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
    if (!asymCrypto)
    {
        return CKR_MECHANISM_INVALID;
    }

    publicKey = asymCrypto->newPublicKey();
    if (!publicKey)
    {
        CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
        return CKR_HOST_MEMORY;
    }

    if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
    {
        asymCrypto->recyclePublicKey(publicKey);
        CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
        return CKR_GENERAL_ERROR;
    }

    modulusSize = ((RSAPublicKey*)publicKey)->getN().size();
    exponentSize = ((RSAPublicKey*)publicKey)->getE().size();

    if (!outBuffer)
    {
        outBufferLength = modulusSize + exponentSize + sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
        return CKR_OK;
    }

    if (outBufferLength < (modulusSize + exponentSize + sizeof(CK_RSA_PUBLIC_KEY_PARAMS)))
    {
        return CKR_BUFFER_TOO_SMALL;
    }

    outBufferLength = modulusSize + exponentSize + sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
    rsaPublicKeyParams.ulExponentLen = exponentSize;
    rsaPublicKeyParams.ulModulusLen  = modulusSize;

    memcpy_s(outBuffer,
             outBufferLength,
             &rsaPublicKeyParams,
             sizeof(CK_RSA_PUBLIC_KEY_PARAMS));

    memcpy_s(outBuffer + sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
             outBufferLength - sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
             ((RSAPublicKey*)publicKey)->getE().const_byte_str(),
             exponentSize);

    memcpy_s(outBuffer + sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + exponentSize,
             outBufferLength - sizeof(CK_RSA_PUBLIC_KEY_PARAMS) - exponentSize,
             ((RSAPublicKey*)publicKey)->getN().const_byte_str(),
             modulusSize);

    asymCrypto->recyclePublicKey(publicKey);
    CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
    publicKey = nullptr;
    asymCrypto = nullptr;

    return CKR_OK;
}

CK_RV SoftHSM::appendQuote(const CK_SESSION_HANDLE& hSession,
                           const sgx_target_info_t* targetInfo,
                           const CK_BYTE_PTR        data,
                           const CK_ULONG&          dataLength,
                           CK_BYTE_PTR              quoteBuffer,
                           const CK_ULONG&          quoteBufferLen)
{
    CK_RV rv {CKR_FUNCTION_FAILED};
    sgx_report_t enclaveReport { 0 };
    sgx_status_t sgxStatus{SGX_SUCCESS};

    if (!quoteBuffer || !targetInfo || !data || !dataLength)
    {
        return CKR_DATA_INVALID;
    }


    rv = digestAndCreateReport(hSession, targetInfo, &enclaveReport, data, dataLength);

    if (CKR_OK != rv)
    {
        return rv;
    }

    sgxStatus = ocall_generate_quote(&rv, &enclaveReport, quoteBuffer, quoteBufferLen);

    if ((SGX_SUCCESS != sgxStatus) || (rv != CKR_OK))
    {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV SoftHSM::createEnclaveReport(const sgx_target_info_t* targetInfo,
                                   const sgx_report_data_t* reportData,
                                   sgx_report_t*            sgxReport)
{
    sgx_status_t status = sgx_create_report(targetInfo, reportData, sgxReport);

    if (sgx_status_t::SGX_SUCCESS != status)
    {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV SoftHSM::digestAndCreateReport(const CK_SESSION_HANDLE  hSession,
                                     const sgx_target_info_t* targetInfo,
                                     sgx_report_t*            sgxReport,
                                     const CK_BYTE_PTR        data,
                                     const CK_ULONG&          dataLength)
{
    sgx_report_data_t reportData{};
    CK_ULONG reportDataLen = SGX_REPORT_DATA_SIZE;
    CK_RV rv = CKR_GENERAL_ERROR;


    if (!is_inside_enclave(targetInfo, sizeof(sgx_target_info_t)) ||
        !is_inside_enclave(sgxReport, sizeof(sgx_report_t))       ||
        !data || !dataLength)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = createDigest(hSession, HashAlgo::SHA256,
                      data, dataLength,
                      reportData.d, &reportDataLen);

    if (rv != CKR_OK)
    {
        return CKR_FUNCTION_FAILED;
    }

    rv = createEnclaveReport(targetInfo, &reportData, sgxReport);

    return rv;
}


CK_RV SoftHSM::createDigest(const CK_SESSION_HANDLE& hSession,
                            const HashAlgo::Type&    algo,
                            const CK_BYTE_PTR        pData,
                            const CK_ULONG&          ulDataLen,
                            CK_BYTE_PTR              pDigest,
                            CK_ULONG_PTR             pulDigestLen)
{
    if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

    if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;

    // Get the session
    Session* session = (Session*)handleManager->getSession(hSession);
    if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

    // Check if we have another operation
    if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

    HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(algo);
    if (hash == NULL) return CKR_MECHANISM_INVALID;

    // Initialize hashing
    if (hash->hashInit() == false)
    {
        CryptoFactory::i()->recycleHashAlgorithm(hash);
        return CKR_GENERAL_ERROR;
    }

    session->setOpType(SESSION_OP_DIGEST);
    session->setDigestOp(hash);
    session->setHashAlgo(algo);

    // Return size
    CK_ULONG size = session->getDigestOp()->getHashSize();
    if (pDigest == NULL_PTR)
    {
        *pulDigestLen = size;
        CryptoFactory::i()->recycleHashAlgorithm(hash);
        return CKR_OK;
    }

    // Check buffer size
    if (*pulDigestLen < size)
    {
        *pulDigestLen = size;
        return CKR_BUFFER_TOO_SMALL;
    }

    // Get the data
    ByteString data(pData, ulDataLen);

    // Digest the data
    if (session->getDigestOp()->hashUpdate(data) == false)
    {
        session->resetOp();
        return CKR_GENERAL_ERROR;
    }

    // Get the digest
    ByteString digest;
    if (session->getDigestOp()->hashFinal(digest) == false)
    {
        session->resetOp();
        return CKR_GENERAL_ERROR;
    }

    // Check size
    if (digest.size() != size)
    {
        // ERROR_MSG("The size of the digest differ from the size of the mechanism");
        session->resetOp();
        return CKR_GENERAL_ERROR;
    }
    memcpy_s(pDigest, *pulDigestLen, digest.byte_str(), size);
    *pulDigestLen = size;

    session->resetOp();

    return CKR_OK;
}
#endif

#ifdef SGXHSM
CK_BBOOL SoftHSM::isRestrictedKeyAttributeValue(const CK_ATTRIBUTE_PTR pTemplate,
                                                const CK_ULONG& ulCount,
                                                const CK_BBOOL& fromSetAttribute,
                                                const CK_OBJECT_HANDLE& hObject)
{
    CK_BBOOL isKeyObject = false;
    CK_BBOOL isRestrictedAttribute = false;

    if (hObject != CK_INVALID_HANDLE)
    {
        OSObject *object = (OSObject *)handleManager->getObject(hObject);
        if (object == NULL_PTR || !object->isValid())
        {
            return CKR_OBJECT_HANDLE_INVALID;
        }

        if (object->attributeExists(CKA_KEY_TYPE))
        {
            isKeyObject = true;
        }
    }

    for (CK_ULONG i=0; i < ulCount; i++)
    {
        switch (pTemplate[i].type)
        {
            case CKA_KEY_TYPE:
                if (hObject == CK_INVALID_HANDLE)
                {
                    isKeyObject = true;
                }
                break;
            case CKA_VALUE:
            case CKA_PRIVATE_EXPONENT:
            case CKA_PRIME_1:
            case CKA_PRIME_2:
            case CKA_EXPONENT_1:
            case CKA_EXPONENT_2:
            case CKA_COEFFICIENT:
                isRestrictedAttribute = true;
                break;
            case CKA_VALUE_LEN:
                fromSetAttribute ? isRestrictedAttribute = true: isRestrictedAttribute = false;
                break;
            default:
                break;
        }
    }
    return (isKeyObject && isRestrictedAttribute);
}

CK_OBJECT_HANDLE SoftHSM::getRSAPairKey(const CK_SESSION_HANDLE& hSession,
                                        const CK_OBJECT_HANDLE&  hKey)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE rsaPairKeyHandle = CK_INVALID_HANDLE;

    OSObject *key = (OSObject *)handleManager->getObject(hKey);
    if (nullptr == key || !key->isValid())
    {
        return rsaPairKeyHandle;
    }

    CK_ULONG pairKeyId = key->getUnsignedLongValue(CKA_ASYMMETRIC_PAIR_ID, 0);

    if (0 != pairKeyId)
    {
        // Given a RSA key handle (public/private) getting corresponding key handle (private/public)
        // Only two objects (RSA public key and corresponding private key)
        // are having same pair id key which is generated randomly
        CK_ATTRIBUTE pTemplate[] = { { CKA_ASYMMETRIC_PAIR_ID, &pairKeyId, sizeof(pairKeyId) } };

        rv = FindObjectsInit(hSession, &pTemplate[0], 1);
        if (CKR_OK != rv)
        {
            C_FindObjectsFinal(hSession);
            return rsaPairKeyHandle;
        }

        CK_OBJECT_HANDLE hObjects[2];
        CK_ULONG ulObjectCount = 0;

        rv = FindObjects(hSession, &hObjects[0], 2, &ulObjectCount);
        if (CKR_OK != rv || 2 != ulObjectCount)
        {
            C_FindObjectsFinal(hSession);
            return rsaPairKeyHandle;
        }

        rv = C_FindObjectsFinal(hSession);
        if (CKR_OK != rv)
        {
            return rsaPairKeyHandle;
        }

        for (CK_ULONG i = 0 ; i < 2 ; i++)
        {
            if (hObjects[i] != hKey)
            {
                rsaPairKeyHandle = hObjects[i];
                break;
            }
        }
    }

    return rsaPairKeyHandle;
}

CK_BBOOL SoftHSM::isSupportedKeyObject(const CK_ATTRIBUTE_PTR pTemplate,
                                       const CK_ULONG&        ulCount,
                                       CK_KEY_TYPE*           keyType)
{
	if (nullptr == keyType)
	{
		return false;
	}

    for (CK_ULONG i=0; i < ulCount; i++)
    {
        switch (pTemplate[i].type)
        {
            case CKA_KEY_TYPE:
                if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE))
                {
                    *keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
                    if (CKK_AES == *keyType          ||
                        CKK_SHA256_HMAC == *keyType  ||
                        CKK_SHA384_HMAC == *keyType  ||
                        CKK_SHA512_HMAC == *keyType)
                    {
                        return true;
                    }
                }
                break;
            default:
                break;
        }
    }

    return false;
}

CK_ULONG SoftHSM::getKeyLength(const CK_ATTRIBUTE_PTR   pTemplate,
                               const CK_ULONG&             ulCount)
{
	CK_ULONG keyLength = 0;

    for (CK_ULONG i=0; i < ulCount; i++)
    {
        switch (pTemplate[i].type)
        {
            case CKA_VALUE_LEN:
                if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
                {
                    return 0;
                }

                keyLength = *(CK_ULONG*)pTemplate[i].pValue;
                break;
            default:
                break;
        }
    }

    return keyLength;
}

CK_BBOOL SoftHSM::isSupportedKeyLength(const CK_ULONG&      keyLength,
                                       const CK_KEY_TYPE&   keyType)
{
    if (CKK_AES == keyType)
    {
        if ((16 != keyLength) && (24 != keyLength) && (32 != keyLength))
        {
            return false;
        }
    }
    else if (CKK_SHA256_HMAC == keyType)
    {
        if ((keyLength < 32) || ((keyLength % 8) != 0))
        {
            return false;
        }
    }
    else if (CKK_SHA384_HMAC == keyType)
    {
        if ((keyLength < 48) || ((keyLength % 8) != 0))
        {
            return false;
        }
    }
    else if (CKK_SHA512_HMAC == keyType)
    {
        if ((keyLength < 64) || ((keyLength % 8) != 0))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    return true;
}

CK_BBOOL SoftHSM::isPrivateObject(const CK_ATTRIBUTE_PTR pTemplate,
                                  const CK_ULONG&        ulCount)
{
    for (CK_ULONG i=0; i < ulCount; i++)
    {
        switch (pTemplate[i].type)
        {
            case CKA_PRIVATE:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                {
                    CK_BBOOL isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
                    return isPrivate;
                }
                break;
            default:
                break;
        }
    }
    return true;
}
#endif

CK_RV SoftHSM::FindObjectsInit(const CK_SESSION_HANDLE& hSession,
                               const CK_ATTRIBUTE_PTR pTemplate,
                               const CK_ULONG& ulCount)
{
    if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

    // Get the session
    Session* session = (Session*)handleManager->getSession(hSession);
    if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

    // Get the slot
    Slot* slot = session->getSlot();
    if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

    // Determine whether we have a public session or not.
    bool isPublicSession;
    switch (session->getState()) {
        case CKS_RO_USER_FUNCTIONS:
        case CKS_RW_USER_FUNCTIONS:
            isPublicSession = false;
            break;
        default:
            isPublicSession = true;
    }

    // Get the token
    Token* token = session->getToken();
    if (token == NULL_PTR) return CKR_GENERAL_ERROR;

    // Check if we have another operation
    if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

    session->setOpType(SESSION_OP_FIND);
    FindOperation *findOp = FindOperation::create();

    // Check if we are out of memory
    if (findOp == NULL_PTR) return CKR_HOST_MEMORY;

    std::set<OSObject*> allObjects;
    token->getObjects(allObjects);
    sessionObjectStore->getObjects(slot->getSlotID(),allObjects);

    std::set<CK_OBJECT_HANDLE> handles;
    std::set<OSObject*>::iterator it;
    for (it=allObjects.begin(); it != allObjects.end(); ++it)
    {
        // Refresh object and check if it is valid
        if (!(*it)->isValid()) {
            // DEBUG_MSG("Object is not valid, skipping");
            continue;
        }

        // Determine if the object has CKA_PRIVATE set to CK_TRUE
        bool isPrivateObject = (*it)->getBooleanValue(CKA_PRIVATE, true);

        // If the object is private, and we are in a public session then skip it !
        if (isPublicSession && isPrivateObject)
            continue; // skip object

        // Perform the actual attribute matching.
        bool bAttrMatch = true; // We let an empty template match everything.
        for (CK_ULONG i=0; i<ulCount; ++i)
        {
            bAttrMatch = false;

            if (!(*it)->attributeExists(pTemplate[i].type))
                break;

            OSAttribute attr = (*it)->getAttribute(pTemplate[i].type);

            if (attr.isBooleanAttribute())
            {
                if (sizeof(CK_BBOOL) != pTemplate[i].ulValueLen)
                    break;
                bool bTemplateValue = (*(CK_BBOOL*)pTemplate[i].pValue == CK_TRUE);
                if (attr.getBooleanValue() != bTemplateValue)
                    break;
            }
            else
            {
                if (attr.isUnsignedLongAttribute())
                {
                    if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
                        break;
                    CK_ULONG ulTemplateValue = *(CK_ULONG_PTR)pTemplate[i].pValue;
                    if (attr.getUnsignedLongValue() != ulTemplateValue)
                        break;
                }
                else
                {
                    if (attr.isByteStringAttribute())
                    {
                        ByteString bsAttrValue;
                        if (isPrivateObject && attr.getByteStringValue().size() != 0)
                        {
                            if (!token->decrypt(attr.getByteStringValue(), bsAttrValue))
                            {
                                delete findOp;
                                return CKR_GENERAL_ERROR;
                            }
                        }
                        else
                            bsAttrValue = attr.getByteStringValue();

                        if (bsAttrValue.size() != pTemplate[i].ulValueLen)
                            break;
                        if (pTemplate[i].ulValueLen != 0)
                        {
                            ByteString bsTemplateValue((const unsigned char*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
                            if (bsAttrValue != bsTemplateValue)
                                break;
                        }
                    }
                    else
                        break;
                }
            }
            // The attribute matched !
            bAttrMatch = true;
        }

        if (bAttrMatch)
        {
            CK_SLOT_ID slotID = slot->getSlotID();
            bool isOnToken = (*it)->getBooleanValue(CKA_TOKEN, false);
            bool isPrivate = (*it)->getBooleanValue(CKA_PRIVATE, true);
            // Create an object handle for every returned object.
            CK_OBJECT_HANDLE hObject;
            if (isOnToken)
                hObject = handleManager->addTokenObject(slotID,isPrivate,*it);
            else
                hObject = handleManager->addSessionObject(slotID,hSession,isPrivate,*it);
            if (hObject == CK_INVALID_HANDLE)
            {
                delete findOp;
                return CKR_GENERAL_ERROR;
            }
            handles.insert(hObject);
        }
    }

    // Storing the object handles for the find will protect the library
    // whenever a stale object handle is used to access the library.
    findOp->setHandles(handles);

    session->setFindOp(findOp);

    return CKR_OK;
}

CK_RV SoftHSM::FindObjects(const CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE_PTR phObject,
                           const CK_ULONG& ulMaxObjectCount,
                           CK_ULONG_PTR pulObjectCount)
{
    // Get the session
    Session* session = (Session*)handleManager->getSession(hSession);
    if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

    // Check if we are doing the correct operation
    if (session->getOpType() != SESSION_OP_FIND) return CKR_OPERATION_NOT_INITIALIZED;

    // return the object handles that have been added to the find operation.
    FindOperation *findOp = session->getFindOp();
    if (findOp == NULL) return CKR_GENERAL_ERROR;

    // Ask the find operation to retrieve the object handles
    *pulObjectCount = findOp->retrieveHandles(phObject,ulMaxObjectCount);

    // Erase the object handles from the find operation.
    findOp->eraseHandles(0,*pulObjectCount);

    return CKR_OK;
}
