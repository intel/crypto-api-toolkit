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

#include "config.h"
#include "p11Defines.h"
#include "Constants.h"
#include "CryptoEnclaveDefs.h"

#include <iostream>
#include <vector>
#include <sgx_quote.h>

#ifdef DCAP_SUPPORT
#include "sgx_pce.h"
#endif

#ifdef _WIN32
#include <windows.h>
#include <string>

void Sleep_App(unsigned milliseconds)
{
    Sleep(milliseconds);
}
#else
#include <unistd.h>
#include <cstring>
#include <dlfcn.h>

void Sleep_App(unsigned milliseconds)
{
    usleep(milliseconds * 1000); // takes microseconds
}
#endif

void unloadLibrary(void * p11ProviderHandle)
{
    if (p11ProviderHandle)
    {
        dlclose(p11ProviderHandle);
    }
}

void exitApp(const std::string& outputText)
{
    std::cout << outputText << std::endl;
    Sleep_App(3000);
    exit(0);
}

bool destroyKey(CK_SESSION_HANDLE hSession,
                CK_OBJECT_HANDLE  hKey,
                std::string&      errorMessage);

void cleanUp(CK_FUNCTION_LIST_PTR p11,
             void*                p11ProviderHandle,
             CK_SESSION_HANDLE    hSession,
             CK_OBJECT_HANDLE     hKey,
             CK_OBJECT_HANDLE     hKeyData,
             CK_OBJECT_HANDLE     hAsymKey,
             CK_OBJECT_HANDLE     hAsymPrivateKey)
{
    std::string errorMessage;

    // Destroy all keys..
    destroyKey(hSession, hKey, errorMessage);
    destroyKey(hSession, hKeyData, errorMessage);
    destroyKey(hSession, hAsymKey, errorMessage);
    destroyKey(hSession, hAsymPrivateKey, errorMessage);

    // Close Session..
    p11->C_CloseSession(hSession);

    // Finalize..
    p11->C_Finalize(NULL_PTR);

    // Unload the library..
    unloadLibrary(p11ProviderHandle);

    std::cout << std::endl;
}

bool encryptTests(CK_MECHANISM_TYPE     mechanismType,
                  CK_SESSION_HANDLE     hSession,
                  CK_OBJECT_HANDLE      hKey,
                  std::string&          errorMessage);

bool encryptTestsSinglePass(CK_MECHANISM_TYPE   mechanismType,
                            CK_SESSION_HANDLE   hSession,
                            CK_OBJECT_HANDLE    hKey,
                            std::string&        errorMessage);

bool encryptTests_BlockSizeCBCPAD(CK_MECHANISM_TYPE     mechanismType,
                                  CK_SESSION_HANDLE     hSession,
                                  CK_OBJECT_HANDLE      hKey,
                                  std::string&          errorMessage);

bool encryptTests_NonBlockSizeCBCPAD(CK_MECHANISM_TYPE  mechanismType,
                                     CK_SESSION_HANDLE  hSession,
                                     CK_OBJECT_HANDLE   hKey,
                                     std::string&       errorMessage);

bool aesWrapUnwrapTests(CK_MECHANISM_TYPE   mechanismType,
                        CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hKey,
                        CK_OBJECT_HANDLE    hKey1,
                        std::string&        errorMessage);

bool hashTests(CK_MECHANISM_TYPE    mechanismType,
               CK_SESSION_HANDLE    hSession,
               std::string&         errorMessage,
               CK_OBJECT_HANDLE     hKey = NULL_PTR);

bool hashTestsSinglePass(CK_MECHANISM_TYPE  mechanismType,
                         CK_SESSION_HANDLE  hSession,
                         std::string&       errorMessage,
                         CK_OBJECT_HANDLE   hKey = NULL_PTR);

bool rsaEncryptTests(CK_MECHANISM_TYPE  mechanismType,
                     CK_SESSION_HANDLE  hSession,
                     CK_OBJECT_HANDLE   hKey,
                     CK_OBJECT_HANDLE   hAsymPrivateKey,
                     std::string&       errorMessage);

bool rsaSignVerifyTests(CK_MECHANISM_TYPE   mechanismType,
                        CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hKey,
                        CK_OBJECT_HANDLE    hAsymPrivateKey,
                        std::string&        errorMessage,
                        CK_VOID_PTR         param       = NULL_PTR,
                        CK_ULONG            paramLen    = 0);

bool rsaWrapUnwrapTests(CK_MECHANISM_TYPE   mechanismType,
                        CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hKey,
                        CK_OBJECT_HANDLE    hAsymPublicKey,
                        CK_OBJECT_HANDLE    hAsymPrivateKey,
                        std::string&          errorMessage);

bool findObjects(CK_SESSION_HANDLE hSession, std::string& errorMessage);

bool eccSignVerifyTests(std::string curveName, CK_SESSION_HANDLE hSession, std::string& errorMessage);

#ifdef DCAP_SUPPORT
bool customQuoteEcdsa(CK_MECHANISM_TYPE     mechanismType,
                      CK_SESSION_HANDLE     hSession,
                      CK_OBJECT_HANDLE      hKey,
                      std::string&          errorMessage);
#endif

bool customQuoteEpid(CK_MECHANISM_TYPE     mechanismType,
                     CK_SESSION_HANDLE     hSession,
                     CK_OBJECT_HANDLE      hKey,
                     std::string&          errorMessage);

bool customQuote(CK_MECHANISM_TYPE     mechanismType,
                 CK_SESSION_HANDLE     hSession,
                 CK_OBJECT_HANDLE      hKey,
                 std::string&          errorMessage);

#ifdef IMPORT_RAW_KEY
bool aesGenerateKeyFromBuffer(CK_SESSION_HANDLE hSession,
                              std::string&      errorMessage);
#endif

bool rsaExportImportPublicKey(CK_MECHANISM_TYPE     mechanismType,
                              CK_SESSION_HANDLE     hSession,
                              CK_OBJECT_HANDLE      hKey,
                              std::string&          errorMessage);

CK_FUNCTION_LIST_PTR    p11;

std::string p11ProviderName = (("NONE" == installationPath)? defaultLibraryPath : libraryDirectory) + "libp11sgx.so.0";

int main()
{
    void*                   p11ProviderHandle   = nullptr;
    char*                   errorMsg            = nullptr;
    bool                    result              = false;
    CK_ULONG                mechanismCount      = 0;
    CK_ULONG                slotCount           = 0;
    CK_SLOT_ID              slotID              = 0;
    CK_RV                   p11Status           = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE       hSession            = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE        hKey                = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE        hKeyData            = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE        hAsymKey            = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE        hAsymPrivateKey     = CK_INVALID_HANDLE;
    CK_BBOOL                tokenPresent        = CK_TRUE;
    CK_SLOT_ID_PTR          pSlotList;
    std::string             errorMessage;
    CK_MECHANISM_TYPE_PTR   pMechanismList;
    CK_MECHANISM_INFO       mechanismInfo;
    CK_SLOT_INFO            slotInfo;
    CK_TOKEN_INFO           tokenInfo;

    p11ProviderHandle = dlopen(p11ProviderName.data(), RTLD_NOW | RTLD_LOCAL);
    errorMsg = dlerror();

    if (errorMsg || !p11ProviderHandle)
    {
        if (p11ProviderHandle)
        {
            unloadLibrary(p11ProviderHandle);
        }

        // loading p11Provider library failed
        errorMessage = "FAILED : To load p11Provider library!!";
        exitApp(errorMessage);
    }

    // Retrieve the entry point for C_GetFunctionList
    CK_C_GetFunctionList pGetFunctionList = (CK_C_GetFunctionList) dlsym(p11ProviderHandle, "C_GetFunctionList");

    errorMsg = dlerror();
    if (errorMsg          ||
        !pGetFunctionList ||
        !*pGetFunctionList)
    {
        unloadLibrary(p11ProviderHandle);

        // no such entry point
        errorMessage = "FAILED : To locate entry point C_GetFunctionList!";
        exitApp(errorMessage);
    }

    // Load the function list
    (*pGetFunctionList)(&p11);

    if (!p11)
    {
        unloadLibrary(p11ProviderHandle);
        errorMessage = "FAILED : To locate entry point C_GetFunctionList!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_Initialize(NULL_PTR);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To initialize PKCS#11 library!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_GetSlotList(tokenPresent, NULL_PTR, &slotCount);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To Get number of slots available!";
        exitApp(errorMessage);
    }

    pSlotList = (CK_SLOT_ID_PTR) malloc(slotCount * sizeof(CK_SLOT_ID));
    if (!pSlotList)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To allocate memory!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_GetSlotList(tokenPresent, pSlotList, &slotCount);
    if (CKR_OK != p11Status)
    {
        free(pSlotList);
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To Get the slot list!";
        exitApp(errorMessage);
    }

    for (auto i = 0; i < slotCount; i++)
    {
        CK_TOKEN_INFO tokenInfo;

        p11Status = p11->C_GetTokenInfo(pSlotList[i], &tokenInfo);
        if (CKR_OK != p11Status)
        {
            free(pSlotList);
            cleanUp(p11,
                    p11ProviderHandle,
                    hSession,
                    hKey,
                    hKeyData,
                    hAsymKey,
                    hAsymPrivateKey);
            errorMessage = "FAILED : To Get the token info!";
            exitApp(errorMessage);
        }

        if (!(CKF_TOKEN_INITIALIZED & tokenInfo.flags)) // The slot is free if token is not initialized.
        {
            slotID = pSlotList[i];
        }
    }

    free(pSlotList);

    const CK_UTF8CHAR_PTR soPin((CK_UTF8CHAR_PTR)"12345678");
    const CK_ULONG        soPinLength(strlen((char*)soPin));
    CK_UTF8CHAR           label[32];

    memset(label, ' ', 32);
    memcpy(label, "token0", strlen("token0"));

    p11Status = p11->C_InitToken(slotID, soPin, soPinLength, label);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To Init Token!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_GetSlotInfo(slotID, &slotInfo);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To get slot info!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_GetTokenInfo(slotID, &tokenInfo);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To get token info!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_GetMechanismList(slotID, NULL_PTR, &mechanismCount);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To Get Count of Mechanisms supported!";
        exitApp(errorMessage);
    }

    if (0 == mechanismCount)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : Number of mechanisms supported are 0!";
        exitApp(errorMessage);
    }

    pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(mechanismCount * sizeof(CK_MECHANISM_TYPE));
    if (!pMechanismList)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To allocate memory!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_GetMechanismList(slotID, pMechanismList, &mechanismCount);
    if (CKR_OK != p11Status)
    {
        free(pMechanismList);
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To get list of mechanisms supported!";
        exitApp(errorMessage);
    }

    free(pMechanismList);

    p11Status = p11->C_GetMechanismInfo(slotID, CKM_AES_KEY_GEN, &mechanismInfo);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To get mechanisms info!";
        exitApp(errorMessage);
    }

    p11Status = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To Open Session!";
        exitApp(errorMessage);
    }

    CK_MECHANISM        mechanism       = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_KEY_TYPE         aesKeyType      = CKK_AES;
    CK_OBJECT_CLASS     aesKeyClass     = CKO_SECRET_KEY;
    CK_BBOOL            bTrue           = CK_TRUE;
    CK_ULONG            keyLength       = 16;
    CK_UTF8CHAR         aesKeyLabel[]   = "AES Key Label";
    CK_ATTRIBUTE        keyAttribs[]    = {{ CKA_ENCRYPT,       &bTrue,       sizeof(bTrue)     },
                                           { CKA_DECRYPT,       &bTrue,       sizeof(bTrue)     },
                                           { CKA_WRAP,          &bTrue,       sizeof(bTrue)     },
                                           { CKA_UNWRAP,        &bTrue,       sizeof(bTrue)     },
                                           { CKA_VALUE_LEN,     &keyLength,   sizeof(keyLength) },
                                           { CKA_KEY_TYPE,      &aesKeyType,  sizeof(aesKeyType)   },
                                           { CKA_CLASS,         &aesKeyClass, sizeof(aesKeyClass)  },
                                           { CKA_LABEL,         aesKeyLabel,  sizeof(aesKeyLabel)-1 }
                                           };

    p11Status = p11->C_GenerateKey(hSession,
                                   &mechanism,
                                   keyAttribs,
                                   sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                   &hKey);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To GenerateKey!";
        exitApp(errorMessage);
    }
    p11Status = p11->C_GenerateKey(hSession,
                                   &mechanism,
                                   keyAttribs,
                                   sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                   &hKeyData);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To GenerateKey!";
        exitApp(errorMessage);
    }


    CK_KEY_TYPE     rsaKeyType           = CKK_RSA;
    CK_OBJECT_CLASS rsaPublicKeyClass    = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS rsaPrivateKeyClass   = CKO_PRIVATE_KEY;
    CK_UTF8CHAR     rsaPublicKeyLabel[]  = "RSA Public Key Label";
    CK_UTF8CHAR     rsaPrivateKeyLabel[] = "RSA Private Key Label";
    CK_UTF8CHAR     id[] = "1";

    CK_ULONG modulusBits = 1024;
    CK_ATTRIBUTE asymKeyAttribs[] = {{ CKA_ENCRYPT,         &bTrue,             sizeof(bTrue) },
                                     { CKA_VERIFY,          &bTrue,             sizeof(bTrue) },
                                     { CKA_WRAP,            &bTrue,             sizeof(bTrue) },
                                     { CKA_MODULUS_BITS,    &modulusBits,       sizeof(modulusBits) },
                                     { CKA_KEY_TYPE,        &rsaKeyType,        sizeof(rsaKeyType)   },
                                     { CKA_CLASS,           &rsaPublicKeyClass, sizeof(rsaPublicKeyClass)  },
                                     { CKA_LABEL,           rsaPublicKeyLabel,  sizeof(rsaPublicKeyLabel)-1 },
                                     { CKA_ID,              &id[0],             sizeof(id) }
                                     };

    CK_ATTRIBUTE asymPrivateKeyAttribs[] = {{ CKA_DECRYPT,  &bTrue,              sizeof(bTrue) },
                                            { CKA_SIGN,     &bTrue,              sizeof(bTrue) },
                                            { CKA_UNWRAP,   &bTrue,              sizeof(bTrue) },
                                            { CKA_KEY_TYPE, &rsaKeyType,         sizeof(rsaKeyType)   },
                                            { CKA_CLASS,    &rsaPrivateKeyClass, sizeof(rsaPrivateKeyClass)  },
                                            { CKA_LABEL,    rsaPrivateKeyLabel,  sizeof(rsaPrivateKeyLabel)-1 },
                                            { CKA_ID,       &id[0],              sizeof(id) }
                                            };

    mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    p11Status = p11->C_GenerateKeyPair(hSession,
                                       &mechanism,
                                       asymKeyAttribs,
                                       sizeof(asymKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                       asymPrivateKeyAttribs,
                                       sizeof(asymPrivateKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                       &hAsymKey,
                                       &hAsymPrivateKey);
    if (CKR_OK != p11Status)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        errorMessage = "FAILED : To GenerateKeyPair!";
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> update --> final) with AES-CTR" << std::endl;
    result = encryptTests(CKM_AES_CTR, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> update --> final) with AES-GCM" << std::endl;
    result = encryptTests(CKM_AES_GCM, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> update --> final) with AES-CBC" << std::endl;
    result = encryptTests(CKM_AES_CBC, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> update --> final) with AES-CBC (Input block size with Padding)" << std::endl;
    result = encryptTests_BlockSizeCBCPAD(CKM_AES_CBC_PAD, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> update --> final) with AES-CBC (Input non block size with Padding)" << std::endl;
    result = encryptTests_NonBlockSizeCBCPAD(CKM_AES_CBC_PAD, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> encrypt/decrypt) with AES-CTR" << std::endl;
    result = encryptTestsSinglePass(CKM_AES_CTR, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> encrypt/decrypt) with AES-GCM" << std::endl;
    result = encryptTestsSinglePass(CKM_AES_GCM, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> encrypt/decrypt) with AES-CBC" << std::endl;
    result = encryptTestsSinglePass(CKM_AES_CBC, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption (init --> encrypt/decrypt) with AES-CBC_PAD" << std::endl;
    result = encryptTestsSinglePass(CKM_AES_CBC_PAD, hSession, hKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

#ifdef IMPORT_RAW_KEY
    std::cout << "Importing AES raw key" << std::endl;
    result = aesGenerateKeyFromBuffer(hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }
#endif

    std::cout << "Executing wrap/unwrap with AES-CTR" << std::endl;
    result = aesWrapUnwrapTests(CKM_AES_CTR, hSession, hKey, hKeyData, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing wrap/unwrap with AES-GCM" << std::endl;
    result = aesWrapUnwrapTests(CKM_AES_GCM, hSession, hKey, hKeyData, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing wrap/unwrap with AES-CBC" << std::endl;
    result = aesWrapUnwrapTests(CKM_AES_CBC, hSession, hKey, hKeyData, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing wrap/unwrap with AES-CBC(Padding)" << std::endl;
    result = aesWrapUnwrapTests(CKM_AES_CBC_PAD, hSession, hKey, hKeyData, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing hash with SHA256 (init --> update --> final)" << std::endl;
    result = hashTests(CKM_SHA256, hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing hash with SHA512 (init --> update --> final)" << std::endl;
    result = hashTests(CKM_SHA512, hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing HMAC with SHA256 (init --> update --> final)" << std::endl;
    result = hashTests(CKM_SHA256_HMAC_AES_KEYID, hSession, errorMessage, hKey);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing HMAC with SHA512 (init --> update --> final)" << std::endl;
    result = hashTests(CKM_SHA512_HMAC_AES_KEYID, hSession, errorMessage, hKeyData);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing hash with SHA256 (init --> digest)" << std::endl;
    result = hashTestsSinglePass(CKM_SHA256, hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing hash with SHA512 (init --> digest)" << std::endl;
    result = hashTestsSinglePass(CKM_SHA512, hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing HMAC with SHA256 (init --> digest)" << std::endl;
    result = hashTestsSinglePass(CKM_SHA256_HMAC_AES_KEYID, hSession, errorMessage, hKey);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Computing HMAC with SHA256 (init --> digest)" << std::endl;
    result = hashTestsSinglePass(CKM_SHA512_HMAC_AES_KEYID, hSession, errorMessage, hKey);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption with RSA PKCS1 padding" << std::endl;
    result = rsaEncryptTests(CKM_RSA_PKCS, hSession, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing encryption/decryption with RSA OAEP padding" << std::endl;
    result = rsaEncryptTests(CKM_RSA_PKCS_OAEP, hSession, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with RSA(CKM_RSA_PKCS)" << std::endl;
    result = rsaSignVerifyTests(CKM_RSA_PKCS, hSession, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with RSA(CKM_RSA_PKCS_PSS)" << std::endl;
    CK_RSA_PKCS_PSS_PARAMS params = { CKM_SHA256, 0, 32 };
    result = rsaSignVerifyTests(CKM_RSA_PKCS_PSS, hSession, hAsymKey, hAsymPrivateKey, errorMessage, &params, sizeof(params));
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with RSA(CKM_SHA256_RSA_PKCS)" << std::endl;
    result = rsaSignVerifyTests(CKM_SHA256_RSA_PKCS, hSession, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with RSA(CKM_SHA512_RSA_PKCS)" << std::endl;
    result = rsaSignVerifyTests(CKM_SHA512_RSA_PKCS, hSession, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with RSA(CKM_SHA256_RSA_PKCS_PSS)" << std::endl;
    result = rsaSignVerifyTests(CKM_SHA256_RSA_PKCS_PSS, hSession, hAsymKey, hAsymPrivateKey, errorMessage, &params, sizeof(params));
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with RSA(CKM_SHA512_RSA_PKCS_PSS)" << std::endl;
    result = rsaSignVerifyTests(CKM_SHA512_RSA_PKCS_PSS, hSession, hAsymKey, hAsymPrivateKey, errorMessage, &params, sizeof(params));
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing wrap/unwrap with RSA PKCS1 padding" << std::endl;
    result = rsaWrapUnwrapTests(CKM_RSA_PKCS, hSession, hKey, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing wrap/unwrap with RSA OAEP padding" << std::endl;
    result = rsaWrapUnwrapTests(CKM_RSA_PKCS_OAEP, hSession, hKey, hAsymKey, hAsymPrivateKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Exporting and Importing RSA public key" << std::endl;
    result = rsaExportImportPublicKey(CKM_EXPORT_RSA_PUBLIC_KEY, hSession, hAsymKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Finding Objects" << std::endl;
    result = findObjects(hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

#ifdef DCAP_SUPPORT
    std::cout << "Retrieving Quote+Public key - ECDSA" << std::endl;
    result = customQuote(CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY, hSession, hAsymKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }
#endif

    std::cout << "Retrieving Quote+Public key - EPID" << std::endl;
    result = customQuote(CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY, hSession, hAsymKey, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with EC - p256" << std::endl;
    result = eccSignVerifyTests("p256", hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    std::cout << "Executing sign/verify with EC - p384" << std::endl;
    result = eccSignVerifyTests("p384", hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

	std::cout << "Executing sign/verify with EC EDWARDS- ed25519" << std::endl;
    result = eccSignVerifyTests("ed25519", hSession, errorMessage);
    if (!result)
    {
        cleanUp(p11,
                p11ProviderHandle,
                hSession,
                hKey,
                hKeyData,
                hAsymKey,
                hAsymPrivateKey);
        exitApp(errorMessage);
    }

    cleanUp(p11,
            p11ProviderHandle,
            hSession,
            hKey,
            hKeyData,
            hAsymKey,
            hAsymPrivateKey);

    std::cout << "All Paths Executed! " << std::endl;
    return 0;
}

bool encryptTests(CK_MECHANISM_TYPE     mechanismType,
                  CK_SESSION_HANDLE     hSession,
                  CK_OBJECT_HANDLE      hKey,
                  std::string&          errorMessage)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    CK_RV                   p11Status           = CKR_GENERAL_ERROR;
    CK_ULONG                bytesDone           = 0;
    CK_ULONG                encryptedBytes      = 0;
    uint32_t                tagBits             = 0;
    uint32_t                tagBytes            = 0;
    const uint32_t          sourceBufferSize    = 16;
    bool                    result              = false;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    sourceBuffer(sourceBufferSize, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());

    if (CKM_AES_GCM == mechanismType)
    {
        tagBytes = 16;
        tagBits  = tagBytes * 8;
    }

    CK_AES_CTR_PARAMS   ctrParams =
    {
        128,
        {
            0x01, 0x02, 0x03, 0x30, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        }
    };

    CK_BYTE gcmIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    };
    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };
    CK_BYTE gcmAAD[] = {
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2
    };
    CK_GCM_PARAMS gcmParams =
    {
        &gcmIV[0],
        sizeof(gcmIV),
        sizeof(gcmIV) * 8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        tagBits
    };

    do
    {
        switch (mechanismType)
        {
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
                pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;
            case CKM_AES_CTR:
                pMechanism->pParameter = &ctrParams;
                pMechanism->ulParameterLen = sizeof(ctrParams);
                break;
            case CKM_AES_GCM:
                pMechanism->pParameter = &gcmParams;
                pMechanism->ulParameterLen = sizeof(gcmParams);
                break;
            default:
                break;
        }

        p11Status = p11->C_EncryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptInit!");
            break;
        }

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data(), sourceBufferSize, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        destBuffer.resize(bytesDone);

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data(), sourceBufferSize, destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        bytesDone = 0;

        p11Status = p11->C_EncryptFinal(hSession, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptFinal!");
            break;
        }

        encryptedBytes = destBuffer.size();
        destBuffer.resize(destBuffer.size() + bytesDone);

        p11Status = p11->C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptFinal!");
            break;
        }
        destBuffer.resize(encryptedBytes + bytesDone);

        // Decryption!
        bytesDone = 0;
        std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);
        CK_ULONG decryptedBytes = 0;

        p11Status = p11->C_DecryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptInit!");
            break;
        }

        // tagBytes will be 0 for non GCM mechanisms
        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data(), sourceBufferSize + tagBytes, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }

        decryptedBuffer.resize(bytesDone);  // bytesDone will be 0 for GCM(DecryptUpdate) as it is AEAD cipher..

        // tagBytes will be 0 for non GCM mechanisms
        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data(), sourceBufferSize + tagBytes, decryptedBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }
        decryptedBytes = decryptedBuffer.size();
        bytesDone = 0;

        p11Status = p11->C_DecryptFinal(hSession, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptFinal!");
            break;
        }

        decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

        p11Status = p11->C_DecryptFinal(hSession, decryptedBuffer.data() + decryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptFinal!");
            break;
        }
        decryptedBuffer.resize(decryptedBytes + bytesDone);
        bytesDone = 0;

        if (sourceBuffer != decryptedBuffer)
        {
            result = false;
            switch (mechanismType)
            {
                case CKM_AES_CTR:
                    errorMessage.append("CTR: PlainText and DecryptedText does not match!");
                    break;
                case CKM_AES_GCM:
                    errorMessage.append("GCM: PlainText and DecryptedText does not match!");
                    break;
                default:
                    break;
            }
        }
        else
        {
            result = true;
        }
    } while(false);

    return result;
}

bool encryptTestsSinglePass(CK_MECHANISM_TYPE   mechanismType,
                            CK_SESSION_HANDLE   hSession,
                            CK_OBJECT_HANDLE    hKey,
                            std::string&        errorMessage)
{
    const CK_MECHANISM      mechanism = { mechanismType, NULL_PTR, 0 };
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    const uint32_t          sourceBufferSize    = 16;
    std::vector<CK_BYTE>    sourceBuffer(sourceBufferSize, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());
    uint32_t                tagBytes = 0;
    uint32_t                tagBits  = 0;
    bool                    result   = false;
    CK_AES_CTR_PARAMS ctrParams =
    {
        128,
        {
            0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        }
    };
    CK_BYTE gcmIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    };
    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };
    CK_BYTE gcmAAD[] = {
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2
    };

    if (CKM_AES_GCM == mechanismType)
    {
        tagBytes = 16;
        tagBits = tagBytes * 8;
    }

    CK_GCM_PARAMS gcmParams =
    {
        &gcmIV[0],
        sizeof(gcmIV),
        sizeof(gcmIV) * 8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        tagBits
    };
    do
    {
        switch (mechanismType)
        {
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
                pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;
            case CKM_AES_CTR:
                pMechanism->pParameter = &ctrParams;
                pMechanism->ulParameterLen = sizeof(ctrParams);
                break;
            case CKM_AES_GCM:
                pMechanism->pParameter = &gcmParams;
                pMechanism->ulParameterLen = sizeof(gcmParams);
                break;
            default:
                break;
        }

        CK_RV p11Status = CKR_GENERAL_ERROR;
        CK_ULONG bytesDone = 0;

        p11Status = p11->C_EncryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptInit!");
            break;
        }

        p11Status = p11->C_Encrypt(hSession, sourceBuffer.data(), sourceBuffer.size(), NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Encrypt!");
            break;
        }
        destBuffer.resize(bytesDone);

        p11Status = p11->C_Encrypt(hSession, sourceBuffer.data(), sourceBuffer.size(), destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Encrypt!");
            break;
        }
        destBuffer.resize(bytesDone);
        bytesDone = 0;

        // Decryption!
        std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);

        p11Status = p11->C_DecryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptInit!");
            break;
        }

        p11Status = p11->C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Decrypt!");
            break;
        }
        decryptedBuffer.resize(bytesDone);

        p11Status = p11->C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), decryptedBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Decrypt!");
            break;
        }
        decryptedBuffer.resize(bytesDone);
        bytesDone = 0;

        if (sourceBuffer != decryptedBuffer)
        {
            result = false;
            switch (mechanismType)
            {
                case CKM_AES_CTR:
                    errorMessage.append("CTR: PlainText and DecryptedText does not match!");
                case CKM_AES_GCM:
                    errorMessage.append("GCM: PlainText and DecryptedText does not match!");
                case CKM_AES_CBC:
                    errorMessage.append("CBC: PlainText and DecryptedText does not match!");
                case CKM_AES_CBC_PAD:
                    errorMessage.append("CBC (Padding): PlainText and DecryptedText does not match!");
                default:
                    break;
            }
        }
        else
        {
            result = true;
        }

    } while (false);

    return result;
}

bool encryptTests_BlockSizeCBCPAD(CK_MECHANISM_TYPE     mechanismType,
                                  CK_SESSION_HANDLE     hSession,
                                  CK_OBJECT_HANDLE      hKey,
                                  std::string&          errorMessage)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    bool                    result              = false;
    const uint32_t          sourceBufferSize    = 16;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    sourceBuffer(sourceBufferSize, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());

    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };

    switch (mechanismType)
    {
        case CKM_AES_CBC_PAD:
            pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
            pMechanism->ulParameterLen = sizeof(cbcIV);
            break;
        default:
            errorMessage.append("InCorrect Function called!");
            break;
    }

    if (0 != errorMessage.size())
    {
        return result;
    }

    CK_RV p11Status = CKR_GENERAL_ERROR;
    CK_ULONG bytesDone = 0;
    CK_ULONG encryptedBytes = 0;

    do
    {
        p11Status = p11->C_EncryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptInit!");
            break;
        }

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data(), 15, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        destBuffer.resize(bytesDone);

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data(), 15, destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        bytesDone = 0;

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 1, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        destBuffer.resize(destBuffer.size() + bytesDone);

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 1, destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        bytesDone = 0;

        p11Status = p11->C_EncryptFinal(hSession, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptFinal!");
            break;
        }

        encryptedBytes = destBuffer.size();
        destBuffer.resize(destBuffer.size() + bytesDone);

        p11Status = p11->C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptFinal!");
            break;
        }
        destBuffer.resize(encryptedBytes + bytesDone);
        bytesDone = 0;

        // Decryption!
        std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);
        CK_ULONG decryptedBytes = 0;

        p11Status = p11->C_DecryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptInit!");
            break;
        }

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data(), 15, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }

        decryptedBuffer.resize(bytesDone);

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data(), 15, decryptedBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }
        decryptedBytes = decryptedBuffer.size();
        bytesDone = 0;

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }

        decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, decryptedBuffer.data() + decryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }
        decryptedBytes = decryptedBuffer.size();
        bytesDone = 0;

        p11Status = p11->C_DecryptFinal(hSession, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptFinal!");
            break;
        }

        decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

        p11Status = p11->C_DecryptFinal(hSession, decryptedBuffer.data() + decryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptFinal!");
            break;
        }
        decryptedBuffer.resize(decryptedBytes + bytesDone);
        bytesDone = 0;

        if (sourceBuffer != decryptedBuffer)
        {
            errorMessage.append("CBC (BlockSize input with Padding): PlainText and DecryptedText does not Match!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

bool encryptTests_NonBlockSizeCBCPAD(CK_MECHANISM_TYPE  mechanismType,
                                     CK_SESSION_HANDLE  hSession,
                                     CK_OBJECT_HANDLE   hKey,
                                     std::string&       errorMessage)
{
    const CK_MECHANISM      mechanism = { mechanismType, NULL_PTR, 0 };
    bool                    result    = false;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    sourceBuffer(18, 1);
    std::vector<CK_BYTE>    destBuffer(sourceBuffer.size());

    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };

    do
    {
        switch (mechanismType)
        {
            case CKM_AES_CBC_PAD:
                pMechanism->pParameter = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;

            default:
                errorMessage.append("InCorrect Function called!");
                break;
        }

        if (0 != errorMessage.size())
        {
            return result;
        }

        CK_RV p11Status = CKR_GENERAL_ERROR;
        CK_ULONG bytesDone = 0;
        CK_ULONG encryptedBytes = 0;

        p11Status = p11->C_EncryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptInit!");
            break;
        }

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data(), 15, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        destBuffer.resize(bytesDone);

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data(), 15, destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        bytesDone = 0;

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 3, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        destBuffer.resize(destBuffer.size() + bytesDone);

        p11Status = p11->C_EncryptUpdate(hSession, sourceBuffer.data() + 15, 3, destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptUpdate!");
            break;
        }
        bytesDone = 0;

        p11Status = p11->C_EncryptFinal(hSession, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptFinal!");
            break;
        }

        encryptedBytes = destBuffer.size();
        destBuffer.resize(destBuffer.size() + bytesDone);

        p11Status = p11->C_EncryptFinal(hSession, destBuffer.data() + encryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptFinal!");
            break;
        }
        destBuffer.resize(encryptedBytes + bytesDone);
        bytesDone = 0;

        // Decryption!
        std::vector<CK_BYTE> decryptedBuffer(sourceBuffer.size(), 0);
        CK_ULONG decryptedBytes = 0;

        p11Status = p11->C_DecryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptInit!");
            break;
        }

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data(), 15, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }

        decryptedBuffer.resize(bytesDone);

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data(), 15, decryptedBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }
        decryptedBytes = decryptedBuffer.size();
        bytesDone = 0;

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }

        decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

        p11Status = p11->C_DecryptUpdate(hSession, destBuffer.data() + 15, destBuffer.size() - 15, decryptedBuffer.data() + decryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptUpdate!");
            break;
        }
        decryptedBytes = decryptedBuffer.size();
        bytesDone = 0;

        p11Status = p11->C_DecryptFinal(hSession, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptFinal!");
            break;
        }

        decryptedBuffer.resize(decryptedBuffer.size() + bytesDone);

        p11Status = p11->C_DecryptFinal(hSession, decryptedBuffer.data() + decryptedBytes, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptFinal!");
            break;
        }
        decryptedBuffer.resize(decryptedBytes + bytesDone);
        if (sourceBuffer != decryptedBuffer)
        {
            errorMessage.append("CBC (BlockSize input with Padding): PlainText and DecryptedText does not Match!");
            break;
        }
        bytesDone = 0;

        result = true;
    } while (false);

    return result;
}

bool aesWrapUnwrapTests(CK_MECHANISM_TYPE   mechanismType,
                        CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hKey,
                        CK_OBJECT_HANDLE    hKeyData,
                        std::string&        errorMessage)
{
    CK_RV                   p11Status       = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism       = { mechanismType, NULL_PTR, 0 };
    CK_OBJECT_HANDLE        hUnwrappedKey   = CK_INVALID_HANDLE;
    CK_BBOOL                bTrue           = CK_TRUE;
    CK_ULONG                wrappedLen      = 0UL;
    bool                    result          = false;
    CK_KEY_TYPE             aesKeyType      = CKK_AES;
    CK_OBJECT_CLASS         aesKeyClass     = CKO_SECRET_KEY;
    CK_UTF8CHAR             aesKeyLabel[]   = "AES Key Label For Wrap/Unwrap";
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);
    std::vector<CK_BYTE>    wrappedData;

    CK_AES_CTR_PARAMS ctrParams =
    {
        128,
        {
            0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        }
    };
    CK_BYTE gcmIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
    };
    CK_BYTE cbcIV[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE,
        0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xBA, 0xBE
    };
    CK_BYTE gcmAAD[] = {
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2
    };
    CK_ULONG tagBits = 128;
    CK_GCM_PARAMS gcmParams =
    {
        &gcmIV[0],
        sizeof(gcmIV),
        sizeof(gcmIV) * 8,
        &gcmAAD[0],
        sizeof(gcmAAD),
        tagBits
    };

    do
    {
        switch (mechanismType)
        {
            case CKM_AES_CBC_PAD:
            case CKM_AES_CBC:
                pMechanism->pParameter     = reinterpret_cast<CK_VOID_PTR>(&cbcIV[0]);
                pMechanism->ulParameterLen = sizeof(cbcIV);
                break;
            case CKM_AES_CTR:
                pMechanism->pParameter      = &ctrParams;
                pMechanism->ulParameterLen  = sizeof(ctrParams);
                break;
            case CKM_AES_GCM:
                pMechanism->pParameter      = &gcmParams;
                pMechanism->ulParameterLen  = sizeof(gcmParams);
                break;
            default:
                break;
        }
        p11Status = p11->C_WrapKey(hSession,
                                   &mechanism,
                                   hKey,
                                   hKeyData,
                                   NULL_PTR,
                                   &wrappedLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey!");
            break;
        }
        wrappedData.resize(wrappedLen);
        p11Status = p11->C_WrapKey(hSession,
                                   &mechanism,
                                   hKey,
                                   hKeyData,
                                   wrappedData.data(),
                                   &wrappedLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey!");
            break;
        }

        CK_ATTRIBUTE keyAttribs[] = {{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
                                     { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
                                     { CKA_WRAP,    &bTrue, sizeof(bTrue) },
                                     { CKA_UNWRAP,  &bTrue, sizeof(bTrue) },
                                     { CKA_KEY_TYPE,      &aesKeyType,  sizeof(aesKeyType)   },
                                     { CKA_CLASS,         &aesKeyClass, sizeof(aesKeyClass)  },
                                     { CKA_LABEL,         aesKeyLabel,  sizeof(aesKeyLabel)-1 }};


        p11Status = p11->C_UnwrapKey(hSession,
                                     &mechanism,
                                     hKey,
                                     wrappedData.data(),
                                     wrappedLen,
                                     keyAttribs,
                                     sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                     &hUnwrappedKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_UnwrapKey!");
            break;
        }

        result = destroyKey(hSession, hUnwrappedKey, errorMessage);

    } while (false);

    return result;
}

bool hashTests(CK_MECHANISM_TYPE    mechanismType,
               CK_SESSION_HANDLE    hSession,
               std::string&         errorMessage,
               CK_OBJECT_HANDLE     hKey)
{
    CK_RV                       p11Status      = CKR_GENERAL_ERROR;
    CK_MECHANISM                mechanism      = { mechanismType, NULL_PTR, 0 };
    bool                        result         = false;
    CK_HMAC_AES_KEYID_PARAMS    hmacParams;
    CK_MECHANISM_PTR            pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        if (CKM_SHA256_HMAC_AES_KEYID == mechanismType ||
            CKM_SHA512_HMAC_AES_KEYID == mechanismType)
        {
            hmacParams                  = { hKey };
            pMechanism->pParameter      = &hmacParams;
            pMechanism->ulParameterLen  = sizeof(hmacParams);
        }
        p11Status = p11->C_DigestInit(hSession, pMechanism);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestInit!");
            break;
        }
        std::vector<CK_BYTE> sourceBuffer = { 0x68, 0x65, 0x6c, 0x6c, 0x6f };
        p11Status = p11->C_DigestUpdate(hSession, sourceBuffer.data(), sourceBuffer.size());
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestUpdate!");
            break;
        }

        std::vector<CK_BYTE> hashedData;
        CK_ULONG hashedDataSize = 0;
        p11Status = p11->C_DigestFinal(hSession, NULL_PTR, &hashedDataSize);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestFinal!");
            break;
        }
        hashedData.resize(hashedDataSize);
        p11Status = p11->C_DigestFinal(hSession, hashedData.data(), &hashedDataSize);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestFinal!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

bool hashTestsSinglePass(CK_MECHANISM_TYPE  mechanismType,
                         CK_SESSION_HANDLE  hSession,
                         std::string&       errorMessage,
                         CK_OBJECT_HANDLE   hKey)
{
    CK_RV                       p11Status      = CKR_GENERAL_ERROR;
    CK_MECHANISM                mechanism      = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                    hashedDataSize = 0;
    bool                        result         = false;
    std::vector<CK_BYTE>        hashedData;
    CK_HMAC_AES_KEYID_PARAMS    hmacParams;
    CK_MECHANISM_PTR            pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        if (CKM_SHA256_HMAC_AES_KEYID == mechanismType ||
            CKM_SHA512_HMAC_AES_KEYID == mechanismType)
        {
            hmacParams                  = { hKey };
            pMechanism->pParameter      = &hmacParams;
            pMechanism->ulParameterLen  = sizeof(hmacParams);
        }
        p11Status = p11->C_DigestInit(hSession, pMechanism);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestInit!");
            break;
        }
        std::vector<CK_BYTE> sourceBuffer = { 0x68, 0x65, 0x6c, 0x6c, 0x6f };
        p11Status = p11->C_Digest(hSession, sourceBuffer.data(), sourceBuffer.size(), nullptr, &hashedDataSize);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Digest!");
            break;
        }
        hashedData.resize(hashedDataSize);
        p11Status = p11->C_Digest(hSession, sourceBuffer.data(), sourceBuffer.size(), hashedData.data(), &hashedDataSize);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Digest!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

bool rsaEncryptTests(CK_MECHANISM_TYPE  mechanismType,
                     CK_SESSION_HANDLE  hSession,
                     CK_OBJECT_HANDLE   hKey,
                     CK_OBJECT_HANDLE   hAsymPrivateKey,
                     std::string&       errorMessage)
{
    const CK_MECHANISM      mechanism           = { mechanismType, NULL_PTR, 0 };
    CK_RV                   p11Status           = CKR_GENERAL_ERROR;
    CK_ULONG                bytesDone           = 0;
    bool                    result              = false;
    const uint32_t          sourceBufferSize    = 16;
    std::vector<CK_BYTE>    destBuffer;
    std::vector<CK_BYTE>    sourceBuffer(sourceBufferSize, 1);
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        p11Status = p11->C_EncryptInit(hSession, pMechanism, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_EncryptInit!");
            break;
        }

        p11Status = p11->C_Encrypt(hSession, sourceBuffer.data(), sourceBufferSize, NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Encrypt!");
            break;
        }

        destBuffer.resize(bytesDone);
        p11Status = p11->C_Encrypt(hSession, sourceBuffer.data(), sourceBufferSize, destBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Encrypt!");
            break;
        }
        bytesDone = 0;

        p11Status = p11->C_DecryptInit(hSession, pMechanism, hAsymPrivateKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DecryptInit!");
            break;
        }

        std::vector<CK_BYTE> decryptedBuffer;
        p11Status = p11->C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Decrypt!");
            break;
        }

        decryptedBuffer.resize(bytesDone);
        p11Status = p11->C_Decrypt(hSession, destBuffer.data(), destBuffer.size(), decryptedBuffer.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Decrypt!");
            break;
        }
        bytesDone = 0;
        if (sourceBuffer != decryptedBuffer)
        {
            errorMessage.append("RSA: PlainText and DecryptedText does not match!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

bool rsaSignVerifyTests(CK_MECHANISM_TYPE   mechanismType,
                        CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hPublicKey,
                        CK_OBJECT_HANDLE    hPrivateKey,
                        std::string&        errorMessage,
                        CK_VOID_PTR         param,
                        CK_ULONG            paramLen)
{
    const CK_MECHANISM      mechanism    = { mechanismType, param, paramLen };
    CK_RV                   p11Status    = CKR_GENERAL_ERROR;
    CK_ULONG                bytesDone    = 0;
    bool                    result       = false;
    std::vector<CK_BYTE>    signature;
    std::vector<CK_BYTE>    sourceBuffer(40, 1);
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        p11Status = p11->C_SignInit(hSession, pMechanism, hPrivateKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_SignInit!");
            break;
        }

        p11Status = p11->C_Sign(hSession, sourceBuffer.data(), sourceBuffer.size(), NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Sign!");
            break;
        }

        signature.resize(bytesDone);
        p11Status = p11->C_Sign(hSession, sourceBuffer.data(), sourceBuffer.size(), signature.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Sign!");
            break;
        }

        p11Status = p11->C_VerifyInit(hSession, pMechanism, hPublicKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_VerifyInit!");
            break;
        }

        p11Status = p11->C_Verify(hSession, sourceBuffer.data(), sourceBuffer.size(), signature.data(), signature.size());
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Verify!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

bool rsaWrapUnwrapTests(CK_MECHANISM_TYPE   mechanismType,
                        CK_SESSION_HANDLE   hSession,
                        CK_OBJECT_HANDLE    hKey,
                        CK_OBJECT_HANDLE    hAsymPublicKey,
                        CK_OBJECT_HANDLE    hAsymPrivateKey,
                        std::string&        errorMessage)
{
    const CK_MECHANISM      mechanism       = { mechanismType, NULL_PTR, 0 };
    CK_RV                   p11Status       = CKR_GENERAL_ERROR;
    CK_OBJECT_HANDLE        hUnwrappedKey   = CK_INVALID_HANDLE;
    CK_ULONG                bytesDone       = 0;
    bool                    result          = false;
    CK_KEY_TYPE             aesKeyType      = CKK_AES;
    CK_OBJECT_CLASS         aesKeyClass     = CKO_SECRET_KEY;
    CK_UTF8CHAR             aesKeyLabel[]   = "AES Key Label for RSA Unwrap";
    std::vector<CK_BYTE>    wrappedKeyBuffer;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        p11Status = p11->C_WrapKey(hSession,
                                   pMechanism,
                                   hAsymPublicKey,
                                   hKey,
                                   NULL_PTR,
                                   &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey!");
            break;
        }

        wrappedKeyBuffer.resize(bytesDone);
        p11Status = p11->C_WrapKey(hSession,
                                   pMechanism,
                                   hAsymPublicKey,
                                   hKey,
                                   wrappedKeyBuffer.data(),
                                   &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey!");
            break;
        }

        CK_BBOOL bTrue  = CK_TRUE;
        CK_ATTRIBUTE keyAttribs[] = {{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
                                     { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
                                     { CKA_WRAP,    &bTrue, sizeof(bTrue) },
                                     { CKA_UNWRAP,  &bTrue, sizeof(bTrue) },
                                     { CKA_KEY_TYPE,      &aesKeyType,  sizeof(aesKeyType)   },
                                     { CKA_CLASS,         &aesKeyClass, sizeof(aesKeyClass)  },
                                     { CKA_LABEL,         aesKeyLabel,  sizeof(aesKeyLabel)-1 }};

        p11Status = p11->C_UnwrapKey(hSession,
                                     pMechanism,
                                     hAsymPrivateKey,
                                     wrappedKeyBuffer.data(),
                                     wrappedKeyBuffer.size(),
                                     keyAttribs,
                                     sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                     &hUnwrappedKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_UnwrapKey!");
            break;
        }

        result = destroyKey(hSession, hUnwrappedKey, errorMessage);

    } while (false);

    return result;
}

bool destroyKey(CK_SESSION_HANDLE hSession,
                CK_OBJECT_HANDLE  hKey,
                std::string&      errorMessage)
{
    CK_RV   p11Status = CKR_GENERAL_ERROR;
    bool    result    = false;
    do
    {
        p11Status = p11->C_DestroyObject(hSession, hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : To DestroyObject!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

#ifdef IMPORT_RAW_KEY
bool aesGenerateKeyFromBuffer(CK_SESSION_HANDLE    hSession,
                              std::string&         errorMessage)
{
    CK_RV               p11Status     = CKR_GENERAL_ERROR;
    CK_OBJECT_HANDLE    hKey          = CK_INVALID_HANDLE;
    CK_MECHANISM        mechanism     = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_BBOOL            bTrue         = CK_TRUE;
    CK_BBOOL            bFalse        = CK_FALSE;
    CK_KEY_TYPE         keyType       = CKK_AES;
    bool                result        = false;
    CK_KEY_TYPE         aesKeyType    = CKK_AES;
    CK_OBJECT_CLASS     aesKeyClass   = CKO_SECRET_KEY;
    CK_UTF8CHAR         aesKeyLabel[] = "AES Key Label";
    CK_BYTE             value[]       = { 0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xFA, 0xCE,
                                          0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88, 0xFA, 0xCE };
    CK_ATTRIBUTE        keyAttribs[]  = { { CKA_ENCRYPT,          &bTrue, sizeof(bTrue) },
                                          { CKA_DECRYPT,          &bTrue, sizeof(bTrue) },
                                          { CKA_WRAP,             &bTrue, sizeof(bTrue) },
                                          { CKA_UNWRAP,           &bTrue, sizeof(bTrue) },
                                          { CKA_VALUE_KEY_BUFFER, &value, sizeof(value) },
                                          { CKA_KEY_TYPE,      &aesKeyType,  sizeof(aesKeyType)   },
                                          { CKA_CLASS,         &aesKeyClass, sizeof(aesKeyClass)  },
                                          { CKA_LABEL,         aesKeyLabel,  sizeof(aesKeyLabel)-1 }};
    do
    {
        p11Status = p11->C_GenerateKey(hSession,
                                       &mechanism,
                                       keyAttribs,
                                       sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
                                       &hKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : To GenerateKey!");
            break;
        }

        result = destroyKey(hSession, hKey, errorMessage);

    } while (false);

    return result;
}
#endif

bool rsaExportImportPublicKey(CK_MECHANISM_TYPE     mechanismType,
                              CK_SESSION_HANDLE     hSession,
                              CK_OBJECT_HANDLE      hKey,
                              std::string&          errorMessage)
{
    CK_RV                           p11Status       = CKR_GENERAL_ERROR;
    CK_MECHANISM                    mechanism       = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                        exportedKeyLen  = 0UL;
    uint32_t                        offset          = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
    CK_OBJECT_HANDLE                hImportAsymKey  = 0;
    bool                            result          = false;
    std::vector<CK_BYTE>            modulus;
    std::vector<CK_BYTE>            exponent;
    std::vector<CK_BYTE>            exportedKey;
    CK_RSA_PUBLIC_KEY_PARAMS        rsaPublicKeyParams{};
    CK_KEY_TYPE                     rsaKeyType           = CKK_RSA;
    CK_OBJECT_CLASS                 rsaPublicKeyClass    = CKO_PUBLIC_KEY;
    CK_UTF8CHAR                     rsaPublicKeyLabel[]  = "RSA Public Key Label";
    CK_ATTRIBUTE                    asymKeyAttribs[] = {{ CKA_KEY_TYPE,  &rsaKeyType,        sizeof(rsaKeyType)   },
                                                        { CKA_CLASS,     &rsaPublicKeyClass, sizeof(rsaPublicKeyClass)  },
                                                        { CKA_LABEL,     rsaPublicKeyLabel,  sizeof(rsaPublicKeyLabel)-1 } };

    do
    {
        // Exporting Public Key...
        p11Status = p11->C_WrapKey(hSession,
                                   &mechanism,
                                   NULL_PTR,
                                   hKey,
                                   NULL_PTR,
                                   &exportedKeyLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey : ExportRSAPublicKey!");
            break;
        }

        exportedKey.resize(exportedKeyLen);
        p11Status = p11->C_WrapKey(hSession,
                                   &mechanism,
                                   NULL_PTR,
                                   hKey,
                                   exportedKey.data(),
                                   &exportedKeyLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey : ExportRSAPublicKey!");
            break;
        }

        memcpy(&rsaPublicKeyParams, exportedKey.data(), sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
        exponent.resize(rsaPublicKeyParams.ulExponentLen);
        memcpy(exponent.data(), exportedKey.data() + offset, rsaPublicKeyParams.ulExponentLen);
        offset += rsaPublicKeyParams.ulExponentLen;
        modulus.resize(rsaPublicKeyParams.ulModulusLen);
        memcpy(modulus.data(), exportedKey.data() + offset, rsaPublicKeyParams.ulModulusLen);

        // Importing Public Key...
        mechanism = { CKM_IMPORT_RSA_PUBLIC_KEY, NULL_PTR, 0 };
        p11Status = p11->C_UnwrapKey(hSession,
                                     &mechanism,
                                     NULL_PTR,
                                     exportedKey.data(),
                                     exportedKey.size(),
                                     asymKeyAttribs,
                                     sizeof(asymKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                     &hImportAsymKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_UnwrapKey!");
            break;
        }

        result = destroyKey(hSession, hImportAsymKey, errorMessage);

    } while (false);

    return result;
}

bool computeSHA256Hash(CK_SESSION_HANDLE        hSession,
                       std::vector<CK_BYTE>&    publicKeyData,
                       std::vector<CK_BYTE>&    hashedData,
                       std::string&             errorMessage)
{
    CK_RV               p11Status      = CKR_GENERAL_ERROR;
    CK_MECHANISM        mechanism      = { CKM_SHA256, NULL_PTR, 0 };
    bool                result         = false;
    CK_MECHANISM_PTR    pMechanism((CK_MECHANISM_PTR)&mechanism);

    do
    {
        p11Status = p11->C_DigestInit(hSession, pMechanism);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestInit!");
            break;
        }

        p11Status = p11->C_DigestUpdate(hSession, publicKeyData.data(), publicKeyData.size());
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestUpdate!");
            break;
        }

        CK_ULONG hashedDataSize = 0;
        p11Status = p11->C_DigestFinal(hSession, NULL_PTR, &hashedDataSize);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestFinal!");
            break;
        }
        hashedData.resize(hashedDataSize);
        p11Status = p11->C_DigestFinal(hSession, hashedData.data(), &hashedDataSize);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_DigestFinal!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

bool customQuote(CK_MECHANISM_TYPE     mechanismType,
                 CK_SESSION_HANDLE     hSession,
                 CK_OBJECT_HANDLE      hKey,
                 std::string&          errorMessage)
{
    if (CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY == mechanismType)
    {
        return customQuoteEpid(mechanismType, hSession, hKey, errorMessage);
    }
#ifdef DCAP_SUPPORT
    else if (CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY == mechanismType)
    {
        return customQuoteEcdsa(mechanismType, hSession, hKey, errorMessage);
    }
#endif
    return false;
}

bool customQuoteEpid(CK_MECHANISM_TYPE     mechanismType,
                     CK_SESSION_HANDLE     hSession,
                     CK_OBJECT_HANDLE      hKey,
                      std::string&         errorMessage)
{
    CK_RV                   p11Status          = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism          = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                quotePublicKeyLen  = 0UL;
    CK_ULONG                signatureType      = UNLINKABLE_SIGNATURE;
    bool                    result             = false;
    std::vector<CK_BYTE>    spid { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33 };
    std::vector<CK_BYTE>    sigRL;
    std::vector<CK_BYTE>    quotePublicKey;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteRSAParams =
    {
        spid.data(),
        spid.size(),
        sigRL.data(),
        sigRL.size(),
        signatureType
    };

    do
    {
        pMechanism->pParameter = &quoteRSAParams;
        pMechanism->ulParameterLen = sizeof(quoteRSAParams);

        p11Status = p11->C_WrapKey(hSession,
                                   pMechanism,
                                   NULL_PTR,
                                   hKey,
                                   NULL_PTR,
                                   &quotePublicKeyLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey : customQuote!");
            break;
        }

        quotePublicKey.resize(quotePublicKeyLen);
        p11Status = p11->C_WrapKey(hSession,
                                   pMechanism,
                                   NULL_PTR,
                                   hKey,
                                   quotePublicKey.data(),
                                   &quotePublicKeyLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey : customQuote!");
            break;
        }

        CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParams = reinterpret_cast<CK_RSA_PUBLIC_KEY_PARAMS*>(quotePublicKey.data());
        uint32_t pubKeySize = rsaPublicKeyParams->ulModulusLen + rsaPublicKeyParams->ulExponentLen;
        uint32_t fullPublicKeySize = sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + rsaPublicKeyParams->ulModulusLen + rsaPublicKeyParams->ulExponentLen;

        sgx_quote_t* sgxQuote  = reinterpret_cast<sgx_quote_t*>(quotePublicKey.data() + fullPublicKeySize);
        uint32_t     quoteSize = quotePublicKeyLen - fullPublicKeySize;

        std::vector<CK_BYTE> quote;
        quote.resize(quoteSize);

        memcpy(&quote[0], sgxQuote, quoteSize);

        // Extract the public key and verify its hash
        const uint32_t HASH_LENGTH = 32;
        std::vector<CK_BYTE> publicKeyHashInQuote(HASH_LENGTH, 0);
        std::vector<CK_BYTE> publicKeyData(pubKeySize, 0);

        // Fill the hash vector
        memcpy(publicKeyHashInQuote.data(),
               sgxQuote->report_body.report_data.d,
               HASH_LENGTH);

        // Fill the data vector
        memcpy(publicKeyData.data(),
               quotePublicKey.data() + sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
               pubKeySize);

        // Compute hash of publicKeyData..
        std::vector<CK_BYTE> hashedData;

        std::cout << "Calling EPID Compute hash" << std::endl;
        computeSHA256Hash(hSession, publicKeyData, hashedData, errorMessage);

        if (publicKeyHashInQuote != hashedData)
        {
            errorMessage.append("FAILED : Public key hash and hash in quote mismatch!");
            break;
        }

        result = true;
    } while (false);

    return result;
}

#ifdef DCAP_SUPPORT
bool customQuoteEcdsa(CK_MECHANISM_TYPE     mechanismType,
                      CK_SESSION_HANDLE     hSession,
                      CK_OBJECT_HANDLE      hKey,
                      std::string&          errorMessage)
{
    CK_RV                   p11Status          = CKR_GENERAL_ERROR;
    CK_MECHANISM            mechanism          = { mechanismType, NULL_PTR, 0 };
    CK_ULONG                quotePublicKeyLen  = 0UL;
    CK_LONG                 qlPolicy           = SGX_QL_PERSISTENT;
    bool                    result             = false;
    std::vector<CK_BYTE>    quotePublicKey;
    CK_MECHANISM_PTR        pMechanism((CK_MECHANISM_PTR)&mechanism);

    CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteRSAParams =
    {
        qlPolicy
    };

    do
    {
        pMechanism->pParameter = &quoteRSAParams;
        pMechanism->ulParameterLen = sizeof(quoteRSAParams);

        p11Status = p11->C_WrapKey(hSession,
                                   pMechanism,
                                   NULL_PTR,
                                   hKey,
                                   NULL_PTR,
                                   &quotePublicKeyLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey : customQuote!");
            break;
        }

        quotePublicKey.resize(quotePublicKeyLen);
        p11Status = p11->C_WrapKey(hSession,
                                   pMechanism,
                                   NULL_PTR,
                                   hKey,
                                   quotePublicKey.data(),
                                   &quotePublicKeyLen);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_WrapKey : customQuote!");
            break;
        }

        CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParams = reinterpret_cast<CK_RSA_PUBLIC_KEY_PARAMS*>(quotePublicKey.data());
        uint32_t pubKeySize = rsaPublicKeyParams->ulModulusLen + rsaPublicKeyParams->ulExponentLen;
        uint32_t fullPublicKeySize = sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + rsaPublicKeyParams->ulModulusLen + rsaPublicKeyParams->ulExponentLen;

        sgx_quote_t* sgxQuote  = reinterpret_cast<sgx_quote_t*>(quotePublicKey.data() + fullPublicKeySize);
        uint32_t     quoteSize = quotePublicKeyLen - fullPublicKeySize;

        std::vector<CK_BYTE> quote;
        quote.resize(quoteSize);

        memcpy(&quote[0], sgxQuote, quoteSize);

        // Extract the public key and verify its hash
        const uint32_t HASH_LENGTH = 32;
        std::vector<CK_BYTE> publicKeyHashInQuote(HASH_LENGTH, 0);
        std::vector<CK_BYTE> publicKeyData(pubKeySize, 0);

        // Fill the hash vector
        memcpy(publicKeyHashInQuote.data(),
               sgxQuote->report_body.report_data.d,
               HASH_LENGTH);

        // Fill the data vector
        memcpy(publicKeyData.data(),
               quotePublicKey.data() + sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
               pubKeySize);

        // Compute hash of publicKeyData..
        std::vector<CK_BYTE> hashedData;

        computeSHA256Hash(hSession, publicKeyData, hashedData, errorMessage);

        if (publicKeyHashInQuote != hashedData)
        {
            errorMessage.append("FAILED : Public key hash and hash in quote mismatch!");
            break;
        }

        result = true;
    } while (false);

    return result;
}
#endif

bool findObjects(CK_SESSION_HANDLE hSession, std::string& errorMessage)
{
    CK_RV            p11Status        = CKR_FUNCTION_FAILED;
    bool             result           = false;
    CK_KEY_TYPE      rsaKeyType       = CKK_RSA;
    CK_ULONG         handleCount      = 10;
    CK_ULONG         numHandlesCopied = 0;
    CK_UTF8CHAR      id[]             = "1";
    CK_OBJECT_HANDLE keyHandles[handleCount];

    do
    {
        CK_ATTRIBUTE keyAttribsFindObj[] = { { CKA_KEY_TYPE, &rsaKeyType,  sizeof(rsaKeyType)  },
                                             { CKA_ID,       &id[0],       sizeof(id) }};

        p11Status = p11->C_FindObjectsInit(hSession,
                                           keyAttribsFindObj,
                                           sizeof(keyAttribsFindObj) / sizeof(CK_ATTRIBUTE));
        if (CKR_OK != p11Status)
        {
            break;
        }

        p11Status = p11->C_FindObjects(hSession,
                                       &keyHandles[0],
                                       handleCount,
                                       &numHandlesCopied);
        if (CKR_OK != p11Status)
        {
            break;
        }

        p11Status = p11->C_FindObjectsFinal(hSession);
        if (CKR_OK != p11Status)
        {
            break;
        }

        result = true;
    } while(false);

    return result;
}

bool eccSignVerifyTests(std::string curveName, CK_SESSION_HANDLE hSession, std::string& errorMessage)
{
    bool             result       = false;
    CK_OBJECT_HANDLE ecPublicKey  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE ecPrivateKey = CK_INVALID_HANDLE;
    CK_MECHANISM     signVerifyMechanism;

    do
    {
        CK_KEY_TYPE       keyType           = ("ed25519" == curveName) ? CKK_EC_EDWARDS : CKK_EC;
        CK_MECHANISM_TYPE mechanismType     = ("ed25519" == curveName) ? CKM_EC_EDWARDS_KEY_PAIR_GEN : CKM_EC_KEY_PAIR_GEN;
        CK_OBJECT_CLASS   ecPublicKeyClass  = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS   ecPrivateKeyClass = CKO_PRIVATE_KEY;

        CK_UTF8CHAR     ecPublicKeyLabel[]  = "RSA Public Key Label";
        CK_UTF8CHAR     ecPrivateKeyLabel[] = "RSA Private Key Label";

        CK_BBOOL        bTrue = CK_TRUE;

        CK_UTF8CHAR     id[] = "1";

        CK_BYTE oidP256[]  = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	    CK_BYTE oidP384[]  = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
	    CK_BYTE oid25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };

        CK_ATTRIBUTE publicKeyAttribs[] = {{ CKA_EC_PARAMS,       NULL,               0 },
                                           { CKA_TOKEN,           &bTrue,             sizeof(bTrue) },
                                           { CKA_VERIFY,          &bTrue,             sizeof(bTrue) },
                                           { CKA_KEY_TYPE,        &keyType,           sizeof(keyType)   },
                                           { CKA_CLASS,           &ecPublicKeyClass,  sizeof(ecPublicKeyClass)  },
                                           { CKA_LABEL,           ecPublicKeyLabel,   sizeof(ecPublicKeyLabel)-1 },
                                           { CKA_ID,              &id[0],             sizeof(id) }
                                           };

        CK_ATTRIBUTE privateKeyAttribs[] = {{ CKA_TOKEN,    &bTrue,              sizeof(bTrue) },
                                            { CKA_SIGN,     &bTrue,              sizeof(bTrue) },
                                            { CKA_KEY_TYPE, &keyType,            sizeof(keyType)   },
                                            { CKA_CLASS,    &ecPrivateKeyClass,  sizeof(ecPrivateKeyClass)  },
                                            { CKA_LABEL,    ecPrivateKeyLabel,   sizeof(ecPrivateKeyLabel)-1 },
                                            { CKA_ID,       &id[0],              sizeof(id) }
                                            };

        if (strcmp(curveName.c_str(), "p256") == 0)
        {
            signVerifyMechanism = { CKM_ECDSA, NULL_PTR, 0 };

            publicKeyAttribs[0].pValue = oidP256;
            publicKeyAttribs[0].ulValueLen = sizeof(oidP256);
        }
        else if (strcmp(curveName.c_str(), "p384") == 0)
        {
            signVerifyMechanism = { CKM_ECDSA, NULL_PTR, 0 };

            publicKeyAttribs[0].pValue = oidP384;
            publicKeyAttribs[0].ulValueLen = sizeof(oidP384);
        }
        else if (strcmp(curveName.c_str(), "ed25519") == 0)
        {
            signVerifyMechanism = { CKM_EDDSA, NULL_PTR, 0 };

            publicKeyAttribs[0].pValue = oid25519;
            publicKeyAttribs[0].ulValueLen = sizeof(oid25519);
        }
        else
        {
            errorMessage.append("Unsupported EC/ED curve name!");
            break;
        }

        CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
        CK_RV p11Status = p11->C_GenerateKeyPair(hSession,
                                                 &mechanism,
                                                 publicKeyAttribs,
                                                 sizeof(publicKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                                 privateKeyAttribs,
                                                 sizeof(privateKeyAttribs) / sizeof(CK_ATTRIBUTE),
                                                 &ecPublicKey,
                                                 &ecPrivateKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : To GenerateKeyPair (EC) !");
            p11->C_DestroyObject(hSession, ecPublicKey);
            p11->C_DestroyObject(hSession, ecPrivateKey);
            break;
        }

        CK_ULONG             bytesDone    = 0;
        std::vector<CK_BYTE> signature;
        std::vector<CK_BYTE> sourceBuffer(40, 1);
        CK_MECHANISM_PTR     pMechanism((CK_MECHANISM_PTR)&signVerifyMechanism);

        p11Status = p11->C_SignInit(hSession, pMechanism, ecPrivateKey);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_SignInit!");
            break;
        }

        p11Status = p11->C_Sign(hSession, sourceBuffer.data(), sourceBuffer.size(), NULL_PTR, &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Sign!");
            break;
        }

        signature.resize(bytesDone);
        p11Status = p11->C_Sign(hSession, sourceBuffer.data(), sourceBuffer.size(), signature.data(), &bytesDone);
        if (CKR_OK != p11Status)
        {
            errorMessage.append("FAILED : C_Sign!");
            break;
        }

        if ((strcmp(curveName.c_str(), "p256") == 0) ||
            (strcmp(curveName.c_str(), "p384") == 0))
        {
#ifdef EC_VERIFY
            p11Status = p11->C_VerifyInit(hSession, pMechanism, ecPublicKey);
            if (CKR_OK != p11Status)
            {
                errorMessage.append("FAILED : C_VerifyInit!");
                break;
            }

            p11Status = p11->C_Verify(hSession, sourceBuffer.data(), sourceBuffer.size(), signature.data(), signature.size());
            if (CKR_OK != p11Status)
            {
                errorMessage.append("FAILED : C_Verify!");
                break;
            }
#else
            std::cout <<"EC_VERIFY support not enabled, skipping signature verification.\n";
#endif
        }
        else if (strcmp(curveName.c_str(), "ed25519") == 0)
        {
#ifdef ED_VERIFY
            p11Status = p11->C_VerifyInit(hSession, pMechanism, ecPublicKey);
            if (CKR_OK != p11Status)
            {
                errorMessage.append("FAILED : C_VerifyInit!");
                break;
            }

            p11Status = p11->C_Verify(hSession, sourceBuffer.data(), sourceBuffer.size(), signature.data(), signature.size());
            if (CKR_OK != p11Status)
            {
                errorMessage.append("FAILED : C_Verify!");
                break;
            }
#else
            std::cout <<"ED_VERIFY support not enabled, skipping signature verification.\n";
#endif
        }

        result = true;
    } while(false);

    C_DestroyObject(hSession, ecPublicKey);
    C_DestroyObject(hSession, ecPrivateKey);

    return result;
}