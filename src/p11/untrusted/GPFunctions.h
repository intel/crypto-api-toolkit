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

#ifndef GP_FUNCTIONS_H
#define GP_FUNCTIONS_H

#include "cryptoki.h"
#include "EnclaveInterface.h"
#include "P11Provider.h"

/**
* Initializes the PKCS#11 library. Typically this is the first Cryptoki call from application other than C_GetFunctionList.
* @param  pInitArgs      Pointer to CK_C_INITIALIZE_ARGS structure.
* @return CK_RV          CKR_OK if the provider is successfully initialized, error code otherwise.
*/
CK_RV initialize(CK_VOID_PTR pInitArgs);

/**
* Finalizes the PKCS#11 library. This is the last Cryptoki call that an application can call.
* @param  pReserved      Pointer that's supposed to be nullptr (reserved for future purposes).
* @return CK_RV          CKR_OK if the provider is successfully finalized, error code otherwise.
*/
CK_RV finalize(CK_VOID_PTR pReserved);

/**
* Gives library's general information.
* @param  pInfo      Pointer to CK_INFO structure that will hold the library's information.
* @return CK_RV      CKR_OK if the information is successfully populated, error code otherwise.
*/
CK_RV getInfo(CK_INFO_PTR pInfo);

/**
* Gives a pointer to a list of function pointers.
* @param  ppFunctionList    Pointer to list of function pointers.
* @return CK_RV             CKR_OK if the functionlist pointer is successfully populated, error code otherwise.
*/
CK_RV getFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

#endif //GP_FUNCTIONS_H