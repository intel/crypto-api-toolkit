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

#ifndef OBJECTMANAGEMENT_H
#define OBJECTMANAGEMENT_H

#include "cryptoki.h"

//---------------------------------------------------------------------------------------------
CK_RV createObject(CK_SESSION_HANDLE    hSession,
                   CK_ATTRIBUTE_PTR     pTemplate,
                   CK_ULONG             ulCount,
                   CK_OBJECT_HANDLE_PTR phObject);

//---------------------------------------------------------------------------------------------=
CK_RV copyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject);

//---------------------------------------------------------------------------------------------
CK_RV destroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);

//---------------------------------------------------------------------------------------------=
CK_RV getObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG_PTR pulSize);

//---------------------------------------------------------------------------------------------
CK_RV getAttributeValue(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE  hObject,
                        CK_ATTRIBUTE_PTR  pTemplate,
                        CK_ULONG          ulCount);

//---------------------------------------------------------------------------------------------
CK_RV setAttributeValue(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE  hObject,
                        CK_ATTRIBUTE_PTR  pTemplate,
                        CK_ULONG          ulCount);

//---------------------------------------------------------------------------------------------
CK_RV findObjectsInit(CK_SESSION_HANDLE hSession,
                      CK_ATTRIBUTE_PTR  pTemplate,
                      CK_ULONG          ulCount);

//---------------------------------------------------------------------------------------------
CK_RV findObjects(CK_SESSION_HANDLE    hSession,
                  CK_OBJECT_HANDLE_PTR phObject,
                  CK_ULONG             ulMaxObjectCount,
                  CK_ULONG_PTR         pulObjectCount);

//---------------------------------------------------------------------------------------------
CK_RV findObjectsFinal(CK_SESSION_HANDLE hSession);


#endif // OBJECTMANAGEMENT_H