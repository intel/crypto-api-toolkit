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

/*****************************************************************************
QuoteGeneration.h

 This file contains structures for quote generation
 *****************************************************************************/
#ifndef _QUOTEGENERATION_H
#define _QUOTEGENERATION_H

#include "pkcs11t.h"

#include <sgx_quote.h>
#include <sgx_pce.h>
#include <sgx_dcap_ql_wrapper.h>

typedef struct CK_RSA_PUBLIC_KEY_PARAMS {
    CK_ULONG ulExponentLen;
    CK_ULONG ulModulusLen;
} CK_RSA_PUBLIC_KEY_PARAMS;

typedef struct CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS {
    CK_LONG qlPolicy;
} CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS;

typedef CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS* CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR;

typedef struct CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL {
    sgx_target_info_t targetInfo;
    uint32_t quoteLength;
} CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL;

typedef CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL* CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS_INTERNAL_PTR;

#endif // !_QUOTEGENERATION_H
