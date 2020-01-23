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

#include "config.h"
#include "p11Enclave_u.h"

#ifdef DCAP_SUPPORT
#include <sgx_pce.h>
#include <sgx_dcap_ql_wrapper.h>

/* ocall functions */

size_t ocall_generate_quote_internal(sgx_report_t* enclaveReport,
                                     uint8_t*      quoteBuffer,
                                     uint32_t      quoteBufferLength)
{
    quote3_error_t qrv = SGX_QL_SUCCESS;

    if (!quoteBuffer || !quoteBufferLength)
    {
        return CKR_DATA_INVALID;
    }

    uint32_t quoteSize{0};
    qrv = sgx_qe_get_quote_size(&quoteSize);

    if ((SGX_QL_SUCCESS != qrv) || (quoteBufferLength != quoteSize))
    {
        return CKR_GENERAL_ERROR;
    }

    qrv = sgx_qe_get_quote(enclaveReport, quoteBufferLength, quoteBuffer);
    if (SGX_QL_SUCCESS != qrv)
    {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}
#endif

size_t ocall_generate_quote(sgx_report_t* enclaveReport,
                            uint8_t*      quoteBuffer,
                            uint32_t      quoteBufferLength)
{
#ifdef DCAP_SUPPORT
    return ocall_generate_quote_internal(enclaveReport, quoteBuffer, quoteBufferLength);
#else
    return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}