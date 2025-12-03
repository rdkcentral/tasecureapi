/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "digest.h" // NOLINT
#include "digest_util.h"
#include "digest_util_mbedtls.h"
#include "log.h"
#include "stored_key_internal.h"

sa_status digest_sha(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t required_length = digest_length(digest_algorithm);
    if (out == NULL) {
        *out_length = required_length;
        return required_length == SIZE_MAX ? SA_STATUS_INVALID_PARAMETER : SA_STATUS_OK;
    }

    if (*out_length < required_length) {
        ERROR("Invalid out_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    *out_length = required_length;

    if (in1 == NULL && in1_length > 0) {
        ERROR("NULL in1");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in2 == NULL && in2_length > 0) {
        ERROR("NULL in2");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in3 == NULL && in3_length > 0) {
        ERROR("NULL in3");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    
    do {
        // Get the message digest info for the algorithm
        mbedtls_md_type_t md_type;
        switch (digest_algorithm) {
            case SA_DIGEST_ALGORITHM_SHA1:
                md_type = MBEDTLS_MD_SHA1;
                break;
            case SA_DIGEST_ALGORITHM_SHA256:
                md_type = MBEDTLS_MD_SHA256;
                break;
            case SA_DIGEST_ALGORITHM_SHA384:
                md_type = MBEDTLS_MD_SHA384;
                break;
            case SA_DIGEST_ALGORITHM_SHA512:
                md_type = MBEDTLS_MD_SHA512;
                break;
            default:
                ERROR("Unknown digest algorithm");
                break;
        }
        
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        if (mbedtls_md_setup(&context, md_info, 0) != 0) {
            ERROR("mbedtls_md_setup failed");
            break;
        }

        if (mbedtls_md_starts(&context) != 0) {
            ERROR("mbedtls_md_starts failed");
            break;
        }

        if (in1_length > 0) {
            if (mbedtls_md_update(&context, in1, in1_length) != 0) {
                ERROR("mbedtls_md_update failed");
                break;
            }
        }

        if (in2_length > 0) {
            if (mbedtls_md_update(&context, in2, in2_length) != 0) {
                ERROR("mbedtls_md_update failed");
                break;
            }
        }

        if (in3_length > 0) {
            if (mbedtls_md_update(&context, in3, in3_length) != 0) {
                ERROR("mbedtls_md_update failed");
                break;
            }
        }

        if (mbedtls_md_finish(&context, (unsigned char*) out) != 0) {
            ERROR("mbedtls_md_finish failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    mbedtls_md_free(&context);
    return status;
}

sa_status digest_key(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t required_length = digest_length(digest_algorithm);
    if (out == NULL) {
        *out_length = required_length;
        return *out_length == SIZE_MAX ? SA_STATUS_INVALID_PARAMETER : SA_STATUS_OK;
    }

    if (*out_length < required_length) {
        ERROR("Invalid out_length");
        return SA_STATUS_INVALID_PARAMETER;
    }
    *out_length = required_length;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);

        // Get the message digest info for the algorithm
        mbedtls_md_type_t md_type;
        switch (digest_algorithm) {
            case SA_DIGEST_ALGORITHM_SHA1:
                md_type = MBEDTLS_MD_SHA1;
                break;
            case SA_DIGEST_ALGORITHM_SHA256:
                md_type = MBEDTLS_MD_SHA256;
                break;
            case SA_DIGEST_ALGORITHM_SHA384:
                md_type = MBEDTLS_MD_SHA384;
                break;
            case SA_DIGEST_ALGORITHM_SHA512:
                md_type = MBEDTLS_MD_SHA512;
                break;
            default:
                ERROR("Unknown digest algorithm");
                break;
        }
        
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        if (mbedtls_md_setup(&context, md_info, 0) != 0) {
            ERROR("mbedtls_md_setup failed");
            break;
        }

        if (mbedtls_md_starts(&context) != 0) {
            ERROR("mbedtls_md_starts failed");
            break;
        }

        if (mbedtls_md_update(&context, key, key_length) != 0) {
            ERROR("mbedtls_md_update failed");
            break;
        }

        if (mbedtls_md_finish(&context, (unsigned char*) out) != 0) {
            ERROR("mbedtls_md_finish failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    mbedtls_md_free(&context);
    return status;
}
