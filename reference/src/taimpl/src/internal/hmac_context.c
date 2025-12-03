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

#include "hmac_context.h" // NOLINT
#include "digest_util.h"
#include "digest_util_mbedtls.h"
#include "hmac_internal.h"
#include "log.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include "pkcs12_mbedtls.h"

struct hmac_context_s {
    mbedtls_md_context_t md_ctx;
    sa_digest_algorithm digest_algorithm;
    bool done;
};

hmac_context_t* hmac_context_create(
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    hmac_context_t* context = NULL;
    bool md_ctx_initialized = false;
    
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        
        // Get mbedTLS message digest type
        mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        context = memory_internal_alloc(sizeof(hmac_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(hmac_context_t));
        
        // Initialize MD context
        mbedtls_md_init(&context->md_ctx);
        md_ctx_initialized = true;
        
        // Setup HMAC
        if (mbedtls_md_setup(&context->md_ctx, md_info, 1) != 0) { // 1 = HMAC mode
            ERROR("mbedtls_md_setup failed");
            break;
        }

        // Start HMAC with key
        if (mbedtls_md_hmac_starts(&context->md_ctx, key, key_length) != 0) {
            ERROR("mbedtls_md_hmac_starts failed");
            break;
        }

        context->digest_algorithm = digest_algorithm;
        return context;
    } while (false);

    // Cleanup on error
    if (context != NULL) {
        if (md_ctx_initialized) {
            mbedtls_md_free(&context->md_ctx);
        }
        memory_internal_free(context);
    }

    return NULL;
}

sa_digest_algorithm hmac_context_get_digest(const hmac_context_t* context) {
    if (context == NULL) {
        ERROR("NULL context");
        return (sa_digest_algorithm) -1;
    }

    return context->digest_algorithm;
}

sa_status hmac_context_update(
        hmac_context_t* context,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length > 0) {
        if (mbedtls_md_hmac_update(&context->md_ctx, in, in_length) != 0) {
            ERROR("mbedtls_md_hmac_update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
    }

    return SA_STATUS_OK;
}

sa_status hmac_context_update_key(
        hmac_context_t* context,
        stored_key_t* stored_key) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (mbedtls_md_hmac_update(&context->md_ctx, key, key_length) != 0) {
        ERROR("mbedtls_md_hmac_update failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

sa_status hmac_context_compute(
        void* mac,
        size_t* mac_length,
        hmac_context_t* context) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mac_length == NULL) {
        ERROR("NULL mac_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mac == NULL) {
        *mac_length = digest_length(context->digest_algorithm);
        return *mac_length == SIZE_MAX ? SA_STATUS_INVALID_PARAMETER : SA_STATUS_OK;
    }

    if (*mac_length < digest_length(context->digest_algorithm)) {
        ERROR("Invalid mac_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    *mac_length = digest_length(context->digest_algorithm);

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    context->done = true;
    if (mbedtls_md_hmac_finish(&context->md_ctx, mac) != 0) {
        ERROR("mbedtls_md_hmac_finish failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

bool hmac_context_done(
        hmac_context_t* context) {
    if (context != NULL) {
        return context->done;
    }

    ERROR("NULL context");
    return true;
}

void hmac_context_free(hmac_context_t* context) {
    if (context == NULL) {
        return;
    }

    mbedtls_md_free(&context->md_ctx);
    memory_internal_free(context);
}

sa_status hmac_internal(
        void* mac,
        size_t* mac_length,
        sa_digest_algorithm digest_algorithm,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length,
        const void* key,
        size_t key_length) {

    if (mac_length == NULL) {
        ERROR("NULL mac_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t hash_length = digest_length(digest_algorithm);
    if (mac == NULL) {
        *mac_length = hash_length;
        return hash_length == SIZE_MAX ? SA_STATUS_INVALID_PARAMETER : SA_STATUS_OK;
    }

    if (*mac_length < hash_length) {
        ERROR("Invalid mac_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    bool md_ctx_initialized = true;
    
    do {
        // Get mbedTLS message digest type
        mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        // Setup HMAC
        if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0) { // 1 = HMAC mode
            ERROR("mbedtls_md_setup failed");
            break;
        }

        // Start HMAC with key
        if (mbedtls_md_hmac_starts(&md_ctx, key, key_length) != 0) {
            ERROR("mbedtls_md_hmac_starts failed");
            break;
        }

        // Update with input data
        if (in1_length > 0) {
            if (mbedtls_md_hmac_update(&md_ctx, in1, in1_length) != 0) {
                ERROR("mbedtls_md_hmac_update failed");
                break;
            }
        }

        if (in2_length > 0) {
            if (mbedtls_md_hmac_update(&md_ctx, in2, in2_length) != 0) {
                ERROR("mbedtls_md_hmac_update failed");
                break;
            }
        }

        if (in3_length > 0) {
            if (mbedtls_md_hmac_update(&md_ctx, in3, in3_length) != 0) {
                ERROR("mbedtls_md_hmac_update failed");
                break;
            }
        }

        // Finalize HMAC
        if (mbedtls_md_hmac_finish(&md_ctx, mac) != 0) {
            ERROR("mbedtls_md_hmac_finish failed");
            break;
        }

        status = SA_STATUS_OK;
        *mac_length = hash_length;
    } while (false);

    if (md_ctx_initialized) {
        mbedtls_md_free(&md_ctx);
    }

    return status;
}

sa_status hmac(
        void* mac,
        size_t* mac_length,
        sa_digest_algorithm digest_algorithm,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length,
        const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return false;
    }

    size_t key_length = stored_key_get_length(stored_key);
    return hmac_internal(mac, mac_length, digest_algorithm, in1, in1_length, in2, in2_length, in3, in3_length, key,
            key_length);
}
