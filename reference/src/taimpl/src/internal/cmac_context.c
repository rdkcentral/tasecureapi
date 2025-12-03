/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

#include "cmac_context.h"
#include "common.h"
#include "key_type.h"
#include "log.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include "pkcs12_mbedtls.h"
#include "mbedtls_header.h"

struct cmac_context_s {
    mbedtls_cipher_context_t cipher_ctx;
    bool done;
};

cmac_context_t* cmac_context_create(const stored_key_t* stored_key) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    cmac_context_t* context = memory_internal_alloc(sizeof(cmac_context_t));
    if (context == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }
    memory_memset_unoptimizable(context, 0, sizeof(cmac_context_t));
    mbedtls_cipher_init(&context->cipher_ctx);

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        memory_internal_free(context);
        return NULL;
    }
    size_t key_length = stored_key_get_length(stored_key);
    if (!key_type_supports_aes(SA_KEY_TYPE_SYMMETRIC, key_length)) {
        ERROR("Invalid key_length: %zu", key_length);
        memory_internal_free(context);
        return NULL;
    }
    const mbedtls_cipher_info_t* cipher_info = NULL;
    if (key_length == SYM_128_KEY_SIZE)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    else if (key_length == SYM_256_KEY_SIZE)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    else {
        ERROR("Unsupported key length for CMAC: %zu", key_length);
        memory_internal_free(context);
        return NULL;
    }
    if (mbedtls_cipher_setup(&context->cipher_ctx, cipher_info) != 0) {
        ERROR("mbedtls_cipher_setup failed");
        memory_internal_free(context);
        return NULL;
    }
    if (mbedtls_cipher_cmac_starts(&context->cipher_ctx, key, key_length * 8) != 0) {
        ERROR("mbedtls_cipher_cmac_starts failed");
        mbedtls_cipher_free(&context->cipher_ctx);
        memory_internal_free(context);
        return NULL;
    }
    context->done = false;
    return context;
}

sa_status cmac_context_update(
        cmac_context_t* context,
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
        if (mbedtls_cipher_cmac_update(&context->cipher_ctx, in, in_length) != 0) {
            ERROR("mbedtls_cipher_cmac_update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
    }

    return SA_STATUS_OK;
}

sa_status cmac_context_update_key(
        cmac_context_t* context,
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
    if (key_length > 0) {
        if (mbedtls_cipher_cmac_update(&context->cipher_ctx, key, key_length) != 0) {
            ERROR("mbedtls_cipher_cmac_update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
    }

    return SA_STATUS_OK;
}

sa_status cmac_context_compute(
        void* mac,
        cmac_context_t* context) {

    if (mac == NULL) {
        ERROR("NULL mac");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    context->done = true;
    if (mbedtls_cipher_cmac_finish(&context->cipher_ctx, mac) != 0) {
        ERROR("mbedtls_cipher_cmac_finish failed");
        return SA_STATUS_INTERNAL_ERROR;
    }
    return SA_STATUS_OK;
}

bool cmac_context_done(cmac_context_t* context) {
    if (context != NULL) {
        return context->done;
    }

    ERROR("NULL context");
    return true;
}

void cmac_context_free(cmac_context_t* context) {
    if (context == NULL) {
        return;
    }

    mbedtls_cipher_free(&context->cipher_ctx);
    memory_internal_free(context);
}

sa_status cmac(
        void* mac,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length,
        const stored_key_t* stored_key) {
    if (mac == NULL) {
        ERROR("NULL mac");
        return SA_STATUS_NULL_PARAMETER;
    }
    if ((in1 == NULL && in1_length > 0) || (in2 == NULL && in2_length > 0) || (in3 == NULL && in3_length > 0)) {
        ERROR("NULL input");
        return SA_STATUS_NULL_PARAMETER;
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
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length: %zu", key_length);
        return SA_STATUS_INVALID_PARAMETER;
    }
    const mbedtls_cipher_info_t* cipher_info = NULL;
    if (key_length == SYM_128_KEY_SIZE)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    else if (key_length == SYM_256_KEY_SIZE)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    else {
        ERROR("Unsupported key length for CMAC: %zu", key_length);
        return SA_STATUS_INVALID_PARAMETER;
    }
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_cipher_init(&cipher_ctx);
    sa_status status = SA_STATUS_INTERNAL_ERROR;
    do {
        if (mbedtls_cipher_setup(&cipher_ctx, cipher_info) != 0) {
            ERROR("mbedtls_cipher_setup failed");
            break;
        }
        if (mbedtls_cipher_cmac_starts(&cipher_ctx, key, key_length * 8) != 0) {
            ERROR("mbedtls_cipher_cmac_starts failed");
            break;
        }
        if (in1_length > 0 && mbedtls_cipher_cmac_update(&cipher_ctx, in1, in1_length) != 0) {
            ERROR("mbedtls_cipher_cmac_update failed (in1)");
            break;
        }
        if (in2_length > 0 && mbedtls_cipher_cmac_update(&cipher_ctx, in2, in2_length) != 0) {
            ERROR("mbedtls_cipher_cmac_update failed (in2)");
            break;
        }
        if (in3_length > 0 && mbedtls_cipher_cmac_update(&cipher_ctx, in3, in3_length) != 0) {
            ERROR("mbedtls_cipher_cmac_update failed (in3)");
            break;
        }
        if (mbedtls_cipher_cmac_finish(&cipher_ctx, mac) != 0) {
            ERROR("mbedtls_cipher_cmac_finish failed");
            break;
        }
        status = SA_STATUS_OK;
    } while (false);
    mbedtls_cipher_free(&cipher_ctx);
    return status;
}
