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
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#include <openssl/evp.h>
#else
#include <openssl/cmac.h>
#endif

struct cmac_context_s {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_CTX* evp_mac_ctx;
#else
    CMAC_CTX* openssl_context;
#endif
    bool done;
};

cmac_context_t* cmac_context_create(const stored_key_t* stored_key) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    cmac_context_t* context = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC* evp_mac = NULL;
    EVP_MAC_CTX* evp_mac_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        if (!key_type_supports_aes(SA_KEY_TYPE_SYMMETRIC, key_length)) {
            ERROR("Invalid key_length: %d", key_length);
            break;
        }

        evp_mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
        if (evp_mac == NULL) {
            ERROR("EVP_MAC_fetch failed");
            break;
        }

        evp_mac_ctx = EVP_MAC_CTX_new(evp_mac);
        if (evp_mac_ctx == NULL) {
            ERROR("EVP_MAC_CTX_new failed");
            break;
        }

        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                        (key_length == SYM_128_KEY_SIZE) ? "aes-128-cbc" : "aes-256-cbc", 0),
                OSSL_PARAM_construct_end()};

        if (EVP_MAC_init(evp_mac_ctx, key, key_length, params) != 1) {
            ERROR("EVP_MAC_init failed");
            break;
        }

        context = memory_internal_alloc(sizeof(cmac_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(cmac_context_t));
        context->evp_mac_ctx = evp_mac_ctx;
        evp_mac_ctx = NULL;
    } while (false);

    EVP_MAC_CTX_free(evp_mac_ctx);
    EVP_MAC_free(evp_mac);
#else
    CMAC_CTX* openssl_context = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        if (!key_type_supports_aes(SA_KEY_TYPE_SYMMETRIC, key_length)) {
            ERROR("Invalid key_length: %d", key_length);
            break;
        }

        openssl_context = CMAC_CTX_new();
        if (openssl_context == NULL) {
            ERROR("CMAC_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = (key_length == SYM_128_KEY_SIZE) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
        if (CMAC_Init(openssl_context, key, key_length, cipher, NULL) != 1) {
            ERROR("CMAC_Init failed");
            break;
        }

        context = memory_internal_alloc(sizeof(cmac_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        memory_memset_unoptimizable(context, 0, sizeof(cmac_context_t));
        context->openssl_context = openssl_context;

        // openssl_context is now owned by the context
        openssl_context = NULL;
    } while (false);

    if (openssl_context != NULL)
        CMAC_CTX_free(openssl_context);
#endif
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        if (EVP_MAC_update(context->evp_mac_ctx, in, in_length) != 1) {
            ERROR("EVP_MAC_update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
#else
        if (CMAC_Update(context->openssl_context, in, in_length) != 1) {
            ERROR("CMAC_Update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
#endif
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        if (EVP_MAC_update(context->evp_mac_ctx, key, key_length) != 1) {
            ERROR("EVP_MAC_update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
#else
        if (CMAC_Update(context->openssl_context, key, key_length) != 1) {
            ERROR("CMAC_Update failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
#endif
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

    size_t length = AES_BLOCK_SIZE;
    context->done = true;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    if (EVP_MAC_final(context->evp_mac_ctx, mac, &length, length) != 1) {
        ERROR("EVP_MAC_final failed");
        return SA_STATUS_INTERNAL_ERROR;
    }
#else
    if (CMAC_Final(context->openssl_context, (unsigned char*) mac, &length) != 1) {
        ERROR("CMAC_Final failed");
        return SA_STATUS_INTERNAL_ERROR;
    }
#endif

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

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_CTX_free(context->evp_mac_ctx);
#else
    CMAC_CTX_free(context->openssl_context);
#endif
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

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC* evp_mac = NULL;
    EVP_MAC_CTX* evp_mac_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
            ERROR("Invalid key_length: %d", key_length);
            break;
        }

        evp_mac = EVP_MAC_fetch(NULL, "cmac", NULL);
        if (evp_mac == NULL) {
            ERROR("EVP_MAC_fetch failed");
            break;
        }

        evp_mac_ctx = EVP_MAC_CTX_new(evp_mac);
        if (evp_mac_ctx == NULL) {
            ERROR("EVP_MAC_CTX_new failed");
            break;
        }

        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("cipher",
                        (key_length == SYM_128_KEY_SIZE) ? "aes-128-cbc" : "aes-256-cbc", 0),
                OSSL_PARAM_construct_end()};

        if (EVP_MAC_init(evp_mac_ctx, key, key_length, params) != 1) {
            ERROR("EVP_MAC_init failed");
            break;
        }

        if (in1_length > 0) {
            if (EVP_MAC_update(evp_mac_ctx, in1, in1_length) != 1) {
                ERROR("EVP_MAC_update failed");
                break;
            }
        }

        if (in2_length > 0) {
            if (EVP_MAC_update(evp_mac_ctx, in2, in2_length) != 1) {
                ERROR("EVP_MAC_update failed");
                break;
            }
        }

        if (in3_length > 0) {
            if (EVP_MAC_update(evp_mac_ctx, in3, in3_length) != 1) {
                ERROR("EVP_MAC_update failed");
                break;
            }
        }

        size_t length = AES_BLOCK_SIZE;
        if (EVP_MAC_final(evp_mac_ctx, (unsigned char*) mac, &length, length) != 1) {
            ERROR("EVP_MAC_final failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_MAC_CTX_free(evp_mac_ctx);
    EVP_MAC_free(evp_mac);
#else
    CMAC_CTX* openssl_context = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
            ERROR("Invalid key_length: %d", key_length);
            break;
        }

        openssl_context = CMAC_CTX_new();
        if (openssl_context == NULL) {
            ERROR("CMAC_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = (key_length == SYM_128_KEY_SIZE) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();

        if (CMAC_Init(openssl_context, key, key_length, cipher, NULL) != 1) {
            ERROR("CMAC_Init failed");
            break;
        }

        if (in1_length > 0) {
            if (CMAC_Update(openssl_context, in1, in1_length) != 1) {
                ERROR("CMAC_Update failed");
                break;
            }
        }

        if (in2_length > 0) {
            if (CMAC_Update(openssl_context, in2, in2_length) != 1) {
                ERROR("CMAC_Update failed");
                break;
            }
        }

        if (in3_length > 0) {
            if (CMAC_Update(openssl_context, in3, in3_length) != 1) {
                ERROR("CMAC_Update failed");
                break;
            }
        }

        size_t signature_length = AES_BLOCK_SIZE;
        if (CMAC_Final(openssl_context, (unsigned char*) mac, &signature_length) != 1) {
            ERROR("CMAC_Final failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    CMAC_CTX_free(openssl_context);
#endif

    return status;
}
