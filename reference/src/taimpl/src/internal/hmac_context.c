/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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
#include "digest.h"
#include "digest_internal.h"
#include "hmac_internal.h"
#include "log.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#endif
#include <openssl/evp.h>

struct hmac_context_s {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_CTX* evp_mac_ctx;
#else
    EVP_MD_CTX* openssl_context;
#endif
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
        evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
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
                OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*) digest_string(digest_algorithm), 0),
                OSSL_PARAM_construct_end()};

        char zero = 0;
        if (EVP_MAC_init(evp_mac_ctx, key != NULL ? key : &zero, key != NULL ? key_length : 1, params) != 1) {
            ERROR("EVP_MAC_init failed");
            break;
        }

        context = memory_internal_alloc(sizeof(hmac_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(hmac_context_t));
        context->evp_mac_ctx = evp_mac_ctx;
        context->digest_algorithm = digest_algorithm;
        evp_mac_ctx = NULL;
    } while (false);

    EVP_MAC_CTX_free(evp_mac_ctx);
    EVP_MAC_free(evp_mac);
#else
    EVP_PKEY* openssl_key = NULL;
    EVP_MD_CTX* openssl_context = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        openssl_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int) key_length);
        if (openssl_key == NULL) {
            ERROR("EVP_PKEY_new_mac_key failed");
            break;
        }

        openssl_context = EVP_MD_CTX_create();
        if (openssl_context == NULL) {
            ERROR("EVP_MD_CTX_create failed");
            break;
        }

        const EVP_MD* md = digest_mechanism(digest_algorithm);
        if (md == NULL) {
            ERROR("digest_mechanism failed");
            break;
        }

        if (EVP_DigestSignInit(openssl_context, NULL, md, NULL, openssl_key) != 1) {
            ERROR("EVP_DigestSignInit failed");
            break;
        }

        context = memory_internal_alloc(sizeof(hmac_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(hmac_context_t));
        context->openssl_context = openssl_context;
        context->digest_algorithm = digest_algorithm;
        openssl_context = NULL;
    } while (false);

    EVP_MD_CTX_destroy(openssl_context);
    EVP_PKEY_free(openssl_key);
#endif

    return context;
}

sa_digest_algorithm hmac_context_get_digest(const hmac_context_t* context) {
    if (context == NULL) {
        ERROR("NULL context");
        return (sa_digest_algorithm) -1;
    }

    return context->digest_algorithm;
}

bool hmac_context_update(
        hmac_context_t* context,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return false;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return false;
    }

    if (in_length > 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        if (EVP_MAC_update(context->evp_mac_ctx, in, in_length) != 1) {
            ERROR("EVP_MAC_update failed");
            return false;
        }
#else
        if (EVP_DigestSignUpdate(context->openssl_context, in, in_length) != 1) {
            ERROR("EVP_DigestSignUpdate failed");
            return false;
        }
#endif
    }

    return true;
}

bool hmac_context_update_key(
        hmac_context_t* context,
        stored_key_t* stored_key) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return false;
    }

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
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    if (EVP_MAC_update(context->evp_mac_ctx, key, key_length) != 1) {
        ERROR("EVP_MAC_update failed");
        return false;
    }
#else
    if (EVP_DigestSignUpdate(context->openssl_context, key, key_length) != 1) {
        ERROR("EVP_DigestSignUpdate failed");
        return false;
    }
#endif

    return true;
}

bool hmac_context_compute(
        void* mac,
        size_t* mac_length,
        hmac_context_t* context) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (mac_length == NULL) {
        ERROR("NULL mac_length");
        return false;
    }

    if (mac == NULL) {
        *mac_length = digest_length(context->digest_algorithm);
        return true;
    }

    if (*mac_length < digest_length(context->digest_algorithm)) {
        ERROR("Invalid mac_length");
        return false;
    }
    *mac_length = digest_length(context->digest_algorithm);

    if (context->done) {
        ERROR("Mac value has already been computed on this context");
        return false;
    }

    size_t length = *mac_length;
    context->done = true;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    if (EVP_MAC_final(context->evp_mac_ctx, mac, &length, *mac_length) != 1) {
        ERROR("EVP_MAC_final failed");
        return false;
    }
#else
    if (EVP_DigestSignFinal(context->openssl_context, (unsigned char*) mac, &length) != 1) {
        ERROR("EVP_DigestSignFinal failed");
        return false;
    }
#endif

    return true;
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC_CTX_free(context->evp_mac_ctx);
#else
    EVP_MD_CTX_destroy(context->openssl_context);
#endif
    memory_internal_free(context);
}

bool hmac_internal(
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
        return false;
    }

    size_t hash_length = digest_length(digest_algorithm);
    if (mac == NULL) {
        *mac_length = hash_length;
        return hash_length != (size_t) -1;
    }

    if (*mac_length < hash_length) {
        ERROR("Invalid mac_length");
        return false;
    }

    bool status = false;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_MAC* evp_mac = NULL;
    EVP_MAC_CTX* evp_mac_ctx = NULL;
    do {
        evp_mac = EVP_MAC_fetch(NULL, "hmac", NULL);
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
                OSSL_PARAM_construct_utf8_string("digest", (char*) digest_string(digest_algorithm), 0),
                OSSL_PARAM_construct_end()};

        char zero = 0;
        if (EVP_MAC_init(evp_mac_ctx, key != NULL ? key : &zero, key != NULL ? key_length : 1, params) != 1) {
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

        size_t length = hash_length;
        if (EVP_MAC_final(evp_mac_ctx, (unsigned char*) mac, &length, *mac_length) != 1) {
            ERROR("EVP_MAC_final failed");
            break;
        }

        status = true;
        *mac_length = length;
    } while (false);

    EVP_MAC_CTX_free(evp_mac_ctx);
    EVP_MAC_free(evp_mac);
#else
    EVP_PKEY* openssl_key = NULL;
    EVP_MD_CTX* openssl_context = NULL;
    do {

        openssl_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int) key_length);
        if (openssl_key == NULL) {
            ERROR("EVP_PKEY_new_mac_key failed");
            break;
        }

        openssl_context = EVP_MD_CTX_create();
        if (openssl_context == NULL) {
            ERROR("EVP_MD_CTX_create failed");
            break;
        }

        const EVP_MD* md = digest_mechanism(digest_algorithm);
        if (md == NULL) {
            ERROR("digest_mechanism failed");
            break;
        }

        if (EVP_DigestInit_ex(openssl_context, md, NULL) != 1) {
            ERROR("EVP_DigestInit_ex failed");
            break;
        }

        if (EVP_DigestSignInit(openssl_context, NULL, md, NULL, openssl_key) != 1) {
            ERROR("EVP_DigestSignInit failed");
            break;
        }

        if (in1_length > 0) {
            if (EVP_DigestSignUpdate(openssl_context, in1, in1_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }
        }

        if (in2_length > 0) {
            if (EVP_DigestSignUpdate(openssl_context, in2, in2_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }
        }

        if (in3_length > 0) {
            if (EVP_DigestSignUpdate(openssl_context, in3, in3_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }
        }

        size_t length = hash_length;
        if (EVP_DigestSignFinal(openssl_context, (unsigned char*) mac, &length) != 1) {
            ERROR("EVP_DigestSignFinal failed");
            break;
        }

        status = true;
        *mac_length = length;
    } while (false);

    EVP_MD_CTX_destroy(openssl_context);
    EVP_PKEY_free(openssl_key);
#endif

    return status;
}

bool hmac(
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
