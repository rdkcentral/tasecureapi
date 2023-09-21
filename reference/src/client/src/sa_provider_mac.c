/**
* Copyright 2023 Comcast Cable Communications Management, LLC
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

/*
 * Some code in this file is based off OpenSSL which is:
 * Copyright 2019-2021 The OpenSSL Project Authors
 * Licensed under the Apache License, Version 2.0
 */

#include "sa_provider_internal.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include "common.h"
#include "digest_util.h"
#include "log.h"
#include "sa_rights.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

typedef struct {
    sa_provider_context* provider_context;
    sa_mac_algorithm mac_algorithm;
    sa_crypto_mac_context mac_context;
    EVP_MD* evp_md;
    sa_key key;
    bool delete_key;
} sa_provider_mac_context;

ossl_unused static OSSL_FUNC_mac_newctx_fn mac_hmac_newctx;
ossl_unused static OSSL_FUNC_mac_newctx_fn mac_cmac_newctx;
ossl_unused static OSSL_FUNC_mac_freectx_fn mac_freectx;
ossl_unused static OSSL_FUNC_mac_init_fn mac_init;
ossl_unused static OSSL_FUNC_mac_update_fn mac_update;
ossl_unused static OSSL_FUNC_mac_final_fn mac_final;
ossl_unused static OSSL_FUNC_mac_get_ctx_params_fn mac_get_ctx_params;
ossl_unused static OSSL_FUNC_mac_gettable_ctx_params_fn mac_gettable_ctx_params;
ossl_unused static OSSL_FUNC_mac_set_ctx_params_fn mac_set_ctx_params;
ossl_unused static OSSL_FUNC_mac_settable_ctx_params_fn mac_hmac_settable_ctx_params;
ossl_unused static OSSL_FUNC_mac_settable_ctx_params_fn mac_cmac_settable_ctx_params;

static void* mac_newctx(
        sa_mac_algorithm mac_algorithm,
        void* provctx) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_mac_context* mac_context = NULL;
    sa_provider_context* provider_context = provctx;
    mac_context = OPENSSL_zalloc(sizeof(sa_provider_mac_context));
    if (mac_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    mac_context->provider_context = provider_context;
    mac_context->mac_algorithm = mac_algorithm;
    mac_context->mac_context = INVALID_HANDLE;
    mac_context->key = INVALID_HANDLE;
    return mac_context;
}

static void mac_freectx(void* mctx) {
    if (mctx == NULL)
        return;

    sa_provider_mac_context* mac_context = mctx;
    if (mac_context->mac_context != INVALID_HANDLE)
        sa_crypto_mac_release(mac_context->mac_context);

    if (mac_context->delete_key && mac_context->key != INVALID_HANDLE)
        sa_key_release(mac_context->key);

    mac_context->key = INVALID_HANDLE;
    mac_context->mac_context = INVALID_HANDLE;
    EVP_MD_free(mac_context->evp_md);
    OPENSSL_free(mac_context);
}

static int mac_init(
        void* mctx,
        const unsigned char* key,
        size_t keylen,
        const OSSL_PARAM params[]) {

    if (mctx == NULL) {
        ERROR("NULL mctx");
        return 0;
    }

    int result = 0;
    sa_provider_mac_context* mac_context = mctx;
    do {
        if (mac_context->mac_context != INVALID_HANDLE) {
            sa_crypto_mac_release(mac_context->mac_context);
            mac_context->mac_context = INVALID_HANDLE;
        }

        if (key != NULL) {
            if (mac_context->key != INVALID_HANDLE)
                sa_key_release(mac_context->key);

            sa_rights rights;
            sa_rights_set_allow_all(&rights);
            sa_import_parameters_symmetric parameters_symmetric = {&rights};
            if (sa_key_import(&mac_context->key, SA_KEY_FORMAT_SYMMETRIC_BYTES, key, keylen,
                        &parameters_symmetric) != SA_STATUS_OK) {
                ERROR("sa_key_import failed");
                break;
            }

            sa_header header;
            if (sa_key_header(&header, mac_context->key) != SA_STATUS_OK) {
                ERROR("sa_key_header failed");
                break;
            }

            mac_context->delete_key = true;
        }

        if (mac_set_ctx_params(mctx, params) != 1) {
            ERROR("mac_set_ctx_params failed");
            break;
        }

        if (mac_context->key == INVALID_HANDLE) {
            ERROR("Invalid key");
            break;
        }

        sa_mac_parameters_hmac parameters_hmac;
        void* parameters = NULL;
        if (mac_context->mac_algorithm == SA_MAC_ALGORITHM_HMAC) {

            parameters_hmac.digest_algorithm = digest_algorithm_from_name(EVP_MD_get0_name(mac_context->evp_md));
            parameters = &parameters_hmac;
        }

        if (sa_crypto_mac_init(&mac_context->mac_context, mac_context->mac_algorithm, mac_context->key,
                    parameters) != SA_STATUS_OK) {
            ERROR("sa_crypto_mac_init failed");
            break;
        }

        result = 1;
    } while (false);

    return result;
}

static int mac_update(
        void* mctx,
        const unsigned char* in,
        size_t inl) {

    if (mctx == NULL) {
        ERROR("NULL mctx");
        return 0;
    }

    sa_provider_mac_context* mac_context = mctx;
    if (sa_crypto_mac_process(mac_context->mac_context, in, inl) != SA_STATUS_OK) {
        ERROR("sa_crypto_mac_process failed");
        return 0;
    }

    return 1;
}

static int mac_final(
        void* mctx,
        unsigned char* out,
        size_t* outl,
        size_t outsize) {

    if (mctx == NULL) {
        ERROR("NULL mctx");
        return 0;
    }

    if (outl == NULL) {
        ERROR("NULL outl");
        return 0;
    }

    sa_provider_mac_context* mac_context = mctx;
    size_t out_length = outsize;
    if (sa_crypto_mac_compute(out, &out_length, mac_context->mac_context) != SA_STATUS_OK) {
        ERROR("sa_crypto_mac_compute failed");
        return 0;
    }

    *outl = out_length;
    return 1;
}

static int mac_get_ctx_params(
        void* mctx,
        OSSL_PARAM params[]) {

    if (mctx == NULL) {
        ERROR("NULL mctx");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }
    sa_provider_mac_context* mac_context = mctx;

    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (param != NULL) {
        if (mac_context->mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
            size_t size = EVP_MD_get_size(mac_context->evp_md);
            if (OSSL_PARAM_set_size_t(param, size) != 1) {
                ERROR("OSSL_PARAM_set_size_t failed");
                return 0;
            }
        } else {
            if (OSSL_PARAM_set_size_t(param, AES_BLOCK_SIZE) != 1) {
                ERROR("OSSL_PARAM_set_size_t failed");
                return 0;
            }
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (param != NULL) {
        if (mac_context->mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
            size_t size = EVP_MD_block_size(mac_context->evp_md);
            if (OSSL_PARAM_set_size_t(param, size) != 1) {
                ERROR("OSSL_PARAM_set_size_t failed");
                return 0;
            }
        } else {
            if (OSSL_PARAM_set_size_t(param, AES_BLOCK_SIZE) != 1) {
                ERROR("OSSL_PARAM_set_size_t failed");
                return 0;
            }
        }
    }

    return 1;
}

static int mac_set_ctx_params(
        void* mctx,
        const OSSL_PARAM params[]) {

    if (mctx == NULL) {
        ERROR("NULL mctx");
        return 0;
    }

    if (params == NULL)
        return 1;

    sa_provider_mac_context* mac_context = mctx;
    const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (param != NULL) {
        char name[MAX_NAME_SIZE];
        char* p_name = name;
        if (!OSSL_PARAM_get_utf8_string(param, &p_name, MAX_NAME_SIZE)) {
            ERROR("OSSL_PARAM_get_utf8_string failed");
            return 0;
        }

        char properties[MAX_PROPQUERY_SIZE];
        char* p_properties = properties;
        param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
        if (param != NULL) {
            if (!OSSL_PARAM_get_utf8_string(param, &p_properties, MAX_PROPQUERY_SIZE))
                return 0;
        } else {
            properties[0] = 0;
        }

        mac_context->evp_md = EVP_MD_fetch(mac_context->provider_context->lib_ctx, name, properties);
        if (mac_context->evp_md == NULL) {
            ERROR("EVP_MD_fetch failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY);
    if (param != NULL) {
        uint64_t key;
        if (!OSSL_PARAM_get_uint64(param, &key)) {
            ERROR("OSSL_PARAM_get_uint64 failed");
            return 0;
        }

        if (mac_context->key != INVALID_HANDLE)
            sa_key_release(mac_context->key);

        mac_context->key = key;
        sa_header header;
        if (sa_key_header(&header, mac_context->key) != SA_STATUS_OK) {
            ERROR("sa_key_header failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY_DELETE);
    if (param != NULL) {
        int delete_key;
        if (!OSSL_PARAM_get_int(param, &delete_key)) {
            ERROR("OSSL_PARAM_get_int failed");
            return 0;
        }

        mac_context->delete_key = delete_key;
    }

    return 1;
}

static const OSSL_PARAM* mac_gettable_ctx_params(
        ossl_unused void* mctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM gettable_params[] = {
            OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
            OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
            OSSL_PARAM_END};

    return gettable_params;
}

ossl_unused static const OSSL_PARAM* mac_hmac_settable_ctx_params(
        ossl_unused void* mctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable_params[] = {
            OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
            OSSL_PARAM_uint64(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable_params;
}

ossl_unused static const OSSL_PARAM* mac_cmac_settable_ctx_params(
        ossl_unused void* mctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable_params[] = {
            OSSL_PARAM_uint64(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable_params;
}

#define SA_PROVIDER_MAC_FUNCTIONS(algorithm, sa_mac_algorithm) \
    static void* mac_##algorithm##_newctx(void* provctx) { \
        return mac_newctx(sa_mac_algorithm, provctx); \
    } \
\
    static const OSSL_DISPATCH sa_provider_##algorithm##_functions[] = { \
            {OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) mac_##algorithm##_newctx}, \
            {OSSL_FUNC_MAC_FREECTX, (void (*)(void)) mac_freectx}, /* Disallow DUPCTX */ \
            {OSSL_FUNC_MAC_INIT, (void (*)(void)) mac_init}, \
            {OSSL_FUNC_MAC_UPDATE, (void (*)(void)) mac_update}, \
            {OSSL_FUNC_MAC_FINAL, (void (*)(void)) mac_final}, \
            {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void)) mac_get_ctx_params}, \
            {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void)) mac_set_ctx_params}, \
            {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void)) mac_gettable_ctx_params}, \
            {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void)) mac_##algorithm##_settable_ctx_params}, \
            {0, NULL}}

SA_PROVIDER_MAC_FUNCTIONS(hmac, SA_MAC_ALGORITHM_HMAC);
SA_PROVIDER_MAC_FUNCTIONS(cmac, SA_MAC_ALGORITHM_CMAC);

ossl_unused const OSSL_ALGORITHM sa_provider_macs[] = {
        {"HMAC", "provider=secapi3", sa_provider_hmac_functions, ""},
        {"CMAC", "provider=secapi3", sa_provider_cmac_functions, ""},
        {NULL, NULL, NULL, NULL}};

#endif
