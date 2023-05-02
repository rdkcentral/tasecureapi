/*
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
#include "log.h"
#include "sa_rights.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

typedef struct {
    sa_provider_context* provider_context;
    sa_provider_key_data* key_data;
    sa_provider_key_data* peer_key_data;
} sa_provider_keyexch_context;

ossl_unused static OSSL_FUNC_keyexch_newctx_fn keyexch_newctx;
ossl_unused static OSSL_FUNC_keyexch_freectx_fn keyexch_freectx;
ossl_unused static OSSL_FUNC_keyexch_dupctx_fn keyexch_dupctx;
ossl_unused static OSSL_FUNC_keyexch_init_fn keyexch_init;
ossl_unused static OSSL_FUNC_keyexch_derive_fn keyexch_derive;
ossl_unused static OSSL_FUNC_keyexch_set_peer_fn keyexch_set_peer;
ossl_unused static OSSL_FUNC_keyexch_set_ctx_params_fn keyexch_set_ctx_params;
ossl_unused static OSSL_FUNC_keyexch_settable_ctx_params_fn keyexch_dh_settable_ctx_params;
ossl_unused static OSSL_FUNC_keyexch_settable_ctx_params_fn keyexch_ecdh_settable_ctx_params;
ossl_unused static OSSL_FUNC_keyexch_settable_ctx_params_fn keyexch_x25519_settable_ctx_params;
ossl_unused static OSSL_FUNC_keyexch_settable_ctx_params_fn keyexch_x448_settable_ctx_params;

void* keyexch_newctx(
        void* provctx) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_keyexch_context* keyexch_context = NULL;
    sa_provider_context* provider_context = provctx;
    keyexch_context = OPENSSL_zalloc(sizeof(sa_provider_keyexch_context));
    if (keyexch_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    keyexch_context->provider_context = provider_context;
    keyexch_context->key_data = NULL;
    keyexch_context->peer_key_data = NULL;
    return keyexch_context;
}

void keyexch_freectx(void* ctx) {
    if (ctx == NULL)
        return;

    sa_provider_keyexch_context* keyexch_context = ctx;
    sa_provider_key_data_free(keyexch_context->key_data);
    sa_provider_key_data_free(keyexch_context->peer_key_data);
    OPENSSL_free(keyexch_context);
}

void* keyexch_dupctx(void* ctx) {
    if (ctx == NULL) {
        ERROR("NULL ctx");
        return NULL;
    }

    sa_provider_keyexch_context* keyexch_context = ctx;
    sa_provider_keyexch_context* new_keyexch_context = NULL;
    new_keyexch_context = OPENSSL_zalloc(sizeof(sa_provider_keyexch_context));
    if (new_keyexch_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    new_keyexch_context->provider_context = keyexch_context->provider_context;
    new_keyexch_context->key_data = sa_provider_key_data_dup(keyexch_context->key_data);
    new_keyexch_context->peer_key_data = sa_provider_key_data_dup(keyexch_context->peer_key_data);
    return new_keyexch_context;
}

int keyexch_init(
        void* ctx,
        void* provkey,
        const OSSL_PARAM params[]) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (provkey == NULL) {
        ERROR("NULL provkey");
        return 0;
    }

    sa_provider_keyexch_context* keyexch_context = ctx;
    keyexch_context->key_data = sa_provider_key_data_dup(provkey);
    return keyexch_set_ctx_params(keyexch_context, params);
}

int keyexch_derive(
        void* ctx,
        unsigned char* secret,
        size_t* secretlen,
        size_t outlen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (secretlen == NULL) {
        ERROR("NULL secretlen");
        return 0;
    }

    if (secret == NULL) {
        *secretlen = sizeof(sa_key);
        return 1;
    }

    if (outlen < sizeof(sa_key)) {
        ERROR("secret too short");
        return 0;
    }

    sa_provider_keyexch_context* keyexch_context = ctx;
    int result = 0;
    sa_key_exchange_algorithm key_exchange_algorithm;
    uint8_t* other_public = NULL;
    size_t other_public_length;
    do {
        if (keyexch_context->key_data->type == EVP_PKEY_DH) {
            key_exchange_algorithm = SA_KEY_EXCHANGE_ALGORITHM_DH;
        } else if (keyexch_context->key_data->type == EVP_PKEY_EC ||
                   keyexch_context->key_data->type == EVP_PKEY_X25519 ||
                   keyexch_context->key_data->type == EVP_PKEY_X448) {
            key_exchange_algorithm = SA_KEY_EXCHANGE_ALGORITHM_ECDH;
        } else {
            ERROR("Invalid key type");
            break;
        }

        other_public_length = i2d_PUBKEY(keyexch_context->peer_key_data->public_key, NULL);
        if (other_public_length <= 0) {
            ERROR("i2d_PUBKEY failed");
            break;
        }

        other_public = OPENSSL_malloc(other_public_length);
        if (other_public == NULL) {
            ERROR("OPENSSL_malloc failed");
            break;
        }

        uint8_t* p_pther_public = other_public;
        other_public_length = i2d_PUBKEY(keyexch_context->peer_key_data->public_key, &p_pther_public);
        if (other_public_length <= 0) {
            ERROR("i2d_PUBKEY failed");
            break;
        }

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        sa_status status = sa_key_exchange((sa_key*) secret, &rights, key_exchange_algorithm,
                keyexch_context->key_data->private_key, other_public, other_public_length, NULL);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
            ERROR("sa_key_exchange operation not supported");
            break;
        }

        if (status != SA_STATUS_OK) {
            ERROR("sa_key_exchange failed");
            break;
        }

        *secretlen = sizeof(sa_key);
        result = 1;
    } while (false);

    OPENSSL_free(other_public);
    return result;
}

int keyexch_set_peer(
        void* ctx,
        void* provkey) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (provkey == NULL) {
        ERROR("NULL provkey");
        return 0;
    }

    sa_provider_keyexch_context* keyexch_context = ctx;
    keyexch_context->peer_key_data = sa_provider_key_data_dup(provkey);
    return 1;
}

int keyexch_set_ctx_params(
        ossl_unused void* ctx,
        ossl_unused const OSSL_PARAM params[]) {
    // We advertise allowing the pad parameter for DH, but we always pad DH, so just ignore it.
    return 1;
}

ossl_unused const OSSL_PARAM* keyexch_dh_settable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused const OSSL_PARAM* keyexch_ecdh_settable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_END};

    return settable;
}

ossl_unused const OSSL_PARAM* keyexch_x25519_settable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_END};

    return settable;
}

ossl_unused const OSSL_PARAM* keyexch_x448_settable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_END};

    return settable;
}

#define SA_PROVIDER_KEYEXCH_FUNCTIONS(algorithm) \
    static const OSSL_DISPATCH sa_provider_##algorithm##_keyexch_functions[] = { \
            {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void)) keyexch_newctx}, \
            {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void)) keyexch_freectx}, \
            {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void)) keyexch_dupctx}, \
            {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void)) keyexch_init}, \
            {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void)) keyexch_derive}, \
            {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void)) keyexch_set_peer}, \
            {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void)) keyexch_set_ctx_params}, \
            {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void)) keyexch_##algorithm##_settable_ctx_params}, \
            {0, NULL}}
SA_PROVIDER_KEYEXCH_FUNCTIONS(dh);
SA_PROVIDER_KEYEXCH_FUNCTIONS(ecdh);
SA_PROVIDER_KEYEXCH_FUNCTIONS(x25519);
SA_PROVIDER_KEYEXCH_FUNCTIONS(x448);

ossl_unused const OSSL_ALGORITHM sa_provider_keyexchs[] = {
        {"DH:dhKeyAgreement:1.2.840.113549.1.3.1", "provider=secapi3", sa_provider_dh_keyexch_functions, ""},
        {"ECDH", "provider=secapi3", sa_provider_ecdh_keyexch_functions, ""},
        {"X25519:1.3.101.110", "provider=secapi3", sa_provider_x25519_keyexch_functions, ""},
        {"X448:1.3.101.111", "provider=secapi3", sa_provider_x448_keyexch_functions, ""},
        {NULL, NULL, NULL, NULL}};
#endif
