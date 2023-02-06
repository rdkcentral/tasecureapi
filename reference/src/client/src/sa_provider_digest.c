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
#include "log.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

typedef struct {
    sa_provider_context* provider_context;
    EVP_MD* evp_md;
    EVP_MD_CTX* evp_md_ctx;
    size_t digest_size;
} sa_provider_digest_context;

ossl_unused static OSSL_FUNC_digest_newctx_fn digest_sha1_newctx;
ossl_unused static OSSL_FUNC_digest_newctx_fn digest_sha256_newctx;
ossl_unused static OSSL_FUNC_digest_newctx_fn digest_sha384_newctx;
ossl_unused static OSSL_FUNC_digest_newctx_fn digest_sha512_newctx;
ossl_unused static OSSL_FUNC_digest_freectx_fn digest_freectx;
ossl_unused static OSSL_FUNC_digest_dupctx_fn digest_dupctx;
ossl_unused static OSSL_FUNC_digest_init_fn digest_init;
ossl_unused static OSSL_FUNC_digest_update_fn digest_update;
ossl_unused static OSSL_FUNC_digest_final_fn digest_final;
ossl_unused static OSSL_FUNC_digest_get_params_fn digest_sha1_get_params;
ossl_unused static OSSL_FUNC_digest_get_params_fn digest_sha256_get_params;
ossl_unused static OSSL_FUNC_digest_get_params_fn digest_sha384_get_params;
ossl_unused static OSSL_FUNC_digest_get_params_fn digest_sha512_get_params;
ossl_unused static OSSL_FUNC_digest_get_ctx_params_fn digest_get_ctx_params;
ossl_unused static OSSL_FUNC_digest_set_ctx_params_fn digest_set_ctx_params;
ossl_unused static OSSL_FUNC_digest_gettable_params_fn digest_sha1_gettable_params;
ossl_unused static OSSL_FUNC_digest_gettable_params_fn digest_sha256_gettable_params;
ossl_unused static OSSL_FUNC_digest_gettable_params_fn digest_sha384_gettable_params;
ossl_unused static OSSL_FUNC_digest_gettable_params_fn digest_sha512_gettable_params;
ossl_unused static OSSL_FUNC_digest_gettable_ctx_params_fn digest_gettable_ctx_params;
ossl_unused static OSSL_FUNC_digest_settable_ctx_params_fn digest_settable_ctx_params;

static void* digest_newctx(
        void* provctx,
        const char* algorithm,
        size_t digest_size) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_digest_context* digest_context = NULL;
    sa_provider_context* provider_context = provctx;
    digest_context = OPENSSL_zalloc(sizeof(sa_provider_digest_context));
    if (digest_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    EVP_MD* evp_md = EVP_MD_fetch(NULL, algorithm, NULL);
    if (evp_md == NULL) {
        ERROR("EVP_MD_fetch failed");
        OPENSSL_free(digest_context);
        return NULL;
    }

    EVP_MD_CTX* evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        ERROR("EVP_MD_CTX_new failed");
        OPENSSL_free(digest_context);
        EVP_MD_free(evp_md);
        return NULL;
    }

    digest_context->provider_context = provider_context;
    digest_context->evp_md = evp_md;
    digest_context->evp_md_ctx = evp_md_ctx;
    digest_context->digest_size = digest_size;
    return digest_context;
}

static void digest_freectx(void* dctx) {
    if (dctx == NULL)
        return;

    sa_provider_digest_context* digest_context = dctx;
    EVP_MD_free(digest_context->evp_md);
    digest_context->evp_md = NULL;
    EVP_MD_CTX_free(digest_context->evp_md_ctx);
    digest_context->evp_md_ctx = NULL;
    OPENSSL_free(digest_context);
}

static void* digest_dupctx(void* dctx) {
    if (dctx == NULL) {
        ERROR("NULL dctx");
        return NULL;
    }

    sa_provider_digest_context* digest_context = dctx;
    sa_provider_digest_context* new_digest_context;
    do {
        new_digest_context = OPENSSL_zalloc(sizeof(sa_provider_digest_context));
        if (new_digest_context == NULL) {
            ERROR("OPENSSL_zalloc failed");
            break;
        }

        new_digest_context->evp_md_ctx = EVP_MD_CTX_new();
        if (new_digest_context->evp_md_ctx == NULL) {
            ERROR("EVP_MD_CTX_new failed");
            break;
        }

        if (EVP_MD_CTX_copy(new_digest_context->evp_md_ctx, digest_context->evp_md_ctx) != 1) {
            ERROR("EVP_MD_CTX_copy failed");
            break;
        }

        new_digest_context->evp_md = digest_context->evp_md;
        if (EVP_MD_up_ref(new_digest_context->evp_md) != 1) {
            ERROR("EVP_MD_up_ref failed");
            new_digest_context->evp_md = NULL;
            break;
        }

        new_digest_context->provider_context = digest_context->provider_context;
        new_digest_context->digest_size = new_digest_context->digest_size;
        return new_digest_context;
    } while (false);

    digest_freectx(new_digest_context);
    return NULL;
}

static int digest_init(
        void* dctx,
        const OSSL_PARAM params[]) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    sa_provider_digest_context* digest_context = dctx;
    if (EVP_DigestInit_ex2(digest_context->evp_md_ctx, digest_context->evp_md, params) != 1) {
        ERROR("EVP_DigestInit_ex2 failed");
        return 0;
    }

    return 1;
}

static int digest_update(
        void* dctx,
        const unsigned char* in,
        size_t inl) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    sa_provider_digest_context* digest_context = dctx;
    if (EVP_DigestUpdate(digest_context->evp_md_ctx, in, inl) != 1) {
        ERROR("EVP_DigestUpdate failed");
        return 0;
    }

    return 1;
}

static int digest_final(
        void* dctx,
        unsigned char* out,
        size_t* outl,
        size_t outsz) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return 0;
    }

    if (outl == NULL) {
        ERROR("NULL outl");
        return 0;
    }

    sa_provider_digest_context* digest_context = dctx;
    if (outsz < digest_context->digest_size) {
        ERROR("digest output size too small");
        return 0;
    }

    unsigned int out_size = 0;
    if (EVP_DigestFinal_ex(digest_context->evp_md_ctx, out, &out_size) != 1) {
        ERROR("EVP_DigestFinal_ex failed");
        return 0;
    }

    *outl = out_size;
    return 1;
}

static int digest_get_params(
        const char* algorithm,
        OSSL_PARAM params[]) {

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    EVP_MD* evp_md = EVP_MD_fetch(NULL, algorithm, NULL);
    if (evp_md == NULL) {
        ERROR("NULL evp_md");
        return 0;
    }

    int result = EVP_MD_get_params(evp_md, params);
    EVP_MD_free(evp_md);
    return result;
}

static int digest_get_ctx_params(
        void* dctx,
        OSSL_PARAM params[]) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    sa_provider_digest_context* digest_context = dctx;
    return EVP_MD_CTX_get_params(digest_context->evp_md_ctx, params);
}

static int digest_set_ctx_params(
        void* dctx,
        const OSSL_PARAM params[]) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    if (params == NULL)
        return 1;

    sa_provider_digest_context* digest_context = dctx;
    return EVP_MD_CTX_set_params(digest_context->evp_md_ctx, params);
}

static const OSSL_PARAM* digest_gettable_params(const char* algorithm) {

    EVP_MD* evp_md = EVP_MD_fetch(NULL, algorithm, NULL);
    if (evp_md == NULL) {
        ERROR("NULL evp_md");
        return 0;
    }

    const OSSL_PARAM* params = EVP_MD_gettable_params(evp_md);
    EVP_MD_free(evp_md);
    return params;
}

static const OSSL_PARAM* digest_gettable_ctx_params(
        void* dctx,
        ossl_unused void* provctx) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    sa_provider_digest_context* digest_context = dctx;
    return EVP_MD_CTX_settable_params(digest_context->evp_md_ctx);
}

static const OSSL_PARAM* digest_settable_ctx_params(
        void* dctx,
        ossl_unused void* provctx) {

    if (dctx == NULL) {
        ERROR("NULL dctx");
        return 0;
    }

    sa_provider_digest_context* digest_context = dctx;
    return EVP_MD_CTX_gettable_params(digest_context->evp_md_ctx);
}

#define SA_PROVIDER_DIGEST_FUNCTIONS(algorithm, name, length) \
    static void* digest_##algorithm##_newctx(void* provctx) { \
        return digest_newctx(provctx, name, length); \
    } \
\
    static int digest_##algorithm##_get_params(OSSL_PARAM params[]) { \
        return digest_get_params(name, params); \
    } \
\
    static const OSSL_PARAM* digest_##algorithm##_gettable_params(ossl_unused void* provctx) { \
        return digest_gettable_params(name); \
    } \
\
    static const OSSL_DISPATCH sa_provider_##algorithm##_digest_functions[] = { \
            {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) digest_##algorithm##_newctx}, \
            {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) digest_freectx}, \
            {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) digest_dupctx}, \
            {OSSL_FUNC_DIGEST_INIT, (void (*)(void)) digest_init}, \
            {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) digest_update}, \
            {OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) digest_final}, \
            {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digest_##algorithm##_get_params}, \
            {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void)) digest_get_ctx_params}, \
            {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) digest_set_ctx_params}, \
            {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void)) digest_##algorithm##_gettable_params}, \
            {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void)) digest_gettable_ctx_params}, \
            {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void)) digest_settable_ctx_params}, \
            {0, NULL}}
SA_PROVIDER_DIGEST_FUNCTIONS(sha1, SN_sha1, SHA_DIGEST_LENGTH);
SA_PROVIDER_DIGEST_FUNCTIONS(sha256, SN_sha256, SHA256_DIGEST_LENGTH);
SA_PROVIDER_DIGEST_FUNCTIONS(sha384, SN_sha384, SHA384_DIGEST_LENGTH);
SA_PROVIDER_DIGEST_FUNCTIONS(sha512, SN_sha512, SHA512_DIGEST_LENGTH);

const OSSL_ALGORITHM sa_provider_digests[] = {
        {"SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", "provider=secapi3", sa_provider_sha1_digest_functions, ""},
        {"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", "provider=secapi3", sa_provider_sha256_digest_functions, ""},
        {"SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", "provider=secapi3", sa_provider_sha384_digest_functions, ""},
        {"SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", "provider=secapi3", sa_provider_sha512_digest_functions, ""},
        {NULL, NULL, NULL, NULL}};

#endif
