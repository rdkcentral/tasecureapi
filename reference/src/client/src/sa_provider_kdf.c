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
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifdef __APPLE__
#define htobe32(x) htonl(x)
#endif

typedef struct {
    sa_provider_context* provider_context;
    sa_kdf_algorithm kdf_algorithm;
    sa_key key;
    bool delete_key;
    sa_digest_algorithm digest_algorithm;
    void* salt;
    size_t salt_length;
    void* info;
    size_t info_length;
    int use_separator;
    int use_l;
} sa_provider_kdf_context;

ossl_unused static OSSL_FUNC_kdf_newctx_fn kdf_hkdf_newctx;
ossl_unused static OSSL_FUNC_kdf_newctx_fn kdf_concat_newctx;
ossl_unused static OSSL_FUNC_kdf_newctx_fn kdf_ansi_x963_newctx;
ossl_unused static OSSL_FUNC_kdf_freectx_fn kdf_freectx;
ossl_unused static OSSL_FUNC_kdf_dupctx_fn kdf_dupctx;
ossl_unused static OSSL_FUNC_kdf_reset_fn kdf_reset;
ossl_unused static OSSL_FUNC_kdf_derive_fn kdf_derive;
ossl_unused static OSSL_FUNC_kdf_get_ctx_params_fn kdf_get_ctx_params;
ossl_unused static OSSL_FUNC_kdf_gettable_ctx_params_fn kdf_gettable_ctx_params;
ossl_unused static OSSL_FUNC_kdf_set_ctx_params_fn kdf_set_ctx_params;
ossl_unused static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_hkdf_settable_ctx_params;
ossl_unused static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_concat_settable_ctx_params;
ossl_unused static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_ansi_x963_settable_ctx_params;
ossl_unused static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_cmac_settable_ctx_params;

void* kdf_newctx(
        sa_kdf_algorithm kdf_algorithm,
        void* provctx) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_kdf_context* kdf_context = NULL;
    sa_provider_context* provider_context = provctx;
    kdf_context = OPENSSL_zalloc(sizeof(sa_provider_kdf_context));
    if (kdf_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    kdf_context->provider_context = provider_context;
    kdf_context->kdf_algorithm = kdf_algorithm;
    kdf_context->key = INVALID_HANDLE;
    kdf_context->digest_algorithm = UINT32_MAX;
    return kdf_context;
}

void kdf_freectx(void* kctx) {
    if (kctx == NULL)
        return;

    sa_provider_kdf_context* kdf_context = kctx;
    if (kdf_context->delete_key && kdf_context->key != INVALID_HANDLE)
        sa_key_release(kdf_context->key);

    kdf_context->key = INVALID_HANDLE;
    OPENSSL_free(kdf_context->salt);
    kdf_context->salt = NULL;
    OPENSSL_free(kdf_context->info);
    kdf_context->info = NULL;
    OPENSSL_free(kdf_context);
}

void* kdf_dupctx(void* kctx) {
    if (kctx == NULL) {
        ERROR("NULL kctx");
        return NULL;
    }

    sa_provider_kdf_context* kdf_context = kctx;
    sa_provider_kdf_context* new_kdf_context = NULL;
    new_kdf_context = OPENSSL_zalloc(sizeof(sa_provider_kdf_context));
    if (new_kdf_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    new_kdf_context->provider_context = kdf_context->provider_context;
    new_kdf_context->digest_algorithm = kdf_context->digest_algorithm;
    new_kdf_context->use_separator = kdf_context->use_separator;
    new_kdf_context->use_l = kdf_context->use_l;
    if (kdf_context->salt_length > 0) {
        new_kdf_context->salt_length = kdf_context->salt_length;
        new_kdf_context->salt = OPENSSL_malloc(kdf_context->salt_length);
        if (new_kdf_context->salt == NULL) {
            ERROR("OPENSSL_malloc failed");
            kdf_freectx(new_kdf_context);
            return NULL;
        }

        memcpy(new_kdf_context->salt, kdf_context->salt, kdf_context->salt_length);
    }

    if (kdf_context->info_length > 0) {
        new_kdf_context->info_length = kdf_context->info_length;
        new_kdf_context->info = OPENSSL_malloc(kdf_context->info_length);
        if (new_kdf_context->info == NULL) {
            ERROR("OPENSSL_malloc failed");
            kdf_freectx(new_kdf_context);
            return NULL;
        }

        memcpy(new_kdf_context->info, kdf_context->info, kdf_context->info_length);
    }

    if (new_kdf_context->delete_key) {
        // We are managing the lifetime of the key, so copy the key by exporting and reimporting it.
        size_t exported_key_length = 0;
        if (sa_key_export(NULL, &exported_key_length, NULL, 0, new_kdf_context->key) != SA_STATUS_OK) {
            ERROR("sa_key_export failed");
            OPENSSL_free(new_kdf_context);
            kdf_freectx(new_kdf_context);
            return NULL;
        }

        uint8_t* exported_key = OPENSSL_malloc(exported_key_length);
        if (exported_key == NULL) {
            ERROR("OPENSSL_malloc failed");
            OPENSSL_free(new_kdf_context);
            kdf_freectx(new_kdf_context);
            return NULL;
        }

        if (sa_key_export(exported_key, &exported_key_length, NULL, 0, kdf_context->key) != SA_STATUS_OK) {
            ERROR("sa_key_export failed");
            kdf_freectx(new_kdf_context);
            OPENSSL_free(exported_key);
            return NULL;
        }

        sa_status status = sa_key_import(&new_kdf_context->key, SA_KEY_FORMAT_EXPORTED, exported_key,
                exported_key_length, NULL);
        OPENSSL_free(exported_key);
        if (status != SA_STATUS_OK) {
            ERROR("sa_key_import failed");
            kdf_freectx(new_kdf_context);
            return NULL;
        }
    }

    return new_kdf_context;
}

void kdf_reset(void* kctx) {
    if (kctx == NULL) {
        ERROR("NULL kctx");
        return;
    }

    sa_provider_kdf_context* kdf_context = kctx;
    if (kdf_context->delete_key && kdf_context->key != INVALID_HANDLE)
        sa_key_release(kdf_context->key);

    kdf_context->key = INVALID_HANDLE;
    kdf_context->delete_key = false;
    OPENSSL_free(kdf_context->salt);
    kdf_context->salt = NULL;
    OPENSSL_free(kdf_context->info);
    kdf_context->info = NULL;
    kdf_context->use_separator = 0;
    kdf_context->use_l = 0;
}

int kdf_derive(
        void* kctx,
        unsigned char* key,
        size_t keylen,
        const OSSL_PARAM params[]) {

    if (kctx == NULL) {
        ERROR("NULL kctx");
        return 0;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return 0;
    }

    sa_provider_kdf_context* kdf_context = kctx;
    if (kdf_set_ctx_params(kctx, params) != 1) {
        ERROR("kdf_set_ctx_params failed");
        return 0;
    }

    int result = 0;
    sa_kdf_parameters_hkdf parameters_hkdf;
    sa_kdf_parameters_concat parameters_concat;
    sa_kdf_parameters_ansi_x963 parameters_ansi_x963;
    sa_kdf_parameters_cmac parameters_cmac;
    uint8_t* other_data = NULL;
    void* parameters = NULL;
    do {
        switch (kdf_context->kdf_algorithm) {
            case SA_KDF_ALGORITHM_HKDF:
                parameters_hkdf.key_length = keylen;
                parameters_hkdf.digest_algorithm = kdf_context->digest_algorithm;
                parameters_hkdf.parent = kdf_context->key;
                parameters_hkdf.salt_length = kdf_context->salt_length;
                parameters_hkdf.salt = kdf_context->salt;
                parameters_hkdf.info_length = kdf_context->info_length;
                parameters_hkdf.info = kdf_context->info;
                parameters = &parameters_hkdf;
                break;

            case SA_KDF_ALGORITHM_CONCAT:
                parameters_concat.key_length = keylen;
                parameters_concat.digest_algorithm = kdf_context->digest_algorithm;
                parameters_concat.parent = kdf_context->key;
                parameters_concat.info_length = kdf_context->info_length;
                parameters_concat.info = kdf_context->info;
                parameters = &parameters_concat;
                break;

            case SA_KDF_ALGORITHM_ANSI_X963:
                parameters_ansi_x963.key_length = keylen;
                parameters_ansi_x963.digest_algorithm = kdf_context->digest_algorithm;
                parameters_ansi_x963.parent = kdf_context->key;
                parameters_ansi_x963.info_length = kdf_context->info_length;
                parameters_ansi_x963.info = kdf_context->info;
                parameters = &parameters_ansi_x963;
                break;

            case SA_KDF_ALGORITHM_CMAC: {
                if (keylen > MAX_CMAC_SIZE) {
                    ERROR("keylen too large");
                    continue; // NOLINT
                }

                size_t length = kdf_context->salt_length + (kdf_context->use_separator == 1 ? 1 : 0) +
                                kdf_context->info_length + (kdf_context->use_l == 1 ? 4 : 0);
                other_data = OPENSSL_malloc(length);
                if (other_data == NULL) {
                    ERROR("OPENSSL_malloc failed");
                    continue; // NOLINT
                }

                size_t position = 0;
                if (kdf_context->salt != NULL) {
                    memcpy(other_data, kdf_context->salt, kdf_context->salt_length);
                    position += kdf_context->salt_length;
                }

                if (kdf_context->use_separator == 1) {
                    other_data[position] = 0;
                    position++;
                }

                if (kdf_context->info != NULL) {
                    memcpy(other_data + position, kdf_context->info, kdf_context->info_length);
                    position += kdf_context->info_length;
                }

                if (kdf_context->use_l) {
                    uint32_t l = htobe32(keylen);
                    memcpy(other_data + position, (unsigned char*) &l, sizeof(uint32_t));
                    position += sizeof(uint32_t);
                }

                parameters_cmac.key_length = keylen;
                parameters_cmac.counter = (keylen / SYM_128_KEY_SIZE) + (keylen % SYM_128_KEY_SIZE == 0 ? 0 : 1);
                parameters_cmac.parent = kdf_context->key;
                parameters_cmac.other_data_length = position;
                parameters_cmac.other_data = other_data;
                parameters = &parameters_cmac;
                break;
            }
            default:
                continue; // NOLINT
        }

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        sa_key derived_key;
        sa_status status = sa_key_derive(&derived_key, &rights, kdf_context->kdf_algorithm, parameters);
        if (status != SA_STATUS_OK) {
            ERROR("sa_key_derive failed");
            break;
        }

        memcpy(key, &derived_key, sizeof(sa_key));
        result = 1;
    } while (false);

    OPENSSL_free(other_data);
    return result;
}

int kdf_get_ctx_params(
        ossl_unused void* kctx,
        ossl_unused OSSL_PARAM params[]) {

    if (kctx == NULL) {
        ERROR("NULL kctx");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    sa_provider_kdf_context* kdf_context = kctx;
    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (param == NULL) {
        ERROR("OSSL_PARAM_locate failed");
        return 0;
    }

    if (kdf_context->kdf_algorithm == SA_KDF_ALGORITHM_CMAC) {
        if (OSSL_PARAM_set_size_t(param, MAX_CMAC_SIZE) != 1) {
            ERROR("OSSL_PARAM_set_size_t failed");
            return 0;
        }
    } else {
        if (OSSL_PARAM_set_size_t(param, digest_length(kdf_context->digest_algorithm)) != 1) {
            ERROR("OSSL_PARAM_set_size_t failed");
            return 0;
        }
    }

    return 1;
}

int kdf_set_ctx_params(
        ossl_unused void* kctx,
        ossl_unused const OSSL_PARAM params[]) {

    if (kctx == NULL) {
        ERROR("NULL kctx");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    sa_provider_kdf_context* kdf_context = kctx;
    const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (param != NULL) {
        size_t length;
        unsigned long key;
        void* p_key = &key;
        if (OSSL_PARAM_get_octet_string(param, &p_key, sizeof(sa_key), &length) != 1) {
            ERROR("OSSL_PARAM_get_octet_string failed");
            return 0;
        }

        sa_header header;
        if (sa_key_header(&header, key) != SA_STATUS_OK) {
            ERROR("sa_key_header failed");
            return 0;
        }

        if (kdf_context->key != INVALID_HANDLE)
            sa_key_release(kdf_context->key);

        kdf_context->key = key;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY);
    if (param != NULL) {
        unsigned long key;
        if (!OSSL_PARAM_get_ulong(param, &key)) {
            ERROR("OSSL_PARAM_get_ulong failed");
            return 0;
        }

        sa_header header;
        if (sa_key_header(&header, key) != SA_STATUS_OK) {
            ERROR("sa_key_header failed");
            return 0;
        }

        if (kdf_context->key != INVALID_HANDLE)
            sa_key_release(kdf_context->key);

        kdf_context->key = key;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY_DELETE);
    if (param != NULL) {
        int delete_key;
        if (!OSSL_PARAM_get_int(param, &delete_key)) {
            ERROR("OSSL_PARAM_get_int failed");
            return 0;
        }

        kdf_context->delete_key = delete_key;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (param != NULL) {
        char name[MAX_NAME_SIZE];
        char* p_name = name;
        if (OSSL_PARAM_get_utf8_string(param, &p_name, MAX_NAME_SIZE) != 1) {
            ERROR("OSSL_PARAM_get_utf8_string failed");
            return 0;
        }

        kdf_context->digest_algorithm = digest_algorithm_from_name(name);
    }

    param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (param != NULL) {
        OPENSSL_free(kdf_context->salt);
        kdf_context->salt = NULL;
        if (OSSL_PARAM_get_octet_string(param, &kdf_context->salt, SIZE_MAX, &kdf_context->salt_length) != 1) {
            ERROR("OSSL_PARAM_get_octet_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (param != NULL) {
        OPENSSL_free(kdf_context->info);
        kdf_context->info = NULL;
        if (OSSL_PARAM_get_octet_string(param, &kdf_context->info, SIZE_MAX, &kdf_context->info_length) != 1) {
            ERROR("OSSL_PARAM_get_octet_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR);
    if (param != NULL) {
        if (OSSL_PARAM_get_int(param, &kdf_context->use_separator) != 1) {
            ERROR("OSSL_PARAM_get_int failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_L);
    if (param != NULL) {
        if (OSSL_PARAM_get_int(param, &kdf_context->use_l) != 1) {
            ERROR("OSSL_PARAM_get_int failed");
            return 0;
        }
    }

    return 1;
}

ossl_unused const OSSL_PARAM* kdf_gettable_ctx_params(
        ossl_unused void* kctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM gettable[] = {
            OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
            OSSL_PARAM_END};

    return gettable;
}

ossl_unused const OSSL_PARAM* kdf_hkdf_settable_ctx_params(
        ossl_unused void* kctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
            OSSL_PARAM_ulong(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused const OSSL_PARAM* kdf_concat_settable_ctx_params(
        ossl_unused void* kctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
            OSSL_PARAM_ulong(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused const OSSL_PARAM* kdf_ansi_x963_settable_ctx_params(
        ossl_unused void* kctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
            OSSL_PARAM_ulong(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused const OSSL_PARAM* kdf_cmac_settable_ctx_params(
        ossl_unused void* kctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM settable[] = {
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
            OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_L, NULL),
            OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, NULL),
            OSSL_PARAM_ulong(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable;
}

#define SA_PROVIDER_KDF_FUNCTIONS(algorithm, kdf_algorithm) \
    static void* kdf_##algorithm##_newctx(void* provctx) { \
        return kdf_newctx(kdf_algorithm, provctx); \
    } \
\
    static const OSSL_DISPATCH sa_provider_##algorithm##_kdf_functions[] = { \
            {OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf_##algorithm##_newctx}, \
            {OSSL_FUNC_KDF_FREECTX, (void (*)(void)) kdf_freectx}, \
            {OSSL_FUNC_KDF_DUPCTX, (void (*)(void)) kdf_dupctx}, \
            {OSSL_FUNC_KDF_RESET, (void (*)(void)) kdf_reset}, \
            {OSSL_FUNC_KDF_DERIVE, (void (*)(void)) kdf_derive}, \
            {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void)) kdf_get_ctx_params}, \
            {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void)) kdf_set_ctx_params}, \
            {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void)) kdf_gettable_ctx_params}, \
            {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void)) kdf_##algorithm##_settable_ctx_params}, \
            {0, NULL}}
SA_PROVIDER_KDF_FUNCTIONS(hkdf, SA_KDF_ALGORITHM_HKDF);
SA_PROVIDER_KDF_FUNCTIONS(concat, SA_KDF_ALGORITHM_CONCAT);
SA_PROVIDER_KDF_FUNCTIONS(ansi_x963, SA_KDF_ALGORITHM_ANSI_X963);
SA_PROVIDER_KDF_FUNCTIONS(cmac, SA_KDF_ALGORITHM_CMAC);

ossl_unused const OSSL_ALGORITHM sa_provider_kdfs[] = {
        {"HKDF", "provider=secapi3", sa_provider_hkdf_kdf_functions, ""},
        {"SSKDF:CONCAT", "provider=secapi3", sa_provider_concat_kdf_functions, ""},
        {"X963KDF:ANSI_X963", "provider=secapi3", sa_provider_ansi_x963_kdf_functions, ""},
        {"KBKDF:CMAC", "provider=secapi3", sa_provider_cmac_kdf_functions, ""},
        {NULL, NULL, NULL, NULL}};
#endif
