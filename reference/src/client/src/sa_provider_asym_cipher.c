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
#include "sa_public_key.h"
#include <memory.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

#define DEFAULT_OAEP_DIGEST "SHA1"

typedef struct {
    sa_provider_context* provider_context;
    sa_provider_key_data* key_data;
    sa_cipher_algorithm cipher_algorithm;
    int padding_mode;
    EVP_MD* oaep_md;
    EVP_MD* oaep_mgf1_md;
    uint8_t* oaep_label;
    size_t oaep_label_length;
} sa_provider_asym_cipher_context;

static OSSL_ITEM padding_values[] = {
        {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15},
        {RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE},
        {RSA_PKCS1_OAEP_PADDING, OSSL_PKEY_RSA_PAD_MODE_OAEP},
        {0, NULL}};

static OSSL_FUNC_asym_cipher_newctx_fn asym_cipher_newctx;
static OSSL_FUNC_asym_cipher_freectx_fn asym_cipher_freectx;
static OSSL_FUNC_asym_cipher_dupctx_fn asym_cipher_dupctx;
static OSSL_FUNC_asym_cipher_encrypt_init_fn asym_cipher_encrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn asym_cipher_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn asym_cipher_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn asym_cipher_decrypt;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn asym_cipher_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn asym_cipher_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn asym_cipher_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn asym_cipher_settable_ctx_params;

static void* asym_cipher_newctx(
        void* provctx) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_asym_cipher_context* asym_cipher_context = NULL;
    sa_provider_context* provider_context = provctx;
    asym_cipher_context = OPENSSL_zalloc(sizeof(sa_provider_asym_cipher_context));
    if (asym_cipher_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    asym_cipher_context->provider_context = provider_context;
    asym_cipher_context->cipher_algorithm = UINT32_MAX;
    asym_cipher_context->key_data = NULL;
    asym_cipher_context->padding_mode = RSA_PKCS1_PADDING;
    return asym_cipher_context;
}

static void asym_cipher_freectx(void* ctx) {
    if (ctx == NULL)
        return;

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    sa_provider_key_data_free(asym_cipher_context->key_data);
    EVP_MD_free(asym_cipher_context->oaep_md);
    asym_cipher_context->oaep_md = NULL;
    EVP_MD_free(asym_cipher_context->oaep_mgf1_md);
    asym_cipher_context->oaep_mgf1_md = NULL;
    OPENSSL_free(asym_cipher_context->oaep_label);
    asym_cipher_context->oaep_label = NULL;
    OPENSSL_free(asym_cipher_context);
}

static void* asym_cipher_dupctx(void* ctx) {
    if (ctx == NULL) {
        ERROR("NULL ctx");
        return NULL;
    }

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    sa_provider_asym_cipher_context* new_asym_cipher_context = NULL;
    new_asym_cipher_context = OPENSSL_zalloc(sizeof(sa_provider_asym_cipher_context));
    if (new_asym_cipher_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    new_asym_cipher_context->provider_context = asym_cipher_context->provider_context;
    new_asym_cipher_context->cipher_algorithm = asym_cipher_context->cipher_algorithm;
    new_asym_cipher_context->key_data = sa_provider_key_data_dup(asym_cipher_context->key_data);
    new_asym_cipher_context->padding_mode = asym_cipher_context->padding_mode;
    new_asym_cipher_context->oaep_md = asym_cipher_context->oaep_md;
    EVP_MD_up_ref(new_asym_cipher_context->oaep_md);
    new_asym_cipher_context->oaep_mgf1_md = asym_cipher_context->oaep_mgf1_md;
    EVP_MD_up_ref(new_asym_cipher_context->oaep_mgf1_md);
    new_asym_cipher_context->oaep_label_length = asym_cipher_context->oaep_label_length;
    new_asym_cipher_context->oaep_label = OPENSSL_malloc(new_asym_cipher_context->oaep_label_length);
    if (new_asym_cipher_context->oaep_label == NULL) {
        ERROR("OPENSSL_malloc failed");
        EVP_MD_free(new_asym_cipher_context->oaep_md);
        EVP_MD_free(new_asym_cipher_context->oaep_mgf1_md);
        OPENSSL_free(new_asym_cipher_context);
        return NULL;
    }

    return new_asym_cipher_context;
}

static int asym_cipher_encrypt_init(
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

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    asym_cipher_context->key_data = sa_provider_key_data_dup(provkey);
    return asym_cipher_set_ctx_params(ctx, params);
}

static int asym_cipher_encrypt(
        void* ctx,
        unsigned char* out,
        size_t* outlen,
        ossl_unused size_t outsize,
        const unsigned char* in,
        size_t inlen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (outlen == NULL) {
        ERROR("NULL out_length");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    if (asym_cipher_context->key_data->public_key == NULL) {
        ERROR("NULL asym_cipher_context->key_data->public_key");
        return 0;
    }

    int result = 0;
    EVP_PKEY_CTX* encrypt_pkey_ctx = NULL;
    do {
        encrypt_pkey_ctx = EVP_PKEY_CTX_new(asym_cipher_context->key_data->public_key, NULL);
        if (encrypt_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new failed");
            break;
        }

        if (EVP_PKEY_encrypt_init(encrypt_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_encrypt_init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(encrypt_pkey_ctx, asym_cipher_context->padding_mode) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
            break;
        }

        if (asym_cipher_context->padding_mode == RSA_PKCS1_OAEP_PADDING) {
            EVP_MD* oaep_md;
            if (asym_cipher_context->oaep_md != NULL)
                oaep_md = asym_cipher_context->oaep_md;
            else
                oaep_md = EVP_MD_fetch(asym_cipher_context->provider_context->lib_ctx, DEFAULT_OAEP_DIGEST, NULL);

            EVP_MD* oaep_mgf1_md = asym_cipher_context->oaep_mgf1_md != NULL ? oaep_md : asym_cipher_context->oaep_md;
            if (EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_pkey_ctx, oaep_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_oaep_md failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(encrypt_pkey_ctx, oaep_mgf1_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
                break;
            }

            if (asym_cipher_context->oaep_label != NULL && asym_cipher_context->oaep_label_length > 0) {
                uint8_t* new_label = OPENSSL_malloc(asym_cipher_context->oaep_label_length);
                if (new_label == NULL) {
                    ERROR("OPENSSL_malloc failed");
                    break;
                }

                memcpy(new_label, asym_cipher_context->oaep_label, asym_cipher_context->oaep_label_length);
                if (EVP_PKEY_CTX_set0_rsa_oaep_label(encrypt_pkey_ctx, new_label,
                            (int) asym_cipher_context->oaep_label_length) != 1) {
                    OPENSSL_free(new_label);
                    ERROR("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
                    break;
                }
            }
        }

        if (EVP_PKEY_encrypt(encrypt_pkey_ctx, out, outlen, in, inlen) != 1) {
            ERROR("EVP_PKEY_encrypt failed");
            break;
        }

        result = 1;
    } while (false);

    EVP_PKEY_CTX_free(encrypt_pkey_ctx);
    return result;
}

static int asym_cipher_decrypt_init(
        void* ctx,
        void* provkey,
        const OSSL_PARAM params[]) {
    return asym_cipher_encrypt_init(ctx, provkey, params);
}

static int asym_cipher_decrypt(void* ctx,
        unsigned char* out, // NOLINT
        size_t* outlen,
        size_t outsize,
        const unsigned char* in,
        size_t inlen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (outlen == NULL) {
        ERROR("NULL out_length");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    if (asym_cipher_context->key_data->public_key == NULL) {
        ERROR("NULL asym_cipher_context->key_data->public_key");
        return 0;
    }

    sa_cipher_algorithm cipher_algorithm;
    sa_cipher_parameters_rsa_oaep parameters_rsa_oaep;
    void* parameters = NULL;
    if (asym_cipher_context->padding_mode == RSA_PKCS1_OAEP_PADDING) {
        cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_OAEP;
        EVP_MD* oaep_md;
        if (asym_cipher_context->oaep_md != NULL)
            oaep_md = asym_cipher_context->oaep_md;
        else
            oaep_md = EVP_MD_fetch(asym_cipher_context->provider_context->lib_ctx, DEFAULT_OAEP_DIGEST, NULL);

        EVP_MD* oaep_mgf1_md = asym_cipher_context->oaep_mgf1_md != NULL ? oaep_md : asym_cipher_context->oaep_md;
        parameters_rsa_oaep.digest_algorithm = digest_algorithm_from_md(oaep_md);
        parameters_rsa_oaep.mgf1_digest_algorithm = digest_algorithm_from_md(oaep_mgf1_md);
        parameters_rsa_oaep.label = asym_cipher_context->oaep_label;
        parameters_rsa_oaep.label_length = asym_cipher_context->oaep_label_length;
        parameters = &parameters_rsa_oaep;
    } else {
        cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_PKCS1V15;
    }

    sa_crypto_cipher_context cipher_context;
    sa_status status = sa_crypto_cipher_init(&cipher_context, cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
            asym_cipher_context->key_data->private_key, parameters);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_cipher_init operation not supported");
        return OPENSSL_NOT_SUPPORTED;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_cipher_init failed");
        return 0;
    }

    sa_buffer out_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {out, outsize, 0}}};
    sa_buffer in_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {(void*) in, inlen, 0}}};
    size_t bytes_to_process = inlen;
    status = sa_crypto_cipher_process(out == NULL ? NULL : &out_buffer, cipher_context, &in_buffer, &bytes_to_process);
    sa_crypto_cipher_release(cipher_context);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_cipher_process operation not supported");
        return OPENSSL_NOT_SUPPORTED;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_cipher_process failed");
        return 0;
    }

    *outlen = bytes_to_process;
    return 1;
}

static int asym_cipher_get_ctx_params(
        void* ctx,
        OSSL_PARAM params[]) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (param != NULL) {
        switch (param->data_type) {
            case OSSL_PARAM_INTEGER:
                if (OSSL_PARAM_set_int(param, asym_cipher_context->padding_mode)) {
                    ERROR("OSSL_PARAM_set_int failed");
                    return 0;
                }

                break;

            case OSSL_PARAM_UTF8_STRING:
                for (int i = 0; padding_values[i].id != 0; i++) {
                    if (asym_cipher_context->padding_mode == (int) padding_values[i].id) {
                        if (OSSL_PARAM_set_utf8_string(param, padding_values[i].ptr) != 1) {
                            ERROR("OSSL_PARAM_set_utf8_string failed");
                            return 0;
                        }

                        break;
                    }
                }

                break;

            default:
                return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (param != NULL) {
        const char* oaep_digest =
                asym_cipher_context->oaep_md == NULL ? "" : EVP_MD_get0_name(asym_cipher_context->oaep_md);

        if (OSSL_PARAM_set_utf8_string(param, oaep_digest) != 1) {
            ERROR("OSSL_PARAM_set_utf8_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (param != NULL) {
        EVP_MD* oaep_mgf1_digest = asym_cipher_context->oaep_mgf1_md == NULL ?
                                           asym_cipher_context->oaep_md :
                                           asym_cipher_context->oaep_mgf1_md;
        const char* oaep_mgf1_digest_name = oaep_mgf1_digest == NULL ? "" : EVP_MD_get0_name(oaep_mgf1_digest);
        if (OSSL_PARAM_set_utf8_string(param, oaep_mgf1_digest_name) != 1) {
            ERROR("OSSL_PARAM_set_utf8_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (param != NULL) {
        if (OSSL_PARAM_set_octet_ptr(param, asym_cipher_context->oaep_label,
                    asym_cipher_context->oaep_label_length) != 1) {
            ERROR("OSSL_PARAM_set_octet_ptr failed");
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM* asym_cipher_gettable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
            OSSL_PARAM_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
            OSSL_PARAM_END};
    return params;
}

static int asym_cipher_set_ctx_params(
        void* ctx,
        const OSSL_PARAM params[]) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (params == NULL)
        return 1;

    sa_provider_asym_cipher_context* asym_cipher_context = ctx;
    char name[MAX_NAME_SIZE];
    char* p_name = name;
    const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (param != NULL) {
        if (!OSSL_PARAM_get_utf8_string(param, &p_name, MAX_NAME_SIZE)) {
            ERROR("OSSL_PARAM_get_utf8_string failed");
            return 0;
        }

        char md_properties[MAX_PROPQUERY_SIZE];
        char* p_md_properties = md_properties;
        param = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if (param != NULL) {
            if (!OSSL_PARAM_get_utf8_string(param, &p_md_properties, MAX_PROPQUERY_SIZE))
                return 0;
        } else {
            md_properties[0] = 0;
        }

        EVP_MD_free(asym_cipher_context->oaep_md);
        asym_cipher_context->oaep_md = EVP_MD_fetch(asym_cipher_context->provider_context->lib_ctx, name,
                md_properties);
        if (asym_cipher_context->oaep_md == NULL) {
            ERROR("EVP_MD_fetch failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (param != NULL) {
        int padding_mode = 0;
        switch (param->data_type) {
            case OSSL_PARAM_INTEGER:
                if (!OSSL_PARAM_get_int(param, &padding_mode))
                    return 0;
                break;

            case OSSL_PARAM_UTF8_STRING:
                if (param->data == NULL) {
                    ERROR("NULL param->data");
                    return 0;
                }

                for (int i = 0; padding_values[i].id != 0; i++) {
                    if (strcmp(param->data, padding_values[i].ptr) == 0) {
                        padding_mode = (int) padding_values[i].id;
                        break;
                    }
                }

                break;

            default:
                return 0;
        }

        asym_cipher_context->padding_mode = padding_mode;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (param != NULL) {
        if (!OSSL_PARAM_get_utf8_string(param, &p_name, sizeof(name))) {
            ERROR("OSSL_PARAM_get_utf8_string failed");
            return 0;
        }

        char md_properties[MAX_PROPQUERY_SIZE];
        char* p_md_properties = md_properties;
        param = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if (param != NULL) {
            if (!OSSL_PARAM_get_utf8_string(param, &p_md_properties, MAX_PROPQUERY_SIZE))
                return 0;
        } else {
            md_properties[0] = 0;
        }

        EVP_MD_free(asym_cipher_context->oaep_mgf1_md);
        asym_cipher_context->oaep_mgf1_md = EVP_MD_fetch(asym_cipher_context->provider_context->lib_ctx, name,
                md_properties);
        if (asym_cipher_context->oaep_mgf1_md == NULL) {
            ERROR("EVP_MD_fetch failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (param != NULL) {
        void* temp_label = NULL;
        size_t temp_label_length;
        if (!OSSL_PARAM_get_octet_string(param, &temp_label, 0, &temp_label_length)) {
            ERROR("OSSL_PARAM_get_octet_string failed");
            return 0;
        }

        OPENSSL_free(asym_cipher_context->oaep_label);
        asym_cipher_context->oaep_label = (unsigned char*) temp_label;
        asym_cipher_context->oaep_label_length = temp_label_length;
    }

    return 1;
}

static const OSSL_PARAM* asym_cipher_settable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
            OSSL_PARAM_END};

    return params;
}

static const OSSL_DISPATCH sa_provider_asym_cipher_functions[] = {
        {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void)) asym_cipher_newctx},
        {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void)) asym_cipher_freectx},
        {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void)) asym_cipher_dupctx},
        {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void)) asym_cipher_encrypt_init},
        {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void)) asym_cipher_encrypt},
        {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void)) asym_cipher_decrypt_init},
        {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void)) asym_cipher_decrypt},
        {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void)) asym_cipher_get_ctx_params},
        {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void)) asym_cipher_set_ctx_params},
        {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void)) asym_cipher_gettable_ctx_params},
        {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void)) asym_cipher_settable_ctx_params},
        {0, NULL}};

const OSSL_ALGORITHM sa_provider_asym_ciphers[] = {
        {"RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=secapi3", sa_provider_asym_cipher_functions, ""},
        {NULL, NULL, NULL, NULL}};

#endif
