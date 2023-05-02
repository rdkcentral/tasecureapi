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
#include "common.h"
#include "digest_util.h"
#include "log.h"
#include "sa_public_key.h"
#include <memory.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#define RSA_DEFAULT_PADDING_MODE RSA_PKCS1_PADDING
#define RSA_DEFAULT_PSS_SALT_LENGTH RSA_PSS_SALTLEN_AUTO

typedef struct {
    sa_provider_context* provider_context;
    sa_provider_key_data* key_data;
    EVP_MD_CTX* evp_md_ctx;
    EVP_MD* evp_md;
    EVP_MD* mgf1_md;
    int padding_mode;
    int pss_salt_length;
} sa_provider_signature_context;

ossl_unused static OSSL_FUNC_signature_newctx_fn signature_newctx;
ossl_unused static OSSL_FUNC_signature_freectx_fn signature_freectx;
ossl_unused static OSSL_FUNC_signature_dupctx_fn signature_dupctx;
ossl_unused static OSSL_FUNC_signature_sign_init_fn signature_sign_init;
ossl_unused static OSSL_FUNC_signature_sign_fn signature_sign;
ossl_unused static OSSL_FUNC_signature_verify_init_fn signature_verify_init;
ossl_unused static OSSL_FUNC_signature_verify_fn signature_verify;
ossl_unused static OSSL_FUNC_signature_digest_sign_init_fn signature_digest_sign_init;
ossl_unused static OSSL_FUNC_signature_digest_sign_update_fn signature_digest_sign_update;
ossl_unused static OSSL_FUNC_signature_digest_sign_final_fn signature_digest_sign_final;
ossl_unused static OSSL_FUNC_signature_digest_sign_fn signature_digest_sign;
ossl_unused static OSSL_FUNC_signature_digest_verify_init_fn signature_digest_verify_init;
ossl_unused static OSSL_FUNC_signature_digest_verify_update_fn signature_digest_verify_update;
ossl_unused static OSSL_FUNC_signature_digest_verify_final_fn signature_digest_verify_final;
ossl_unused static OSSL_FUNC_signature_digest_verify_fn signature_digest_verify;
ossl_unused static OSSL_FUNC_signature_get_ctx_params_fn signature_get_ctx_params;
ossl_unused static OSSL_FUNC_signature_set_ctx_params_fn signature_set_ctx_params;
ossl_unused static OSSL_FUNC_signature_gettable_ctx_params_fn signature_rsa_gettable_ctx_params;
ossl_unused static OSSL_FUNC_signature_gettable_ctx_params_fn signature_ecdsa_gettable_ctx_params;
ossl_unused static OSSL_FUNC_signature_gettable_ctx_params_fn signature_eddsa_gettable_ctx_params;
ossl_unused static OSSL_FUNC_signature_get_ctx_md_params_fn signature_get_ctx_md_params;
ossl_unused static OSSL_FUNC_signature_gettable_ctx_md_params_fn signature_gettable_ctx_md_params;
ossl_unused static OSSL_FUNC_signature_set_ctx_md_params_fn signature_set_ctx_md_params;
ossl_unused static OSSL_FUNC_signature_settable_ctx_md_params_fn signature_settable_ctx_md_params;

static uint8_t rsa_sha1_oid[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
        0x00};
static uint8_t rsa_sha256_oid[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
        0x00};
static uint8_t rsa_sha384_oid[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05,
        0x00};
static uint8_t rsa_sha512_oid[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05,
        0x00};
static uint8_t ecdsa_sha1_oid[] = {0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01};
static uint8_t ecdsa_sha256_oid[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
static uint8_t ecdsa_sha384_oid[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
static uint8_t ecdsa_sha512_oid[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04};
static uint8_t eddsa_ed25519_oid[] = {0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70};
static uint8_t eddsa_ed448_oid[] = {0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71};

static void* signature_newctx(
        void* provctx,
        ossl_unused const char* propq) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_signature_context* signature_context = NULL;
    sa_provider_context* provider_context = provctx;
    signature_context = OPENSSL_zalloc(sizeof(sa_provider_signature_context));
    if (signature_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    signature_context->provider_context = provider_context;
    signature_context->key_data = NULL;
    signature_context->evp_md_ctx = NULL;
    signature_context->evp_md = NULL;
    signature_context->mgf1_md = NULL;
    signature_context->padding_mode = RSA_DEFAULT_PADDING_MODE;
    signature_context->pss_salt_length = RSA_DEFAULT_PSS_SALT_LENGTH;
    return signature_context;
}

static void signature_freectx(void* ctx) {
    if (ctx == NULL)
        return;

    sa_provider_signature_context* signature_context = ctx;
    sa_provider_key_data_free(signature_context->key_data);
    EVP_MD_CTX_free(signature_context->evp_md_ctx);
    signature_context->evp_md_ctx = NULL;
    EVP_MD_free(signature_context->evp_md);
    signature_context->evp_md = NULL;
    EVP_MD_free(signature_context->mgf1_md);
    signature_context->mgf1_md = NULL;
    OPENSSL_free(signature_context);
}

static void* signature_dupctx(void* ctx) {
    if (ctx == NULL) {
        ERROR("NULL ctx");
        return NULL;
    }

    int result = 0;
    sa_provider_signature_context* signature_context = ctx;
    sa_provider_signature_context* new_signature_context;
    do {
        new_signature_context = OPENSSL_zalloc(sizeof(sa_provider_signature_context));
        if (new_signature_context == NULL) {
            ERROR("OPENSSL_zalloc failed");
            break;
        }

        new_signature_context->provider_context = signature_context->provider_context;
        new_signature_context->key_data = sa_provider_key_data_dup(signature_context->key_data);
        new_signature_context->evp_md_ctx = EVP_MD_CTX_new();
        if (new_signature_context->evp_md_ctx == NULL) {
            ERROR("EVP_MD_CTX_new failed");
            break;
        }

        if (EVP_MD_CTX_copy(new_signature_context->evp_md_ctx, signature_context->evp_md_ctx) != 1) {
            ERROR("EVP_MD_CTX_copy failed");
            break;
        }

        new_signature_context->evp_md = signature_context->evp_md;
        if (new_signature_context->evp_md != NULL &&
                EVP_MD_up_ref(new_signature_context->evp_md) != 1) {
            ERROR("EVP_MD_up_ref failed");
            break;
        }

        new_signature_context->mgf1_md = signature_context->mgf1_md;
        if (new_signature_context->mgf1_md != NULL &&
                EVP_MD_up_ref(new_signature_context->mgf1_md) != 1) {
            ERROR("EVP_MD_up_ref failed");
            break;
        }

        new_signature_context->padding_mode = signature_context->padding_mode;
        new_signature_context->pss_salt_length = signature_context->pss_salt_length;
        result = 1;
    } while (false);

    if (result == 0 && new_signature_context != NULL) {
        EVP_MD_CTX_free(new_signature_context->evp_md_ctx);
        EVP_MD_free(new_signature_context->evp_md);
        EVP_MD_free(new_signature_context->mgf1_md);
        OPENSSL_free(new_signature_context);
    }

    return new_signature_context;
}

static int signature_sign_init(
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

    sa_provider_signature_context* signature_context = ctx;
    signature_context->key_data = sa_provider_key_data_dup(provkey);
    return signature_set_ctx_params(ctx, params);
}

static int signature_sign(
        void* ctx,
        unsigned char* sig,
        size_t* siglen,
        ossl_unused size_t sigsize,
        const unsigned char* tbs,
        size_t tbslen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (siglen == NULL) {
        ERROR("NULL siglen");
        return 0;
    }

    if (tbs == NULL)
        tbslen = 0;

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->key_data == NULL) {
        ERROR("NULL key_data");
        return 0;
    }

    sa_signature_algorithm signature_algorithm;
    sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
    sa_sign_parameters_rsa_pss parameters_rsa_pss;
    sa_sign_parameters_ecdsa parameters_ecdsa;
    void* parameters = NULL;
    switch (signature_context->key_data->private_key_header.type) {
        case SA_KEY_TYPE_RSA:
            if (signature_context->padding_mode == RSA_PKCS1_PADDING) {
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15;
                parameters_rsa_pkcs1v15.digest_algorithm = digest_algorithm_from_md(signature_context->evp_md);
                if (parameters_rsa_pkcs1v15.digest_algorithm == UINT32_MAX)
                    parameters_rsa_pkcs1v15.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

                parameters_rsa_pkcs1v15.precomputed_digest = true;
                parameters = &parameters_rsa_pkcs1v15;
            } else if (signature_context->padding_mode == RSA_PKCS1_PSS_PADDING) {
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PSS;
                parameters_rsa_pss.digest_algorithm = digest_algorithm_from_md(signature_context->evp_md);
                parameters_rsa_pss.mgf1_digest_algorithm = digest_algorithm_from_md(signature_context->mgf1_md);
                if (parameters_rsa_pss.digest_algorithm == UINT32_MAX)
                    parameters_rsa_pss.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

                if (parameters_rsa_pss.mgf1_digest_algorithm == UINT32_MAX)
                    parameters_rsa_pss.mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

                parameters_rsa_pss.precomputed_digest = true;
                int salt_length;
                if (signature_context->pss_salt_length == RSA_PSS_SALTLEN_DIGEST) {
                    salt_length = (int) digest_length(parameters_rsa_pss.digest_algorithm);
                } else if (signature_context->pss_salt_length == RSA_PSS_SALTLEN_AUTO ||
                           signature_context->pss_salt_length == RSA_PSS_SALTLEN_MAX) {
                    salt_length = EVP_PKEY_size(signature_context->key_data->public_key) -
                                  digest_length(parameters_rsa_pss.digest_algorithm) - 2;
                    if ((EVP_PKEY_bits(signature_context->key_data->public_key) & 0x7) == 1)
                        salt_length--;

                    if (salt_length < 0) {
                        ERROR("salt_length unknown");
                        return 0;
                    }
                } else
                    salt_length = signature_context->pss_salt_length;

                parameters_rsa_pss.salt_length = salt_length;
                parameters = &parameters_rsa_pss;
            } else {
                ERROR("Invalid padding mode");
                return 0;
            }

            break;

        case SA_KEY_TYPE_EC:
            if (!is_pcurve(signature_context->key_data->private_key_header.type_parameters.curve)) {
                ERROR("Invalid EC curve");
                return 0;
            }

            signature_algorithm = SA_SIGNATURE_ALGORITHM_ECDSA;
            parameters_ecdsa.digest_algorithm = digest_algorithm_from_md(signature_context->evp_md);
            if (parameters_ecdsa.digest_algorithm == UINT32_MAX)
                parameters_ecdsa.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

            parameters_ecdsa.precomputed_digest = true;
            parameters = &parameters_ecdsa;
            break;

        default:
            ERROR("Invalid key type");
            return 0;
    }

    uint8_t local_signature[MAX_SIGNATURE_LENGTH];
    size_t local_signature_length = MAX_SIGNATURE_LENGTH;
    sa_status status = sa_crypto_sign(sig != NULL ? local_signature : NULL, &local_signature_length,
            signature_algorithm, signature_context->key_data->private_key, tbs, tbslen, parameters);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_sign operation not supported");
        return 0;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
    }

    if (signature_context->key_data->private_key_header.type == SA_KEY_TYPE_EC) {
        // Take the SecApi 3 signature and encode it like OpenSSL would so that it looks like it came from
        // OpenSSL
        if (sig != NULL) {
            if (!ec_encode_signature(sig, siglen, local_signature, local_signature_length)) {
                ERROR("ec_encode_signature failed");
                return 0;
            }
        } else {
            // Add the most number of bytes that can be added by ASN.1 encoding (9). It could be as few as 6.
            *siglen = local_signature_length + 9;
        }
    } else {
        if (sig != NULL)
            memcpy(sig, local_signature, local_signature_length);

        *siglen = local_signature_length;
    }

    return 1;
}

static int signature_verify_init(
        void* ctx,
        void* provkey,
        const OSSL_PARAM params[]) {
    return signature_sign_init(ctx, provkey, params);
}

static int signature_verify(
        void* ctx,
        const unsigned char* sig,
        size_t siglen,
        const unsigned char* tbs,
        size_t tbslen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (tbs == NULL)
        tbslen = 0;

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->key_data == NULL) {
        ERROR("NULL key_data");
        return 0;
    }

    sa_header* header = &signature_context->key_data->private_key_header;
    // ED25519 and ED448 have to use the signature_digest_verify function.
    if (header->type == SA_KEY_TYPE_EC &&
            (header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                    header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED448)) {
        ERROR("Invalid key type");
        return 0;
    }

    int result = 0;
    EVP_PKEY* verify_pkey = signature_context->key_data->public_key;
    EVP_PKEY_CTX* verify_pkey_ctx = NULL;
    do {
        int key_type = EVP_PKEY_base_id(verify_pkey);
        verify_pkey_ctx = EVP_PKEY_CTX_new(verify_pkey, NULL);
        if (verify_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new failed");
            break;
        }

        if (EVP_PKEY_verify_init(verify_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_verify_init failed");
            break;
        }

        if (key_type == EVP_PKEY_RSA) {
            if (EVP_PKEY_CTX_set_rsa_padding(verify_pkey_ctx, signature_context->padding_mode) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (signature_context->padding_mode == RSA_PKCS1_PSS_PADDING) {
                if (signature_context->mgf1_md != NULL)
                    if (EVP_PKEY_CTX_set_rsa_mgf1_md(verify_pkey_ctx, signature_context->mgf1_md) != 1) {
                        ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
                        break;
                    }

                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_pkey_ctx,
                            signature_context->pss_salt_length) != 1) {
                    ERROR("EVP_PKEY_CTX_set_rsa_pss_saltlen failed");
                    break;
                }
            }
        }

        if (EVP_PKEY_CTX_set_signature_md(verify_pkey_ctx, signature_context->evp_md) != 1) {
            ERROR("EVP_PKEY_CTX_set_signature_md failed");
            break;
        }

        if (EVP_PKEY_verify(verify_pkey_ctx, sig, siglen, tbs, tbslen) != 1) {
            ERROR("EVP_PKEY_verify");
            break;
        }

        result = 1;
    } while (false);

    EVP_PKEY_CTX_free(verify_pkey_ctx);
    return result;
}

static int signature_digest_sign_init(
        void* ctx,
        const char* mdname,
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

    int result = 0;
    sa_provider_signature_context* signature_context = ctx;
    do {
        if (signature_sign_init(ctx, provkey, params) != 1) {
            ERROR("signature_sign_init failed");
            break;
        }

        sa_header* header = &signature_context->key_data->private_key_header;
        if (header->type == SA_KEY_TYPE_EC && (header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                                                      header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED448)) {
            if (mdname != NULL && mdname[0] != '\0') {
                ERROR("Invalid digest for ED25519 or ED448");
                break;
            }

            EVP_MD_free(signature_context->evp_md);
            signature_context->evp_md = NULL;
            EVP_MD_CTX_free(signature_context->evp_md_ctx);
            signature_context->evp_md_ctx = NULL;
        } else {
            EVP_MD_free(signature_context->evp_md);
            signature_context->evp_md = EVP_MD_fetch(signature_context->provider_context->lib_ctx,
                    mdname, NULL);
            if (signature_context->evp_md == NULL) {
                ERROR("NULL evp_md");
                break;
            }

            EVP_MD_CTX_free(signature_context->evp_md_ctx);
            signature_context->evp_md_ctx = EVP_MD_CTX_new();
            if (signature_context->evp_md_ctx == NULL) {
                ERROR("NULL evp_md_ctx");
                break;
            }

            if (EVP_DigestInit_ex2(signature_context->evp_md_ctx, signature_context->evp_md,
                        params) != 1) {
                ERROR("EVP_DigestInit_ex2 failed");
                break;
            }
        }

        result = 1;
    } while (false);

    if (result == 0) {
        EVP_MD_free(signature_context->evp_md);
        EVP_MD_CTX_free(signature_context->evp_md_ctx);
        signature_context->evp_md = NULL;
        signature_context->evp_md_ctx = NULL;
        signature_context->key_data = NULL;
    }

    return 1;
}

static int signature_digest_sign_update(
        void* ctx,
        const unsigned char* data,
        size_t datalen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (data == NULL) {
        ERROR("NULL data");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    if (EVP_DigestUpdate(signature_context->evp_md_ctx, data, datalen) != 1) {
        ERROR("EVP_DigestUpdate failed");
        return 0;
    }

    return 1;
}

static int signature_digest_sign_final(
        void* ctx,
        unsigned char* sig,
        size_t* siglen,
        size_t sigsize) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (siglen == NULL) {
        ERROR("NULL siglen");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int md_size;
    if (sig != NULL) {
        if (EVP_DigestFinal_ex(signature_context->evp_md_ctx, md, &md_size) != 1) {
            ERROR("EVP_DigestFinal_ex failed");
            return 0;
        }
    } else {
        md_size = EVP_MD_get_size(signature_context->evp_md);
    }

    if (signature_sign(ctx, sig, siglen, sigsize, md, md_size) != 1) {
        ERROR("signature_sign failed");
        return 0;
    }

    return 1;
}

static int signature_digest_sign(
        void* ctx,
        unsigned char* sigret,
        size_t* siglen,
        size_t sigsize,
        const unsigned char* tbs,
        size_t tbslen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (siglen == NULL) {
        ERROR("NULL siglen");
        return 0;
    }

    if (tbs == NULL)
        tbslen = 0;

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->key_data == NULL) {
        ERROR("NULL key_data");
        return 0;
    }

    sa_header* header = &signature_context->key_data->private_key_header;
    if (header->type != SA_KEY_TYPE_EC &&
            !(header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                    header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED448)) {
        ERROR("Invalid key type");
        return 0;
    }

    if (sigret != NULL)
        *siglen = sigsize;

    sa_signature_algorithm signature_algorithm = SA_SIGNATURE_ALGORITHM_EDDSA;
    sa_status status = sa_crypto_sign(sigret, siglen, signature_algorithm,
            signature_context->key_data->private_key, tbs, tbslen, NULL);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_sign operation not supported");
        return 0;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
    }

    return 1;
}

static int signature_digest_verify_init(
        void* ctx,
        const char* mdname,
        void* provkey,
        const OSSL_PARAM params[]) {
    return signature_digest_sign_init(ctx, mdname, provkey, params);
}

static int signature_digest_verify_update(
        void* ctx,
        const unsigned char* data,
        size_t datalen) {
    return signature_digest_sign_update(ctx, data, datalen);
}

static int signature_digest_verify_final(
        void* ctx,
        const unsigned char* sig,
        size_t siglen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (sig == NULL) {
        ERROR("NULL sig");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int md_size;
    if (EVP_DigestFinal_ex(signature_context->evp_md_ctx, md, &md_size) != 1) {
        ERROR("EVP_DigestFinal_ex failed");
        return 0;
    }

    if (signature_verify(ctx, sig, siglen, md, md_size) != 1) {
        ERROR("signature_verify failed");
        return 0;
    }

    return 1;
}

static int signature_digest_verify(
        void* ctx,
        const unsigned char* sig,
        size_t siglen,
        const unsigned char* tbs,
        size_t tbslen) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (sig == NULL) {
        ERROR("NULL sig");
        return 0;
    }

    if (tbs == NULL)
        tbslen = 0;

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->key_data == NULL) {
        ERROR("NULL key_data");
        return 0;
    }

    sa_header* header = &signature_context->key_data->private_key_header;
    if (header->type != SA_KEY_TYPE_EC &&
            !(header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                    header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED448)) {
        ERROR("Invalid key type");
        return 0;
    }

    int result = 0;
    EVP_PKEY* verify_pkey = signature_context->key_data->public_key;
    EVP_MD_CTX* verify_md_ctx = NULL;
    do {
        verify_md_ctx = EVP_MD_CTX_new();
        if (verify_md_ctx == NULL) {
            ERROR("NULL verify_md_ctx");
            break;
        }

        if (EVP_DigestVerifyInit(verify_md_ctx, NULL, NULL, NULL, verify_pkey) != 1) {
            ERROR("EVP_DigestVerifyInit failed");
            break;
        }

        if (EVP_DigestVerify(verify_md_ctx, sig, siglen, tbs, tbslen) != 1) {
            ERROR("EVP_DigestVerify");
            break;
        }

        result = 1;
    } while (false);

    EVP_MD_CTX_free(verify_md_ctx);
    return result;
}

static int signature_get_ctx_params(
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

    sa_provider_signature_context* signature_context = ctx;
    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (param != NULL) {
        uint8_t* algorithm_id = NULL;
        size_t algorithm_id_length = 0;
        if (signature_context->key_data->type == EVP_PKEY_RSA) {
            switch (EVP_MD_get_type(signature_context->evp_md)) {
                case NID_sha1:
                    algorithm_id = rsa_sha1_oid;
                    algorithm_id_length = sizeof(rsa_sha1_oid);
                    break;

                case NID_sha256:
                    algorithm_id = rsa_sha256_oid;
                    algorithm_id_length = sizeof(rsa_sha256_oid);
                    break;

                case NID_sha384:
                    algorithm_id = rsa_sha384_oid;
                    algorithm_id_length = sizeof(rsa_sha384_oid);
                    break;

                case NID_sha512:
                    algorithm_id = rsa_sha512_oid;
                    algorithm_id_length = sizeof(rsa_sha512_oid);
                    break;

                default:
                    break;
            }
        } else if (signature_context->key_data->type == EVP_PKEY_EC) {
            switch (EVP_MD_get_type(signature_context->evp_md)) {
                case NID_sha1:
                    algorithm_id = ecdsa_sha1_oid;
                    algorithm_id_length = sizeof(ecdsa_sha1_oid);
                    break;

                case NID_sha256:
                    algorithm_id = ecdsa_sha256_oid;
                    algorithm_id_length = sizeof(ecdsa_sha256_oid);
                    break;

                case NID_sha384:
                    algorithm_id = ecdsa_sha384_oid;
                    algorithm_id_length = sizeof(ecdsa_sha384_oid);
                    break;

                case NID_sha512:
                    algorithm_id = ecdsa_sha512_oid;
                    algorithm_id_length = sizeof(ecdsa_sha512_oid);
                    break;

                default:
                    break;
            }
        } else if (signature_context->key_data->type == EVP_PKEY_ED25519) {
            algorithm_id = eddsa_ed25519_oid;
            algorithm_id_length = sizeof(eddsa_ed25519_oid);
        } else if (signature_context->key_data->type == EVP_PKEY_ED448) {
            algorithm_id = eddsa_ed448_oid;
            algorithm_id_length = sizeof(eddsa_ed448_oid);
        }

        if (!OSSL_PARAM_set_octet_string(param, algorithm_id, algorithm_id_length)) {
            ERROR("OSSL_PARAM_set_octet_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (param != NULL) {
        if (param->data_type == OSSL_PARAM_INTEGER) {
            if (!OSSL_PARAM_set_int(param, signature_context->padding_mode)) {
                ERROR("OSSL_PARAM_set_int failed");
                return 0;
            }
        } else if (param->data_type == OSSL_PARAM_UTF8_STRING) {
            if (signature_context->padding_mode == RSA_PKCS1_PADDING) {
                if (OSSL_PARAM_set_utf8_string(param, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) != 1) {
                    ERROR("OSSL_PARAM_set_utf8_string failed");
                    return 0;
                }
            } else if (signature_context->padding_mode == RSA_PKCS1_PSS_PADDING) {
                if (OSSL_PARAM_set_utf8_string(param, OSSL_PKEY_RSA_PAD_MODE_PSS) != 1) {
                    ERROR("OSSL_PARAM_set_utf8_string failed");
                    return 0;
                }
            } else {
                ERROR("Unknown padding mode");
                return 0;
            }
        } else {
            ERROR("Unsupported param data type");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (param != NULL) {
        const char* md_name = EVP_MD_get0_name(signature_context->evp_md);
        if (md_name == NULL) {
            ERROR("NULL md_name");
            return 0;
        }

        if (OSSL_PARAM_set_utf8_string(param, md_name) != 1) {
            ERROR("OSSL_PARAM_set_utf8_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (param != NULL) {
        size_t digest_size = EVP_MD_get_size(signature_context->evp_md);
        if (OSSL_PARAM_set_size_t(param, digest_size) != 1) {
            ERROR("OSSL_PARAM_set_size_t failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (param != NULL) {
        const char* md_name = EVP_MD_get0_name(signature_context->mgf1_md);
        if (md_name == NULL) {
            ERROR("NULL md_name");
            return 0;
        }

        if (OSSL_PARAM_set_utf8_string(param, md_name) != 1) {
            ERROR("OSSL_PARAM_set_utf8_string failed");
            return 0;
        }
    }

    param = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (param != NULL) {
        if (param->data_type == OSSL_PARAM_INTEGER) {
            if (OSSL_PARAM_set_int(param, signature_context->pss_salt_length) != 1) {
                ERROR("OSSL_PARAM_set_int failed");
                return 0;
            }
        } else if (param->data_type == OSSL_PARAM_UTF8_STRING) {
            const char* value;
            switch (signature_context->pss_salt_length) {
                case RSA_PSS_SALTLEN_DIGEST:
                    value = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
                    break;

                case RSA_PSS_SALTLEN_MAX:
                    value = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
                    break;

                case RSA_PSS_SALTLEN_AUTO:
                    value = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
                    break;

                default:
                    ERROR("Unknown salt length");
                    return 0;
            }

            if (OSSL_PARAM_set_utf8_string(param, value) != 1) {
                ERROR("OSSL_PARAM_set_utf8_string failed");
                return 0;
            }
        } else {
            ERROR("Unexpected param type");
            return 0;
        }
    }

    return 1;
}

static int signature_set_ctx_params(
        void* ctx,
        const OSSL_PARAM params[]) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    if (params == NULL)
        return 1;

    sa_provider_signature_context* signature_context = ctx;
    const OSSL_PARAM* param;

    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (param != NULL) {
        char md_name[MAX_NAME_SIZE];
        char* p_md_name = md_name;
        if (!OSSL_PARAM_get_utf8_string(param, &p_md_name, MAX_NAME_SIZE))
            return 0;

        char md_properties[MAX_PROPQUERY_SIZE];
        char* p_md_properties = md_properties;
        param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
        if (param != NULL) {
            if (!OSSL_PARAM_get_utf8_string(param, &p_md_properties, MAX_PROPQUERY_SIZE))
                return 0;
        } else {
            md_properties[0] = 0;
        }

        EVP_MD* evp_md = EVP_MD_fetch(signature_context->provider_context->lib_ctx, md_name, md_properties);
        if (evp_md == NULL) {
            ERROR("evp_md not found");
            return 0;
        }

        EVP_MD_free(signature_context->evp_md);
        signature_context->evp_md = evp_md;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (param != NULL) {
        switch (param->data_type) {
            case OSSL_PARAM_INTEGER:
                if (!OSSL_PARAM_get_int(param, &signature_context->padding_mode)) {
                    ERROR("Unable to get pad_mode");
                    return 0;
                }

                if (signature_context->padding_mode != RSA_PKCS1_PADDING &&
                        signature_context->padding_mode != RSA_PKCS1_PSS_PADDING) {
                    ERROR("Unsupported padding mode");
                    return 0;
                }

                break;

            case OSSL_PARAM_UTF8_STRING:
                if (param->data == NULL) {
                    ERROR("NULL param data");
                    return 0;
                }

                if (strcmp(param->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0) {
                    signature_context->padding_mode = RSA_PKCS1_PADDING;
                } else if (strcmp(param->data, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0) {
                    signature_context->padding_mode = RSA_PKCS1_PSS_PADDING;
                } else {
                    ERROR("Unsupported padding mode");
                    return 0;
                }

                break;
            default:
                ERROR("Unknown param type");
                return 0;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (param != NULL) {
        char md_name[MAX_NAME_SIZE];
        char* p_md_name = md_name;
        if (!OSSL_PARAM_get_utf8_string(param, &p_md_name, MAX_NAME_SIZE))
            return 0;

        char md_properties[MAX_PROPQUERY_SIZE];
        char* p_md_properties = md_properties;
        param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);
        if (param != NULL) {
            if (!OSSL_PARAM_get_utf8_string(param, &p_md_properties, MAX_PROPQUERY_SIZE))
                return 0;
        } else {
            md_properties[0] = 0;
        }

        EVP_MD* evp_md = EVP_MD_fetch(signature_context->provider_context->lib_ctx, md_name, md_properties);
        if (evp_md == NULL) {
            ERROR("evp_md not found");
            return 0;
        }

        EVP_MD_free(signature_context->mgf1_md);
        signature_context->mgf1_md = evp_md;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (param != NULL) {
        switch (param->data_type) {
            case OSSL_PARAM_INTEGER:
                if (!OSSL_PARAM_get_int(param, &signature_context->pss_salt_length))
                    return 0;
                break;

            case OSSL_PARAM_UTF8_STRING:
                if (strcmp(param->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                    signature_context->pss_salt_length = RSA_PSS_SALTLEN_DIGEST;
                else if (strcmp(param->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                    signature_context->pss_salt_length = RSA_PSS_SALTLEN_MAX;
                else if (strcmp(param->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                    signature_context->pss_salt_length = RSA_PSS_SALTLEN_AUTO;
                else
                    signature_context->pss_salt_length = atoi(param->data); // NOLINT
                break;

            default:
                return 0;
        }
    }

    return 1;
}

ossl_unused static const OSSL_PARAM* signature_rsa_gettable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
            OSSL_PARAM_END};
    return params;
}

ossl_unused static const OSSL_PARAM* signature_ecdsa_gettable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
            OSSL_PARAM_END};
    return params;
}

static const OSSL_PARAM* signature_eddsa_gettable_ctx_params(
        ossl_unused void* ctx,
        ossl_unused void* provctx) {

    static const OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
            OSSL_PARAM_END};

    return params;
}

static int signature_get_ctx_md_params(
        void* ctx,
        OSSL_PARAM params[]) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    return EVP_MD_CTX_get_params(signature_context->evp_md_ctx, params);
}

static const OSSL_PARAM* signature_gettable_ctx_md_params(void* ctx) {
    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->evp_md == NULL) {
        ERROR("NULL evp_md");
        return 0;
    }

    return EVP_MD_gettable_ctx_params(signature_context->evp_md);
}

static int signature_set_ctx_md_params(
        void* ctx,
        const OSSL_PARAM params[]) {

    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    return EVP_MD_CTX_set_params(signature_context->evp_md_ctx, params);
}

static const OSSL_PARAM* signature_settable_ctx_md_params(void* ctx) {
    if (ctx == NULL) {
        ERROR("NULL ctx");
        return 0;
    }

    sa_provider_signature_context* signature_context = ctx;
    if (signature_context->evp_md == NULL) {
        ERROR("NULL evp_md");
        return 0;
    }

    return EVP_MD_settable_ctx_params(signature_context->evp_md);
}

#define SA_PROVIDER_SIGNATURE_FUNCTIONS(algorithm) \
    static const OSSL_DISPATCH sa_provider_##algorithm##_signature_functions[] = { \
            {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) signature_newctx}, \
            {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) signature_freectx}, \
            {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) signature_dupctx}, \
            {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) signature_sign_init}, \
            {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) signature_sign}, \
            {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) signature_verify_init}, \
            {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) signature_verify}, \
            {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) signature_digest_sign_init}, \
            {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) signature_digest_sign_update}, \
            {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) signature_digest_sign_final}, \
            {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) signature_digest_verify_init}, \
            {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) signature_digest_verify_update}, \
            {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) signature_digest_verify_final}, \
            {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void)) signature_get_ctx_params}, \
            {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void)) signature_set_ctx_params}, \
            {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void)) signature_##algorithm##_gettable_ctx_params}, \
            {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void)) signature_##algorithm##_gettable_ctx_params}, \
            {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void)) signature_get_ctx_md_params}, \
            {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void)) signature_set_ctx_md_params}, \
            {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void)) signature_gettable_ctx_md_params}, \
            {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void)) signature_settable_ctx_md_params}, \
            {0, NULL}}
SA_PROVIDER_SIGNATURE_FUNCTIONS(rsa);
SA_PROVIDER_SIGNATURE_FUNCTIONS(ecdsa);

static const OSSL_DISPATCH sa_provider_eddsa_signature_functions[] = {
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) signature_newctx},
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) signature_freectx},
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) signature_dupctx},
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) signature_digest_sign_init},
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void)) signature_digest_sign},
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) signature_digest_verify_init},
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void)) signature_digest_verify},
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void)) signature_get_ctx_params},
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void)) signature_eddsa_gettable_ctx_params},
        {0, NULL}};

ossl_unused const OSSL_ALGORITHM sa_provider_signatures[] = {
        {"RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=secapi3", sa_provider_rsa_signature_functions, ""},
        {"ECDSA", "provider=secapi3", sa_provider_ecdsa_signature_functions, ""},
        {"ED25519:1.3.101.112", "provider=secapi3", sa_provider_eddsa_signature_functions, ""},
        {"ED448:1.3.101.113", "provider=secapi3", sa_provider_eddsa_signature_functions, ""},
        {NULL, NULL, NULL, NULL}};

#endif
