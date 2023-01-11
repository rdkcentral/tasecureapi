/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#include "common.h"
#include "log.h"
#include "sa.h"
#include "sa_engine_internal.h"
#include "sa_rights.h"
#include <openssl/engine.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000
#define MAX_GROUP_NAME 24
#include <openssl/core_names.h>
#else
#include <memory.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define EVP_PKEY_get0_engine(evp_pkey) evp_pkey->engine
#endif

#define RSA_DEFAULT_PADDING_MODE RSA_PKCS1_PADDING
#define RSA_DEFAULT_PSS_SALT_LENGTH RSA_PSS_SALTLEN_AUTO
#define OPENSSL_OPERATION_NOT_SUPPORTED (-2)

typedef struct {
    int padding_mode;
    int pss_salt_length;
    EVP_MD_CTX* evp_md_ctx;
    const EVP_MD* evp_md;
    const EVP_MD* mgf1_md;
    void* oaep_label;
    int oaep_label_length;
    // Mac key signing
    sa_crypto_mac_context mac_context;
} pkey_app_data;

static int pkey_nids[] = {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        EVP_PKEY_ED25519,
        EVP_PKEY_X25519,
        EVP_PKEY_ED448,
        EVP_PKEY_X448,
#endif
        EVP_PKEY_SYM,
        EVP_PKEY_EC,
        EVP_PKEY_RSA,
        EVP_PKEY_DH};

static int pkey_nids_num = (sizeof(pkey_nids) / sizeof(pkey_nids[0]));
#if OPENSSL_VERSION_NUMBER >= 0x10100000
static EVP_PKEY_METHOD* ed25519_pkey_method = NULL;
static EVP_PKEY_METHOD* x25519_pkey_method = NULL;
static EVP_PKEY_METHOD* ed448_pkey_method = NULL;
static EVP_PKEY_METHOD* x448_pkey_method = NULL;
#endif
static EVP_PKEY_METHOD* sym_pkey_method = NULL;
static EVP_PKEY_METHOD* ec_key_pkey_method = NULL;
static EVP_PKEY_METHOD* rsa_pkey_method = NULL;
static EVP_PKEY_METHOD* dh_pkey_method = NULL;

static sa_digest_algorithm get_digest_algorithm(const EVP_MD* evp_md) {
    if (evp_md != NULL) {
        switch (EVP_MD_nid(evp_md)) {
            case NID_sha1:
                return SA_DIGEST_ALGORITHM_SHA1;

            case NID_sha256:
                return SA_DIGEST_ALGORITHM_SHA256;

            case NID_sha384:
                return SA_DIGEST_ALGORITHM_SHA384;

            case NID_sha512:
                return SA_DIGEST_ALGORITHM_SHA512;
        }
    }

    return UINT32_MAX;
}

static int pkey_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    pkey_app_data* app_data = OPENSSL_malloc(sizeof(pkey_app_data));
    if (app_data == NULL) {
        ERROR("malloc failed");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey != NULL) {
        int key_type = EVP_PKEY_base_id(evp_pkey);
        if (key_type == EVP_PKEY_RSA) {
            app_data->padding_mode = RSA_DEFAULT_PADDING_MODE;
            app_data->pss_salt_length = RSA_DEFAULT_PSS_SALT_LENGTH;
            app_data->evp_md = EVP_sha1();
            app_data->mgf1_md = EVP_sha1();
            app_data->oaep_label = NULL;
            app_data->oaep_label_length = 0;
        } else {
            app_data->padding_mode = 0;
            app_data->pss_salt_length = 0;
            app_data->evp_md = NULL;
            app_data->mgf1_md = NULL;
            app_data->oaep_label = NULL;
            app_data->oaep_label_length = 0;
        }
    } else {
        app_data->padding_mode = 0;
        app_data->pss_salt_length = 0;
        app_data->evp_md = NULL;
        app_data->mgf1_md = NULL;
        app_data->oaep_label = NULL;
        app_data->oaep_label_length = 0;
    }

    app_data->evp_md_ctx = NULL;
    app_data->mac_context = 0;
    EVP_PKEY_CTX_set_app_data(evp_pkey_ctx, app_data);
    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
static int pkey_copy(
        EVP_PKEY_CTX* dst_evp_pkey_ctx,
        const EVP_PKEY_CTX* src_evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data((EVP_PKEY_CTX*) src_evp_pkey_ctx);
#else
static int pkey_copy(
        EVP_PKEY_CTX* dst_evp_pkey_ctx,
        EVP_PKEY_CTX* src_evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(src_evp_pkey_ctx);
#endif
    pkey_app_data* new_app_data = OPENSSL_malloc(sizeof(pkey_app_data));
    if (new_app_data == NULL) {
        ERROR("malloc failed");
        return 0;
    }

    new_app_data->padding_mode = app_data->padding_mode;
    new_app_data->pss_salt_length = app_data->pss_salt_length;
    new_app_data->evp_md_ctx = app_data->evp_md_ctx;
    new_app_data->evp_md = app_data->evp_md;
    new_app_data->mgf1_md = app_data->mgf1_md;
    if (app_data->oaep_label_length > 0) {
        new_app_data->oaep_label = OPENSSL_malloc(app_data->oaep_label_length);
        if (new_app_data->oaep_label == NULL) {
            ERROR("OPENSSL_malloc failed");
            return 0;
        }

        memcpy(new_app_data->oaep_label, app_data->oaep_label, app_data->oaep_label_length);
        new_app_data->oaep_label_length = app_data->oaep_label_length;
    } else {
        new_app_data->oaep_label = NULL;
        new_app_data->oaep_label_length = 0;
    }

    new_app_data->mac_context = app_data->mac_context;
    EVP_PKEY_CTX_set_app_data(dst_evp_pkey_ctx, new_app_data);
    return 1;
}

static void pkey_cleanup(EVP_PKEY_CTX* evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data->oaep_label != NULL)
        OPENSSL_free(app_data->oaep_label);

    if (app_data != NULL)
        OPENSSL_free(app_data);
}

// RSA and EC signing and verification
static int pkey_signverify_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int type = EVP_PKEY_base_id(evp_pkey);
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_EC) {
        ERROR("Invalid key type for sign or verify");
        return 0;
    }

    return 1;
}

// RSA and EC signing
static int pkey_sign(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* signature,
        size_t* signature_length,
        const unsigned char* in,
        size_t in_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return 0;
    }

    if (in == NULL)
        in_length = 0;

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    if (data == NULL) {
        ERROR("EVP_PKEY_get0 failed");
        return 0;
    }

    sa_signature_algorithm signature_algorithm;
    sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
    sa_sign_parameters_rsa_pss parameters_rsa_pss;
    sa_sign_parameters_ecdsa parameters_ecdsa;
    void* parameters = NULL;
    switch (data->header.type) {
        case SA_KEY_TYPE_RSA:
            if (app_data->padding_mode == RSA_PKCS1_PADDING) {
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15;
                parameters_rsa_pkcs1v15.digest_algorithm = get_digest_algorithm(app_data->evp_md);
                if (parameters_rsa_pkcs1v15.digest_algorithm == UINT32_MAX) {
                    ERROR("digest_algorithm unknown");
                    return 0;
                }

                parameters_rsa_pkcs1v15.precomputed_digest = true;
                parameters = &parameters_rsa_pkcs1v15;
            } else if (app_data->padding_mode == RSA_PKCS1_PSS_PADDING) {
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PSS;
                parameters_rsa_pss.digest_algorithm = get_digest_algorithm(app_data->evp_md);
                parameters_rsa_pss.mgf1_digest_algorithm = get_digest_algorithm(app_data->mgf1_md);
                if (parameters_rsa_pss.digest_algorithm == UINT32_MAX) {
                    ERROR("digest_algorithm unknown");
                    return 0;
                }

                if (parameters_rsa_pss.mgf1_digest_algorithm == UINT32_MAX) {
                    ERROR("digest_algorithm unknown");
                    return 0;
                }

                parameters_rsa_pss.precomputed_digest = true;
                int salt_length;
                if (app_data->pss_salt_length == RSA_PSS_SALTLEN_DIGEST) {
                    salt_length = EVP_MD_size(app_data->evp_md);
                } else if (app_data->pss_salt_length == RSA_PSS_SALTLEN_AUTO ||
                           app_data->pss_salt_length == RSA_PSS_SALTLEN_MAX) {
                    salt_length = EVP_PKEY_size(evp_pkey) - EVP_MD_size(app_data->evp_md) - 2;
                    if ((EVP_PKEY_bits(evp_pkey) & 0x7) == 1)
                        salt_length--;

                    if (salt_length < 0) {
                        ERROR("salt_length unknown");
                        return 0;
                    }
                } else
                    salt_length = app_data->pss_salt_length;

                parameters_rsa_pss.salt_length = salt_length;
                parameters = &parameters_rsa_pss;
            } else {
                ERROR("Invalid padding mode");
                return 0;
            }

            break;

        case SA_KEY_TYPE_EC:
            if (!is_pcurve(data->header.type_parameters.curve)) {
                ERROR("Invalid EC curve");
                return 0;
            }

            signature_algorithm = SA_SIGNATURE_ALGORITHM_ECDSA;
            parameters_ecdsa.digest_algorithm = get_digest_algorithm(app_data->evp_md);
            if (parameters_ecdsa.digest_algorithm == UINT32_MAX) {
                ERROR("digest_algorithm unknown");
                return 0;
            }

            parameters_ecdsa.precomputed_digest = true;
            parameters = &parameters_ecdsa;
            break;

        default:
            ERROR("Invalid key type");
            return 0;
    }

    uint8_t local_signature[MAX_SIGNATURE_LENGTH];
    size_t local_signature_length = MAX_SIGNATURE_LENGTH;
    sa_status status = sa_crypto_sign(signature != NULL ? local_signature : NULL, &local_signature_length,
            signature_algorithm, data->private_key, in, in_length, parameters);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_sign operation not supported");
        return OPENSSL_OPERATION_NOT_SUPPORTED;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
    }

    if (data->header.type == SA_KEY_TYPE_EC) {
        // Take the SecApi 3 signature and encode it like OpenSSL would so that it looks like it came from
        // OpenSSL
        if (signature != NULL) {
            if (!ec_encode_signature(signature, signature_length, local_signature, local_signature_length)) {
                ERROR("ec_encode_signature failed");
                return 0;
            }
        } else {
            // Add the most number of bytes that can be added by ASN.1 encoding (9). It could be as few as 6.
            *signature_length = local_signature_length + 9;
        }
    } else {
        if (signature != NULL)
            memcpy(signature, local_signature, local_signature_length);

        *signature_length = local_signature_length;
    }

    return 1;
}

// RSA and EC verification
static int pkey_verify(
        EVP_PKEY_CTX* evp_pkey_ctx,
        const unsigned char* signature,
        size_t signature_length,
        const unsigned char* in,
        size_t in_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (signature == NULL) {
        ERROR("NULL signature");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int result = 0;
    EVP_PKEY* verify_pkey = NULL;
    EVP_PKEY_CTX* verify_pkey_ctx = NULL;
    do {

        const pkey_data* data = sa_get_pkey_data(evp_pkey);
        if (data == NULL) {
            ERROR("EVP_PKEY_get0 failed");
            return 0;
        }

        verify_pkey = sa_get_public_key(data->private_key);
        if (verify_pkey == NULL) {
            ERROR("NULL verify_pkey");
            break;
        }

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
            if (EVP_PKEY_CTX_set_rsa_padding(verify_pkey_ctx, app_data->padding_mode) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (app_data->padding_mode == RSA_PKCS1_PSS_PADDING) {
                if (EVP_PKEY_CTX_set_rsa_mgf1_md(verify_pkey_ctx, app_data->mgf1_md) != 1) {
                    ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
                    break;
                }

                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_pkey_ctx, app_data->pss_salt_length) != 1) {
                    ERROR("EVP_PKEY_CTX_set_rsa_pss_saltlen failed");
                    break;
                }
            }
        }

        if (EVP_PKEY_CTX_set_signature_md(verify_pkey_ctx, app_data->evp_md) != 1) {
            ERROR("EVP_PKEY_CTX_set_signature_md failed");
            break;
        }

        if (EVP_PKEY_verify(verify_pkey_ctx, signature, signature_length, in, in_length) != 1) {
            ERROR("EVP_PKEY_verify");
            break;
        }

        result = 1;
    } while (false);

    EVP_PKEY_CTX_free(verify_pkey_ctx);
    EVP_PKEY_free(verify_pkey);
    return result;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
// ED25519 and ED448 signing
static int pkey_digestsign(
        EVP_MD_CTX* evp_md_ctx,
        unsigned char* signature,
        size_t* signature_length,
        const unsigned char* in,
        size_t in_length) {

    if (evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    EVP_PKEY_CTX* evp_pkey_ctx = EVP_MD_CTX_pkey_ctx(evp_md_ctx);
    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    if (data == NULL) {
        ERROR("sa_get_pkey_data failed");
        return 0;
    }

    if (data->header.type != SA_KEY_TYPE_EC &&
            !(data->header.type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                    data->header.type_parameters.curve == SA_ELLIPTIC_CURVE_ED448)) {
        ERROR("Invalid key type");
        return 0;
    }

    sa_signature_algorithm signature_algorithm = SA_SIGNATURE_ALGORITHM_EDDSA;
    sa_status status = sa_crypto_sign(signature, signature_length, signature_algorithm, data->private_key, in,
            in_length, NULL);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_sign operation not supported");
        return OPENSSL_OPERATION_NOT_SUPPORTED;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
    }

    return 1;
}

// ED25519 and ED448 verification
static int pkey_digestverify(
        EVP_MD_CTX* evp_md_ctx,
        const unsigned char* signature,
        size_t signature_length,
        const unsigned char* in,
        size_t in_length) {

    if (evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    if (signature == NULL) {
        ERROR("NULL signature");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    EVP_PKEY_CTX* evp_pkey_ctx = EVP_MD_CTX_pkey_ctx(evp_md_ctx);
    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int result = 0;
    EVP_PKEY* verify_pkey = NULL;
    EVP_MD_CTX* verify_md_ctx = NULL;
    do {

        const pkey_data* data = sa_get_pkey_data(evp_pkey);
        if (data == NULL) {
            ERROR("sa_get_pkey_data failed");
            return 0;
        }

        verify_pkey = sa_get_public_key(data->private_key);
        if (verify_pkey == NULL) {
            ERROR("NULL verify_pkey");
            break;
        }

        verify_md_ctx = EVP_MD_CTX_new();
        if (verify_md_ctx == NULL) {
            ERROR("NULL verify_md_ctx");
            break;
        }

        if (EVP_DigestVerifyInit(verify_md_ctx, NULL, NULL, NULL, verify_pkey) != 1) {
            ERROR("EVP_DigestVerifyinit failed");
            break;
        }

        if (EVP_DigestVerify(verify_md_ctx, signature, signature_length, in, in_length) != 1) {
            ERROR("EVP_DigestVerify");
            break;
        }

        result = 1;
    } while (false);

    EVP_MD_CTX_free(verify_md_ctx);
    EVP_PKEY_free(verify_pkey);
    return result;
}
#endif

static int pkey_mac_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    if (data == NULL) {
        ERROR("sa_get_pkey_data failed");
        return 0;
    }

    sa_mac_algorithm mac_algorithm;
    sa_mac_parameters_hmac parameters_hmac;
    void* parameters;
    if (data->header.type == SA_KEY_TYPE_SYMMETRIC) {
        sa_digest_algorithm digest_algorithm = get_digest_algorithm(app_data->evp_md);
        if (digest_algorithm == UINT32_MAX) {
            mac_algorithm = SA_MAC_ALGORITHM_CMAC;
            parameters = NULL;
        } else {
            mac_algorithm = SA_MAC_ALGORITHM_HMAC;
            parameters_hmac.digest_algorithm = digest_algorithm;
            parameters = &parameters_hmac;
        }
    } else {
        ERROR("Unkown MAC algorithm");
        return 0;
    }

    sa_status status = sa_crypto_mac_init(&app_data->mac_context, mac_algorithm, data->private_key, parameters);
    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_mac_init failed");
        return 0;
    }

    return 1;
}

static int pkey_mac_update(
        EVP_MD_CTX* evp_md_ctx,
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY_CTX* evp_pkey_ctx = EVP_MD_CTX_pkey_ctx(evp_md_ctx);
#else
    EVP_PKEY_CTX* evp_pkey_ctx = evp_md_ctx->pctx;
#endif
    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    sa_status status = sa_crypto_mac_process(app_data->mac_context, in, in_length);
    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_mac_process failed");
        return 0;
    }

    return 1;
}

// HMAC and CMAC signing
static int pkey_signctx_init(
        EVP_PKEY_CTX* evp_pkey_ctx,
        EVP_MD_CTX* evp_md_ctx) {

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    app_data->evp_md_ctx = evp_md_ctx;
    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    if (data == NULL) {
        ERROR("sa_get_pkey_data failed");
        return 0;
    }

    if (data->header.type != SA_KEY_TYPE_SYMMETRIC) {
        ERROR("Invalid key type for mac sign");
        return 0;
    }

    EVP_MD_CTX_set_flags(evp_md_ctx, EVP_MD_CTX_FLAG_NO_INIT);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_MD_CTX_set_update_fn(evp_md_ctx, pkey_mac_update);
#else
    evp_md_ctx->update = pkey_mac_update;
#endif
    return 1;
}

// HMAC and CMAC signing
static int pkey_signctx(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* signature,
        size_t* signature_length,
        EVP_MD_CTX* evp_md_ctx) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    sa_status status = sa_crypto_mac_compute(signature, signature_length, app_data->mac_context);
    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_mac_compute failed");
        return 0;
    }

    return 1;
}

// RSA encrypt/decrypt
static int pkey_encryptdecrypt_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int type = EVP_PKEY_base_id(evp_pkey);
    if (type != EVP_PKEY_RSA) {
        ERROR("Invalid key type for encrypt or decrypt");
        return 0;
    }

    return 1;
}

// RSA encrypt
static int pkey_encrypt(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* out,
        size_t* out_length,
        const unsigned char* in,
        size_t in_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int result = 0;
    EVP_PKEY* encrypt_pkey = NULL;
    EVP_PKEY_CTX* encrypt_pkey_ctx = NULL;
    do {
        const pkey_data* data = sa_get_pkey_data(evp_pkey);
        if (data == NULL) {
            ERROR("sa_get_pkey_data failed");
            return 0;
        }

        encrypt_pkey = sa_get_public_key(data->private_key);
        if (encrypt_pkey == NULL) {
            ERROR("sa_get_public_key failed");
            break;
        }

        encrypt_pkey_ctx = EVP_PKEY_CTX_new(encrypt_pkey, NULL);
        if (encrypt_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new failed");
            break;
        }

        if (EVP_PKEY_encrypt_init(encrypt_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_encrypt_init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(encrypt_pkey_ctx, app_data->padding_mode) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
            break;
        }

        if (app_data->padding_mode == RSA_PKCS1_OAEP_PADDING) {
            if (EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_pkey_ctx, app_data->evp_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_oaep_md failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(encrypt_pkey_ctx, app_data->mgf1_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
                break;
            }

            if (app_data->oaep_label != NULL && app_data->oaep_label_length > 0) {
                uint8_t* new_label = OPENSSL_malloc(app_data->oaep_label_length);
                if (new_label == NULL) {
                    ERROR("OPENSSL_malloc failed");
                    break;
                }

                memcpy(new_label, app_data->oaep_label, app_data->oaep_label_length);
                if (EVP_PKEY_CTX_set0_rsa_oaep_label(encrypt_pkey_ctx, new_label, app_data->oaep_label_length) != 1) {
                    OPENSSL_free(new_label);
                    ERROR("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
                    break;
                }
            }
        }

        if (EVP_PKEY_encrypt(encrypt_pkey_ctx, out, out_length, in, in_length) != 1) {
            ERROR("EVP_PKEY_encrypt failed");
            break;
        }

        result = 1;
    } while (false);

    EVP_PKEY_CTX_free(encrypt_pkey_ctx);
    EVP_PKEY_free(encrypt_pkey);
    return result;
}

// RSA decrypt
static int pkey_decrypt(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* out, // NOLINT
        size_t* out_length,
        const unsigned char* in,
        size_t in_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    if (data == NULL) {
        ERROR("sa_get_pkey_data failed");
        return 0;
    }

    sa_cipher_algorithm cipher_algorithm;
    sa_cipher_parameters_rsa_oaep parameters_rsa_oaep;
    void* parameters = NULL;
    if (app_data->padding_mode == RSA_PKCS1_OAEP_PADDING) {
        cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_OAEP;
        parameters_rsa_oaep.digest_algorithm = get_digest_algorithm(app_data->evp_md);
        parameters_rsa_oaep.mgf1_digest_algorithm = get_digest_algorithm(app_data->mgf1_md);
        parameters_rsa_oaep.label = app_data->oaep_label;
        parameters_rsa_oaep.label_length = app_data->oaep_label_length;
        parameters = &parameters_rsa_oaep;
    } else {
        cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_PKCS1V15;
    }

    sa_crypto_cipher_context cipher_context;
    sa_status status = sa_crypto_cipher_init(&cipher_context, cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
            data->private_key, parameters);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_cipher_init operation not supported");
        return OPENSSL_OPERATION_NOT_SUPPORTED;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_cipher_init failed");
        return 0;
    }

    sa_buffer out_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {out, *out_length, 0}}};
    sa_buffer in_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {(void*) in, in_length, 0}}};
    size_t bytes_to_process = in_length;
    status = sa_crypto_cipher_process(out == NULL ? NULL : &out_buffer, cipher_context, &in_buffer, &bytes_to_process);
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("sa_crypto_cipher_process operation not supported");
        return OPENSSL_NOT_SUPPORTED;
    }

    if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_cipher_process failed");
        return 0;
    }

    *out_length = bytes_to_process;
    return 1;
}

// DH and ECDH derive
static int pkey_pderive_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int type = EVP_PKEY_base_id(evp_pkey);
    if (type != EVP_PKEY_DH && type != EVP_PKEY_EC
#if OPENSSL_VERSION_NUMBER >= 0x10100000
            && type != EVP_PKEY_X25519 && type != EVP_PKEY_X448
#endif
    ) {
        ERROR("Invalid key type for encrypt or decrypt");
        return 0;
    }

    return 1;
}

// DH and ECDH derive
static int pkey_pderive(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* shared_secret_key,
        size_t* shared_secret_key_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    *shared_secret_key_length = sizeof(sa_key);
    if (shared_secret_key == NULL)
        return 1;

    if (shared_secret_key_length == NULL) {
        ERROR("NULL shared_secret_key_length");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* peer_key = EVP_PKEY_CTX_get0_peerkey(evp_pkey_ctx);
    if (peer_key == NULL) {
        ERROR("EVP_PKEY_CTX_get0_peerkey failed");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    int type = EVP_PKEY_base_id(evp_pkey);
    int other_public_type = EVP_PKEY_base_id(peer_key);
    if (other_public_type != type) {
        ERROR("Invalid peer key type");
        return 0;
    }

    int result = 0;
    sa_key_exchange_algorithm key_exchange_algorithm;
    uint8_t* other_public = NULL;
    size_t other_public_length;
    do {
        if (type == EVP_PKEY_DH) {
            key_exchange_algorithm = SA_KEY_EXCHANGE_ALGORITHM_DH;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        } else if (type == EVP_PKEY_EC || type == EVP_PKEY_X25519 || type == EVP_PKEY_X448) {
#else
        } else if (type == EVP_PKEY_EC) {
#endif
            key_exchange_algorithm = SA_KEY_EXCHANGE_ALGORITHM_ECDH;
        } else {
            ERROR("Invalid key type");
            break;
        }

        other_public_length = i2d_PUBKEY(peer_key, NULL);
        if (other_public_length <= 0) {
            ERROR("Invalid other_public_length");
            break;
        }

        other_public = OPENSSL_malloc(other_public_length);
        if (other_public == NULL) {
            ERROR("OPENSSL_malloc failed");
            break;
        }

        uint8_t* p_pther_public = other_public;
        other_public_length = i2d_PUBKEY(peer_key, &p_pther_public);
        if (other_public_length <= 0) {
            ERROR("Invalid other_public_length");
            break;
        }

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        sa_status status = sa_key_exchange((void*) shared_secret_key, &rights, key_exchange_algorithm,
                data->private_key, other_public, other_public_length, NULL);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
            ERROR("sa_key_exchange operation not supported");
            result = OPENSSL_NOT_SUPPORTED;
            break;
        }

        if (status != SA_STATUS_OK) {
            ERROR("sa_key_exchange failed");
            break;
        }

        result = 1;
    } while (false);

    OPENSSL_free(other_public);
    return result;
}

static int pkey_ctrl(
        EVP_PKEY_CTX* evp_pkey_ctx,
        int command,
        int p1,
        void* p2) {

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("EVP_PKEY_CTX_get0_pkey failed");
        return 0;
    }

    int type = EVP_PKEY_base_id(evp_pkey);
    const pkey_data* data = sa_get_pkey_data(evp_pkey);
    if (data == NULL) {
        ERROR("sa_get_pkey_data failed");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    switch (command) {
        case EVP_PKEY_CTRL_DIGESTINIT:
            if (type == EVP_PKEY_SYM)
                return pkey_mac_init(evp_pkey_ctx);

            break;

        case EVP_PKEY_CTRL_MD:
            if (type == EVP_PKEY_SYM) {
                if (p2 != NULL)
                    app_data->evp_md = p2;
                else
                    app_data->evp_md = EVP_md_null();

                if (EVP_DigestInit_ex(app_data->evp_md_ctx, app_data->evp_md, EVP_PKEY_get0_engine(evp_pkey)) != 1) {
                    ERROR("EVP_DigestInit_ex failed");
                    return 0;
                }
            } else {
                app_data->evp_md = p2;
            }

            break;

        case EVP_PKEY_CTRL_GET_MD:
            if (p2 == NULL) {
                ERROR("NULL p2");
                return 0;
            }

            *(const EVP_MD**) p2 = app_data->evp_md;
            break;

        case EVP_PKEY_CTRL_RSA_PADDING:
            app_data->padding_mode = p1;
            break;

        case EVP_PKEY_CTRL_GET_RSA_PADDING:
            if (p2 == NULL) {
                ERROR("NULL p2");
                return 0;
            }

            *((int*) p2) = app_data->padding_mode;
            break;

        case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
            if (app_data->padding_mode != RSA_PKCS1_PSS_PADDING) {
                ERROR("Invalid padding mode for EVP_PKEY_CTRL_RSA_PSS_SALTLEN");
                return 0;
            }

            app_data->pss_salt_length = p1;
            break;

        case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
            if (app_data->padding_mode != RSA_PKCS1_PSS_PADDING) {
                ERROR("Invalid padding mode for EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN");
                return 0;
            }

            if (p2 == NULL) {
                ERROR("NULL p2");
                return 0;
            }

            *((int*) p2) = app_data->pss_salt_length;
            break;

        case EVP_PKEY_CTRL_PKCS7_SIGN: {
            // Just checks if valid key type for PKCS7 signing.
            if (type != EVP_PKEY_RSA && type != EVP_PKEY_EC) {
                ERROR("Invalid key_type for PKCS7");
                return 0;
            }

            break;
        }

        case EVP_PKEY_CTRL_PEER_KEY: {
            if (type != EVP_PKEY_DH && type != EVP_PKEY_EC
#if OPENSSL_VERSION_NUMBER >= 0x10100000
                    && type != EVP_PKEY_X25519 && type != EVP_PKEY_X448
#endif
            ) {
                ERROR("Invalid key_type for PKCS7");
                return 0;
            }

            break;
        }
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        case EVP_PKEY_CTRL_DH_PAD: {
            if (type != EVP_PKEY_DH) {
                ERROR("Invalid key_type for PKCS7");
                return 0;
            }

            // We only support DH padding.
            if (p1 == 0) {
                ERROR("Unsupported DH padding");
                return 0;
            }

            break;
        }
#endif
        case EVP_PKEY_CTRL_CIPHER:
            if (p2 != EVP_aes_128_cbc() && p2 != EVP_aes_256_cbc()) {
                ERROR("Unsupported CMAC cipher");
                return 0;
            }

            break;

        case EVP_PKEY_CTRL_RSA_OAEP_MD:
            if (p2 == NULL) {
                ERROR("oaep_md is NULL");
                return 0;
            }

            app_data->evp_md = p2;
            break;

        case EVP_PKEY_CTRL_RSA_MGF1_MD:
            if (p2 == NULL) {
                ERROR("mgf1_md is NULL");
                return 0;
            }

            app_data->mgf1_md = p2;
            break;

        case EVP_PKEY_CTRL_RSA_OAEP_LABEL:
            if (p2 == NULL && p1 > 0) {
                ERROR("oaep_label is NULL");
                return 0;
            }

            // Take ownership of label.
            app_data->oaep_label = p2;
            app_data->oaep_label_length = p1;
            break;

        default:
            return OPENSSL_NOT_SUPPORTED;
    }

    return 1;
}

static EVP_PKEY_METHOD* get_pkey_method(
        int nid,
        int flags) {
    EVP_PKEY_METHOD* evp_pkey_method = EVP_PKEY_meth_new(nid, flags);
    if (evp_pkey_method != NULL) {
        EVP_PKEY_meth_set_init(evp_pkey_method, pkey_init);
        EVP_PKEY_meth_set_copy(evp_pkey_method, pkey_copy);
        EVP_PKEY_meth_set_cleanup(evp_pkey_method, pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(evp_pkey_method, pkey_ctrl, NULL);
    }

    return evp_pkey_method;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
// OpenSSL 3 doesn't set up a key read through d2i_PUBKEY correctly for use by an engine. Stream it out as a PublicKey
// and reread it to get the correct settings.
static EVP_PKEY* fixup_openssl3_key(EVP_PKEY* evp_pkey) {
    int type = EVP_PKEY_id(evp_pkey);
    EVP_PKEY* new_evp_pkey = NULL;
    uint8_t* public_key = NULL;
    EC_GROUP* ec_group = NULL;
    EC_POINT* ec_point = NULL;
    EC_KEY* ec_key = NULL;
    do {
        if (type == EVP_PKEY_DH) {
            // Don't fix a DH key.
            return evp_pkey;
        }

        if (type == EVP_PKEY_RSA) {
            int length = i2d_PublicKey(evp_pkey, NULL);
            if (length <= 0) {
                ERROR("i2d_PublicKey failed");
                break;
            }

            public_key = OPENSSL_malloc(length);
            if (public_key == NULL) {
                ERROR("OPENSSL_malloc failed");
                break;
            }

            uint8_t* p_public_key = public_key;
            length = i2d_PublicKey(evp_pkey, &p_public_key);
            if (length <= 0) {
                ERROR("i2d_PublicKey failed");
                break;
            }

            const uint8_t* p_public_key2 = public_key;
            new_evp_pkey = d2i_PublicKey(type, NULL, &p_public_key2, length);
            if (new_evp_pkey == NULL) {
                ERROR("d2i_PublicKey failed");
                break;
            }
        } else if (type == EVP_PKEY_EC) {
            char group_name[MAX_GROUP_NAME];
            size_t group_name_length = MAX_GROUP_NAME;
            if (EVP_PKEY_get_utf8_string_param(evp_pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name,
                        group_name_length, &group_name_length) != 1) {
                ERROR("EVP_PKEY_get_utf8_string_param failed");
                break;
            }

            size_t public_key_length = 0;
            if (EVP_PKEY_get_octet_string_param(evp_pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, public_key_length,
                        &public_key_length) != 1) {
                ERROR("EVP_PKEY_get_octet_string_param failed");
                break;
            }

            public_key = OPENSSL_malloc(public_key_length);
            if (public_key == NULL) {
                ERROR("OPENSSL_malloc failed");
                break;
            }

            if (EVP_PKEY_get_octet_string_param(evp_pkey, OSSL_PKEY_PARAM_PUB_KEY, public_key, public_key_length,
                        &public_key_length) != 1) {
                ERROR("EVP_PKEY_get_octet_string_param failed");
                break;
            }

            OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, group_name_length),
                    OSSL_PARAM_construct_end()};

            ec_group = EC_GROUP_new_from_params(params, NULL, NULL);
            if (ec_group == NULL) {
                ERROR("EC_GROUP_new_from_params failed");
                break;
            }

            ec_point = EC_POINT_new(ec_group);
            if (ec_point == NULL) {
                ERROR("EC_POINT_new failed");
                break;
            }

            if (EC_POINT_oct2point(ec_group, ec_point, public_key, public_key_length, NULL) != 1) {
                ERROR("EC_POINT_oct2point failed");
                break;
            }

            ec_key = EC_KEY_new();
            if (ec_key == NULL) {
                ERROR("EC_KEY_new failed");
                break;
            }

            if (EC_KEY_set_group(ec_key, ec_group) != 1) {
                ERROR("EC_KEY_set_group failed");
                break;
            }

            if (EC_KEY_set_public_key(ec_key, ec_point) != 1) {
                ERROR("EC_KEY_set_public_key failed");
                break;
            }

            new_evp_pkey = EVP_PKEY_new();
            if (new_evp_pkey == NULL) {
                ERROR("EVP_PKEY_new failed");
                break;
            }

            if (EVP_PKEY_set1_EC_KEY(new_evp_pkey, ec_key) != 1) {
                ERROR("EVP_PKEY_set1_EC_KEY failed");
                EVP_PKEY_free(evp_pkey);
                break;
            }
        } else if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448 || type == EVP_PKEY_X25519 ||
                   type == EVP_PKEY_X448) {
            size_t public_key_length = 0;
            if (EVP_PKEY_get_raw_public_key(evp_pkey, NULL, &public_key_length) != 1) {
                ERROR("EVP_PKEY_get_raw_public_key failed");
                break;
            }

            public_key = OPENSSL_malloc(public_key_length);
            if (public_key == NULL) {
                ERROR("OPENSSL_malloc failed");
                break;
            }

            if (EVP_PKEY_get_raw_public_key(evp_pkey, public_key, &public_key_length) != 1) {
                ERROR("EVP_PKEY_get_raw_public_key failed");
                break;
            }

            new_evp_pkey = EVP_PKEY_new_raw_public_key(type, NULL, public_key, public_key_length);
            if (new_evp_pkey == NULL) {
                ERROR("EVP_PKEY_new_raw_public_key failed");
                break;
            }

            break;
        } else {
            ERROR("Unknown key type");
            break;
        }
    } while (false);

    OPENSSL_free(public_key);
    EC_GROUP_free(ec_group);
    EC_POINT_free(ec_point);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_pkey);

    evp_pkey = new_evp_pkey;
    return evp_pkey;
}
#endif

EVP_PKEY* sa_load_engine_private_pkey(
        ENGINE* engine,
        const char* key_id,
        UI_METHOD* ui_method,
        void* callback_data) {

    EVP_PKEY* evp_pkey = NULL;
    do {
        pkey_data data;
        data.private_key = *((sa_key*) key_id);
        if (sa_key_header(&data.header, data.private_key) != SA_STATUS_OK) {
            ERROR("sa_key_header failed");
            break;
        }

        if (data.header.type != SA_KEY_TYPE_SYMMETRIC) {
            evp_pkey = sa_get_public_key(data.private_key);
            if (evp_pkey == NULL) {
                ERROR("sa_get_public_key failed");
                break;
            }

#if OPENSSL_VERSION_NUMBER >= 0x30000000
            evp_pkey = fixup_openssl3_key(evp_pkey);
#endif
        }
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        else {
            evp_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_SYM, engine, (unsigned char*) &data, sizeof(pkey_data));
            if (evp_pkey == NULL) {
                ERROR("EVP_PKEY_new_raw_private_key failed");
                break;
            }
        }
#endif

        if (sa_set_pkey_data(&evp_pkey, &data) != 1) {
            ERROR("sa_set_pkey_data failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        if (EVP_PKEY_set1_engine(evp_pkey, engine) != 1) {
            ERROR("EVP_PKEY_set1_engine failed");
            break;
        }
#else
        if (evp_pkey->engine != NULL)
            ENGINE_finish(evp_pkey->engine);

        evp_pkey->engine = engine;
        ENGINE_init(evp_pkey->engine);
#endif
    } while (false);

    return evp_pkey;
}

int sa_get_engine_pkey_methods(
        ENGINE* engine,
        EVP_PKEY_METHOD** method,
        const int** nids,
        int nid) {

    if (!method) {
        if (nids == NULL)
            return 0;

        *nids = pkey_nids;
        return pkey_nids_num;
    }

    if (mtx_lock(&engine_mutex) != 0) {
        ERROR("mtx_lock failed");
        return 0;
    }

    if (nid == EVP_PKEY_SYM) {
        if (sym_pkey_method == NULL) {
            sym_pkey_method = get_pkey_method(EVP_PKEY_SYM, EVP_PKEY_FLAG_AUTOARGLEN | EVP_PKEY_FLAG_SIGCTX_CUSTOM);
            EVP_PKEY_meth_set_signctx(sym_pkey_method, pkey_signctx_init, pkey_signctx);
        }

        *method = sym_pkey_method;
    } else if (nid == EVP_PKEY_EC) {
        if (ec_key_pkey_method == NULL) {
            ec_key_pkey_method = get_pkey_method(EVP_PKEY_EC, 0);
            EVP_PKEY_meth_set_sign(ec_key_pkey_method, pkey_signverify_init, pkey_sign);
            EVP_PKEY_meth_set_verify(ec_key_pkey_method, pkey_signverify_init, pkey_verify);
            EVP_PKEY_meth_set_derive(ec_key_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = ec_key_pkey_method;
    } else if (nid == EVP_PKEY_RSA) {
        if (rsa_pkey_method == NULL) {
            // Make OpenSSL think we are using an actual RSA key so that the call to RSA_pkey_ctx_ctrl passes.
            rsa_pkey_method = get_pkey_method(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
            EVP_PKEY_meth_set_sign(rsa_pkey_method, pkey_signverify_init, pkey_sign);
            EVP_PKEY_meth_set_verify(rsa_pkey_method, pkey_signverify_init, pkey_verify);
            EVP_PKEY_meth_set_encrypt(rsa_pkey_method, pkey_encryptdecrypt_init, pkey_encrypt);
            EVP_PKEY_meth_set_decrypt(rsa_pkey_method, pkey_encryptdecrypt_init, pkey_decrypt);
        }

        *method = rsa_pkey_method;
    } else if (nid == EVP_PKEY_DH) {
        if (dh_pkey_method == NULL) {
            dh_pkey_method = get_pkey_method(EVP_PKEY_DH, EVP_PKEY_FLAG_AUTOARGLEN);
            EVP_PKEY_meth_set_derive(dh_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = dh_pkey_method;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    } else if (nid == EVP_PKEY_ED25519) {
        if (ed25519_pkey_method == NULL) {
            ed25519_pkey_method = get_pkey_method(EVP_PKEY_ED25519,
                    EVP_PKEY_FLAG_AUTOARGLEN | EVP_PKEY_FLAG_SIGCTX_CUSTOM);
            EVP_PKEY_meth_set_digestsign(ed25519_pkey_method, pkey_digestsign);
            EVP_PKEY_meth_set_digestverify(ed25519_pkey_method, pkey_digestverify);
        }

        *method = ed25519_pkey_method;
    } else if (nid == EVP_PKEY_X25519) {
        if (x25519_pkey_method == NULL) {
            x25519_pkey_method = get_pkey_method(EVP_PKEY_X25519, EVP_PKEY_FLAG_AUTOARGLEN);
            EVP_PKEY_meth_set_derive(x25519_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = x25519_pkey_method;
    } else if (nid == EVP_PKEY_ED448) {
        if (ed448_pkey_method == NULL) {
            ed448_pkey_method = get_pkey_method(EVP_PKEY_ED448,
                    EVP_PKEY_FLAG_AUTOARGLEN | EVP_PKEY_FLAG_SIGCTX_CUSTOM);
            EVP_PKEY_meth_set_digestsign(ed448_pkey_method, pkey_digestsign);
            EVP_PKEY_meth_set_digestverify(ed448_pkey_method, pkey_digestverify);
        }

        *method = ed448_pkey_method;
    } else if (nid == EVP_PKEY_X448) {
        if (x448_pkey_method == NULL) {
            x448_pkey_method = get_pkey_method(EVP_PKEY_X448, EVP_PKEY_FLAG_AUTOARGLEN);
            EVP_PKEY_meth_set_derive(x448_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = x448_pkey_method;
#endif
    } else {
        *method = NULL;
    }

    mtx_unlock(&engine_mutex);
    return *method == NULL ? 0 : 1;
}
