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
#include "log.h"
#include "pkcs8.h"
#include "sa_public_key.h"
#include "sa_rights.h"
#include <memory.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

typedef struct {
    sa_provider_context* provider_context;
    int type;
    const char* name;
    int selection;
    size_t key_size;
    sa_type_parameters type_parameters;
} sa_provider_key_gen_context;

/*
 * Values here are derived from RFC 3526 which is
 * Copyright (C) The Internet Society (2003). All Rights Reserved.
 */
static const uint8_t MODP_2048_P[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
        0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
        0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
        0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
        0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF};

static const uint8_t MODP_2048_G[] = {
        0x02,
};

ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_rsa_new;
ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_ec_new;
ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_dh_new;
ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_x25519_new;
ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_x448_new;
ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_ed25519_new;
ossl_unused static OSSL_FUNC_keymgmt_new_fn keymgmt_ed448_new;
ossl_unused static OSSL_FUNC_keymgmt_free_fn keymgmt_free;
ossl_unused static OSSL_FUNC_keymgmt_dup_fn keymgmt_dup;
ossl_unused static OSSL_FUNC_keymgmt_import_fn keymgmt_import;
ossl_unused static OSSL_FUNC_keymgmt_has_fn keymgmt_has;
ossl_unused static OSSL_FUNC_keymgmt_match_fn keymgmt_match;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_import_types;
ossl_unused static OSSL_FUNC_keymgmt_export_fn keymgmt_export;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_rsa_export_types;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_ec_export_types;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_dh_export_types;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_x25519_export_types;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_x448_export_types;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_ed25519_export_types;
ossl_unused static OSSL_FUNC_keymgmt_import_types_fn keymgmt_ed448_export_types;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_rsa_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_ec_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_dh_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_x25519_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_x448_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_ed25519_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_ed448_gettable_params;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_rsa_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_ec_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_dh_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_x25519_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_x448_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_ed25519_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_ed448_query_operation_name;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_rsa_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_ec_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_dh_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_x25519_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_x448_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_ed25519_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_init_fn keymgmt_ed448_gen_init;
ossl_unused static OSSL_FUNC_keymgmt_gen_set_template_fn keymgmt_gen_set_template;
ossl_unused static OSSL_FUNC_keymgmt_gen_set_params_fn keymgmt_gen_set_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_rsa_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_ec_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_dh_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_x25519_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_x448_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_ed25519_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_ed448_gen_settable_params;
ossl_unused static OSSL_FUNC_keymgmt_gen_fn keymgmt_gen;
ossl_unused static OSSL_FUNC_keymgmt_gen_cleanup_fn keymgmt_gen_cleanup;

static sa_elliptic_curve ec_get_curve_from_type(EVP_PKEY* evp_pkey) {
    int type = EVP_PKEY_get_id(evp_pkey);
    char group_name[MAX_NAME_SIZE];
    size_t group_name_length = 0;

    switch (type) {
        case EVP_PKEY_X25519:
            return SA_ELLIPTIC_CURVE_X25519;

        case EVP_PKEY_X448:
            return SA_ELLIPTIC_CURVE_X448;

        case EVP_PKEY_ED25519:
            return SA_ELLIPTIC_CURVE_ED25519;

        case EVP_PKEY_ED448:
            return SA_ELLIPTIC_CURVE_ED448;

        case EVP_PKEY_EC:
            if (EVP_PKEY_get_group_name(evp_pkey, group_name, MAX_NAME_SIZE, &group_name_length) != 1)
                return UINT32_MAX;

            if (strcmp(group_name, "P-192") == 0)
                return SA_ELLIPTIC_CURVE_NIST_P192;

            if (strcmp(group_name, "P-224") == 0)
                return SA_ELLIPTIC_CURVE_NIST_P224;

            if (strcmp(group_name, "P-256") == 0)
                return SA_ELLIPTIC_CURVE_NIST_P256;

            if (strcmp(group_name, "P-384") == 0)
                return SA_ELLIPTIC_CURVE_NIST_P384;

            if (strcmp(group_name, "P-521") == 0)
                return SA_ELLIPTIC_CURVE_NIST_P521;

            return UINT32_MAX;

        default:
            return UINT32_MAX;
    }
}

static sa_elliptic_curve ec_get_curve_from_name(const char* name) {
    if (strcmp("prime192v1", name) == 0 || strcmp("P-192", name) == 0)
        return SA_ELLIPTIC_CURVE_NIST_P192;

    if (strcmp("secp224r1", name) == 0 || strcmp("P-224", name) == 0)
        return SA_ELLIPTIC_CURVE_NIST_P224;

    if (strcmp("prime256v1", name) == 0 || strcmp("P-256", name) == 0)
        return SA_ELLIPTIC_CURVE_NIST_P256;

    if (strcmp("secp384r1", name) == 0 || strcmp("P-384", name) == 0)
        return SA_ELLIPTIC_CURVE_NIST_P384;

    if (strcmp("secp521r1", name) == 0 || strcmp("P-521", name) == 0)
        return SA_ELLIPTIC_CURVE_NIST_P521;

    if (strcmp("ED25519", name) == 0)
        return SA_ELLIPTIC_CURVE_ED25519;

    if (strcmp("X25519", name) == 0)
        return SA_ELLIPTIC_CURVE_X25519;

    if (strcmp("ED448", name) == 0)
        return SA_ELLIPTIC_CURVE_ED448;

    if (strcmp("X448", name) == 0)
        return SA_ELLIPTIC_CURVE_X448;

    return UINT32_MAX;
}

static void* keymgmt_new(
        int type,
        const char* name,
        void* provctx) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_key_data* key_data = NULL;
    sa_provider_context* provider_context = provctx;
    key_data = OPENSSL_zalloc(sizeof(sa_provider_key_data));
    if (key_data == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    key_data->provider_context = provider_context;
    atomic_init(&key_data->reference_count, 1);
    key_data->type = type;
    key_data->name = name;
    key_data->private_key = INVALID_HANDLE;
    key_data->public_key = NULL;
    key_data->delete_key = false;
    return key_data;
}

static void keymgmt_free(void* keydata) {
    if (keydata == NULL)
        return;

    sa_provider_key_data* key_data = keydata;
    int value = atomic_fetch_sub(&key_data->reference_count, 1) - 1;
    if (value == 0) {
        if (key_data->delete_key && key_data->private_key != INVALID_HANDLE)
            sa_key_release(key_data->private_key);

        key_data->private_key = INVALID_HANDLE;
        EVP_PKEY_free(key_data->public_key);
        key_data->public_key = NULL;
        OPENSSL_free(key_data);
    }
}

static void* keymgmt_dup(
        const void* keydata_from,
        ossl_unused int selection) {

    if (keydata_from == NULL) {
        ERROR("NULL keydata_from");
        return NULL;
    }

    sa_provider_key_data* key_data = (sa_provider_key_data*) keydata_from;
    atomic_fetch_add(&key_data->reference_count, 1);
    return key_data;
}

static int keymgmt_has(
        const void* keydata,
        ossl_unused int selection) {

    if (keydata == NULL) {
        ERROR("NULL keydata");
        return 0;
    }

    const sa_provider_key_data* key_data = keydata;
    return key_data->private_key != INVALID_HANDLE;
}

static int keymgmt_match(
        const void* keydata1,
        const void* keydata2,
        ossl_unused int selection) {

    if (keydata1 == NULL) {
        ERROR("NULL keydata1");
        return 0;
    }

    if (keydata2 == NULL) {
        ERROR("NULL keydata2");
        return 0;
    }

    const sa_provider_key_data* key_data1 = keydata1;
    const sa_provider_key_data* key_data2 = keydata1;
    return key_data1->private_key == key_data2->private_key;
}

static int keymgmt_import(
        void* keydata,
        ossl_unused int selection,
        const OSSL_PARAM params[]) {

    if (keydata == NULL) {
        ERROR("NULL keydata");
        return 0;
    }

    sa_provider_key_data* key_data = keydata;
    int result = 0;
    uint8_t* pkcs8 = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    BIGNUM* p = NULL;
    BIGNUM* g = NULL;
    sa_key private_key = INVALID_HANDLE;
    int delete_key = 0;
    sa_header private_key_header;
    memset(&private_key_header, 0, sizeof(sa_header));
    do {
        // Import a private key and/or a public key.
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
            const OSSL_PARAM* sa_key_param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY);
            if (sa_key_param != NULL) {
                // Import the private key from SecApi3.
                if (OSSL_PARAM_get_ulong(sa_key_param, &private_key) != 1) {
                    ERROR("OSSL_PARAM_get_ulong failed");
                    break;
                }
            } else {
                // Import the raw private or public key.
                evp_pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, key_data->name, NULL);
                if (evp_pkey_ctx == NULL) {
                    ERROR("EVP_PKEY_CTX_new_from_name failed");
                    break;
                }

                if (EVP_PKEY_fromdata_init(evp_pkey_ctx) != 1) {
                    ERROR("EVP_PKEY_fromdata_init failed");
                    break;
                }

                if (EVP_PKEY_fromdata(evp_pkey_ctx, &evp_pkey, EVP_PKEY_KEYPAIR, (OSSL_PARAM*) params) != 1) {
                    ERROR("EVP_PKEY_fromdata failed");
                    break;
                }

                size_t pkcs8_length = 0;
                // Check if a private key is available and if so import it. If not include only the public key.
                if (evp_pkey_to_pkcs8(NULL, &pkcs8_length, evp_pkey)) {
                    pkcs8 = OPENSSL_malloc(pkcs8_length);
                    if (pkcs8 == NULL) {
                        ERROR("OPENSSL_malloc failed");
                        break;
                    }

                    if (!evp_pkey_to_pkcs8(pkcs8, &pkcs8_length, evp_pkey)) {
                        ERROR("evp_pkey_to_pkcs8 failed");
                        break;
                    }

                    sa_key_format key_format;
                    void* parameters = NULL;
                    sa_import_parameters_rsa_private_key_info parameters_rsa;
                    sa_import_parameters_ec_private_bytes parameters_ec;
                    sa_rights rights;
                    sa_rights_set_allow_all(&rights);
                    if (key_data->type == EVP_PKEY_RSA) {
                        key_format = SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO;
                        parameters_rsa.rights = &rights;
                        parameters = &parameters_rsa;
                    } else if (key_data->type == EVP_PKEY_EC ||
                               key_data->type == EVP_PKEY_X25519 ||
                               key_data->type == EVP_PKEY_X448 ||
                               key_data->type == EVP_PKEY_ED25519 ||
                               key_data->type == EVP_PKEY_ED448) {
                        key_format = SA_KEY_FORMAT_EC_PRIVATE_BYTES;
                        parameters_ec.curve = ec_get_curve_from_type(evp_pkey);
                        if (parameters_ec.curve == UINT32_MAX) {
                            ERROR("Unkonwn EC curve");
                            break;
                        }

                        parameters_ec.rights = &rights;
                        parameters = &parameters_ec;
                    } else {
                        ERROR("Unsupported key type for import");
                        return 0;
                    }

                    if (sa_key_import(&private_key, key_format, pkcs8, pkcs8_length,
                                parameters) != SA_STATUS_OK) {
                        ERROR("sa_key_import failed");
                        break;
                    }

                    delete_key = 1;
                }
            }
        }

        if (private_key != INVALID_HANDLE) {
            // If the private was imported, get the public key and the header.
            evp_pkey = sa_get_public_key(private_key);
            if (evp_pkey == NULL) {
                ERROR("sa_get_public_key failed");
                break;
            }

            if (sa_key_header(&private_key_header, private_key) != SA_STATUS_OK) {
                ERROR("sa_key_header failed");
                break;
            }

            const OSSL_PARAM* sa_key_delete_param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY_DELETE);
            if (sa_key_delete_param != NULL) {
                if (OSSL_PARAM_get_int(sa_key_delete_param, &delete_key) != 1) {
                    ERROR("OSSL_PARAM_get_int failed");
                    break;
                }
            }
        } else {
            // The private key was not loaded, so then populate the header from the params.
            private_key = INVALID_HANDLE;
            if (key_data->type == EVP_PKEY_DH) {
                const OSSL_PARAM* p_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
                const OSSL_PARAM* g_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);
                if (p_param != NULL && g_param != NULL) {
                    if (OSSL_PARAM_get_BN(p_param, &p) != 1) {
                        ERROR("OSSL_PARAM_get_BN failed");
                        break;
                    }

                    if (OSSL_PARAM_get_BN(g_param, &g) != 1) {
                        ERROR("OSSL_PARAM_get_BN failed");
                        BN_free(p);
                        break;
                    }

                    private_key_header.type = SA_KEY_TYPE_DH;
                    private_key_header.size = BN_num_bytes(p);
                    BN_bn2nativepad(p, private_key_header.type_parameters.dh_parameters.p, BN_num_bytes(p));
                    private_key_header.type_parameters.dh_parameters.p_length = BN_num_bytes(p);
                    BN_bn2nativepad(g, private_key_header.type_parameters.dh_parameters.g, BN_num_bytes(g));
                    private_key_header.type_parameters.dh_parameters.g_length = BN_num_bytes(g);
                }
            } else if (key_data->type == EVP_PKEY_EC) {
                const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
                if ((param) != NULL) {
                    char name[MAX_NAME_SIZE];
                    char* p_name = name;
                    if (OSSL_PARAM_get_utf8_string(param, &p_name, MAX_NAME_SIZE) != 1) {
                        ERROR("OSSL_PARAM_get_utf8_string failed");
                        break;
                    }

                    private_key_header.type = SA_KEY_TYPE_EC;
                    private_key_header.type_parameters.curve = ec_get_curve_from_name(name);
                    private_key_header.size = ec_get_key_size(private_key_header.type_parameters.curve);
                }
            } else if (key_data->type == EVP_PKEY_RSA) {
                private_key_header.type = SA_KEY_TYPE_RSA;
                if (evp_pkey != NULL) {
                    private_key_header.size = EVP_PKEY_get_bits(evp_pkey) / 8;
                } else {
                    const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
                    if (param != NULL) {
                        int key_size;
                        if (OSSL_PARAM_get_int(param, &key_size) != 1) {
                            ERROR("OSSL_PARAM_get_int failed");
                            break;
                        }

                        private_key_header.size = key_size / 8;
                    }
                }
            } else if (key_data->type == EVP_PKEY_X25519) {
                private_key_header.type = SA_KEY_TYPE_EC;
                private_key_header.type_parameters.curve = SA_ELLIPTIC_CURVE_X25519;
                private_key_header.size = EC_25519_KEY_SIZE;
            } else if (key_data->type == EVP_PKEY_X448) {
                private_key_header.type = SA_KEY_TYPE_EC;
                private_key_header.type_parameters.curve = SA_ELLIPTIC_CURVE_X448;
                private_key_header.size = EC_X448_KEY_SIZE;
            } else if (key_data->type == EVP_PKEY_ED25519) {
                private_key_header.type = SA_KEY_TYPE_EC;
                private_key_header.type_parameters.curve = SA_ELLIPTIC_CURVE_ED25519;
                private_key_header.size = EC_25519_KEY_SIZE;
            } else if (key_data->type == EVP_PKEY_ED448) {
                private_key_header.type = SA_KEY_TYPE_EC;
                private_key_header.type_parameters.curve = SA_ELLIPTIC_CURVE_ED448;
                private_key_header.size = EC_ED448_KEY_SIZE;
            }
        }

        if (key_data->private_key != INVALID_HANDLE)
            sa_key_release(key_data->private_key);

        EVP_PKEY_free(key_data->public_key);
        key_data->private_key = private_key;
        key_data->public_key = EVP_PKEY_dup(evp_pkey);
        memcpy(&key_data->private_key_header, &private_key_header, sizeof(sa_header));
        key_data->delete_key = delete_key;

        result = 1;
    } while (false);

    OPENSSL_free(pkcs8);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(evp_pkey);
    BN_free(p);
    BN_free(g);
    if (result != 1) {
        if (key_data->private_key != INVALID_HANDLE) {
            sa_key_release(key_data->private_key);
            key_data->private_key = INVALID_HANDLE;
        }

        EVP_PKEY_free(key_data->public_key);
        key_data->public_key = NULL;
        memset(&key_data->private_key_header, 0, sizeof(sa_header));
    }

    return result;
}

static const OSSL_PARAM* keymgmt_import_types(ossl_unused int selection) {
    static const OSSL_PARAM settable_params[] = {
            OSSL_PARAM_ulong(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return settable_params;
}

static int keymgmt_export(
        void* keydata,
        int selection,
        OSSL_CALLBACK* param_cb,
        void* cbarg) {
    if (keydata == NULL) {
        ERROR("NULL keydata");
        return 0;
    }

    int result = 0;
    OSSL_PARAM* public_key_params = NULL;
    OSSL_PARAM* merged_params = NULL;
    do {
        sa_provider_key_data* key_data = keydata;
        if (key_data->public_key == NULL) {
            ERROR("NULL key_data->public_key");
            break;
        }

        OSSL_PARAM private_key_params[] = {
                OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, &key_data->private_key),
                OSSL_PARAM_construct_end()};

        if (EVP_PKEY_todata(key_data->public_key, selection, &public_key_params) != 1) {
            ERROR("EVP_PKEY_todata failed");
            break;
        }

        merged_params = OSSL_PARAM_merge(private_key_params, public_key_params);
        if (merged_params == NULL) {
            ERROR("NULL merged_params");
            break;
        }

        if (param_cb(merged_params, cbarg) != 1) {
            ERROR("param_cb failed");
            break;
        }

        result = 1;
    } while (false);

    OSSL_PARAM_free(public_key_params);
    OSSL_PARAM_free(merged_params);
    return result;
}

ossl_unused static const OSSL_PARAM* keymgmt_rsa_export_types(ossl_unused int selection) {
    static const OSSL_PARAM rsa_key_types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
            OSSL_PARAM_END};

    return rsa_key_types;
}

ossl_unused static const OSSL_PARAM* keymgmt_ec_export_types(ossl_unused int selection) {
    static const OSSL_PARAM ec_key_types[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};

    return ec_key_types;
}

ossl_unused static const OSSL_PARAM* keymgmt_dh_export_types(ossl_unused int selection) {
    static const OSSL_PARAM dh_key_types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};

    return dh_key_types;
}

ossl_unused static const OSSL_PARAM* keymgmt_x25519_export_types(ossl_unused int selection) {
    static const OSSL_PARAM x25519_key_types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};

    return x25519_key_types;
}

ossl_unused static const OSSL_PARAM* keymgmt_x448_export_types(ossl_unused int selection) {
    static const OSSL_PARAM x25519_key_types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};

    return x25519_key_types;
}

ossl_unused static const OSSL_PARAM* keymgmt_ed25519_export_types(ossl_unused int selection) {
    static const OSSL_PARAM x25519_key_types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};

    return x25519_key_types;
}

ossl_unused static const OSSL_PARAM* keymgmt_ed448_export_types(ossl_unused int selection) {
    static const OSSL_PARAM x25519_key_types[] = {
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};

    return x25519_key_types;
}

static int keymgmt_get_params(
        void* keydata,
        OSSL_PARAM params[]) {

    if (keydata == NULL) {
        ERROR("NULL keydata");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    sa_provider_key_data* key_data = keydata;
    if (key_data->public_key == NULL)
        // Don't log
        return 0;

    if (EVP_PKEY_get_params(key_data->public_key, params) != 1) {
        ERROR("EVP_PKEY_get_params failed");
        return 0;
    }

    return 1;
}

static const OSSL_PARAM* keymgmt_gettable_params(int type) {
    const OSSL_PARAM* gettable_params = NULL;
    EVP_PKEY* evp_pkey = NULL;
    do {
        evp_pkey = EVP_PKEY_new();
        if (evp_pkey == NULL) {
            ERROR("NULL evp_pkey");
            break;
        }

        if (EVP_PKEY_set_type(evp_pkey, type) != 1) {
            ERROR("EVP_PKEY_set_type failed");
            break;
        }

        gettable_params = EVP_PKEY_gettable_params(evp_pkey);
    } while (false);

    EVP_PKEY_free(evp_pkey);
    return gettable_params;
}

ossl_unused static const char* keymgmt_query_operation_name(
        int type,
        ossl_unused int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE) {
        switch (type) {
            case EVP_PKEY_RSA:
                return "RSA";

            case EVP_PKEY_EC:
                return "ECDSA";

            case EVP_PKEY_ED25519:
                return "ED25519";

            case EVP_PKEY_ED448:
                return "ED448";

            default:
                return NULL;
        }
    }

    if (operation_id == OSSL_OP_KEYEXCH) {
        switch (type) {
            case EVP_PKEY_DH:
                return "DH";

            case EVP_PKEY_EC:
                return "ECDH";

            case EVP_PKEY_X25519:
                return "X25519";

            case EVP_PKEY_X448:
                return "X448";

            default:
                return NULL;
        }
    }

    if (operation_id == OSSL_OP_ASYM_CIPHER) {
        if (type == EVP_PKEY_RSA)
            return "RSA";

        return NULL;
    }

    return NULL;
}

static void* keymgmt_gen_init(
        int type,
        const char* name,
        void* provctx,
        int selection,
        const OSSL_PARAM params[]) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_key_gen_context* key_gen_context = NULL;
    sa_provider_context* provider_context = provctx;
    key_gen_context = OPENSSL_zalloc(sizeof(sa_provider_key_gen_context));
    if (key_gen_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    key_gen_context->provider_context = provider_context;
    key_gen_context->type = type;
    key_gen_context->name = name;
    key_gen_context->selection = selection;
    switch (type) {
        case EVP_PKEY_RSA:
            key_gen_context->key_size = RSA_2048_BYTE_LENGTH;
            key_gen_context->type_parameters.curve = UINT32_MAX;
            break;

        case EVP_PKEY_DH:
            key_gen_context->key_size = DH_2048_BYTE_LENGTH;
            memcpy(key_gen_context->type_parameters.dh_parameters.p, MODP_2048_P, sizeof(MODP_2048_P));
            key_gen_context->type_parameters.dh_parameters.p_length = sizeof(MODP_2048_P);
            memcpy(key_gen_context->type_parameters.dh_parameters.g, MODP_2048_G, sizeof(MODP_2048_G));
            key_gen_context->type_parameters.dh_parameters.g_length = sizeof(MODP_2048_G);
            break;

        case EVP_PKEY_EC:
            key_gen_context->key_size = 0;
            key_gen_context->type_parameters.curve = SA_ELLIPTIC_CURVE_NIST_P256;
            break;

        case EVP_PKEY_X25519:
            key_gen_context->key_size = 0;
            key_gen_context->type_parameters.curve = SA_ELLIPTIC_CURVE_X25519;
            break;

        case EVP_PKEY_X448:
            key_gen_context->key_size = 0;
            key_gen_context->type_parameters.curve = SA_ELLIPTIC_CURVE_X448;
            break;

        case EVP_PKEY_ED25519:
            key_gen_context->key_size = 0;
            key_gen_context->type_parameters.curve = SA_ELLIPTIC_CURVE_ED25519;
            break;

        case EVP_PKEY_ED448:
            key_gen_context->key_size = 0;
            key_gen_context->type_parameters.curve = SA_ELLIPTIC_CURVE_ED448;
            break;

        default:
            ERROR("Unsupported type");
            OPENSSL_free(key_gen_context);
            return NULL;
    }

    keymgmt_gen_set_params(key_gen_context, params);
    return key_gen_context;
}

static int keymgmt_gen_set_template(
        void* genctx,
        void* templ) {

    if (genctx == NULL) {
        ERROR("NULL genctx");
        return 0;
    }

    if (templ == NULL) {
        ERROR("NULL templ");
        return 0;
    }

    sa_provider_key_gen_context* key_gen_context = genctx;
    sa_provider_key_data* key_data = templ;
    key_gen_context->key_size = key_data->private_key_header.size;
    key_gen_context->type_parameters = key_data->private_key_header.type_parameters;
    return 1;
}

static void* keymgmt_gen(
        void* genctx,
        ossl_unused OSSL_CALLBACK* cb,
        ossl_unused void* cbarg) {

    if (genctx == NULL) {
        ERROR("NULL genctx");
        return NULL;
    }

    sa_provider_key_gen_context* key_gen_context = genctx;
    sa_provider_key_data* key_data = NULL;
    if ((key_gen_context->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        sa_key_type key_type;
        sa_generate_parameters_rsa parameters_rsa;
        sa_generate_parameters_ec parameters_ec;
        sa_generate_parameters_dh parameters_dh;
        void* parameters = NULL;
        switch (key_gen_context->type) {
            case EVP_PKEY_RSA:
                key_type = SA_KEY_TYPE_RSA;
                parameters_rsa.modulus_length = key_gen_context->key_size;
                parameters = &parameters_rsa;
                break;

            case EVP_PKEY_EC:
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448:
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                key_type = SA_KEY_TYPE_EC;
                parameters_ec.curve = key_gen_context->type_parameters.curve;
                parameters = &parameters_ec;
                break;

            case EVP_PKEY_DH:
                key_type = SA_KEY_TYPE_DH;
                parameters_dh.p = key_gen_context->type_parameters.dh_parameters.p;
                parameters_dh.p_length = key_gen_context->type_parameters.dh_parameters.p_length;
                parameters_dh.g = key_gen_context->type_parameters.dh_parameters.g;
                parameters_dh.g_length = key_gen_context->type_parameters.dh_parameters.g_length;
                parameters = &parameters_dh;
                break;

            default:
                ERROR("Unknown key type");
                return NULL;
        }

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        key_data = keymgmt_new(key_gen_context->type, key_gen_context->name, key_gen_context->provider_context);
        if (key_data == NULL) {
            ERROR("keymgmt_new failed");
            return NULL;
        }

        key_data->delete_key = true;
        if (sa_key_generate(&key_data->private_key, &rights, key_type, parameters) != SA_STATUS_OK) {
            ERROR("sa_key_generate failed");
            keymgmt_free(key_data);
            return NULL;
        }

        key_data->public_key = sa_get_public_key(key_data->private_key);
        if (key_data->public_key == NULL) {
            ERROR("sa_get_public_key failed");
            keymgmt_free(key_data);
            return NULL;
        }

        if (sa_key_header(&key_data->private_key_header, key_data->private_key) != SA_STATUS_OK) {
            ERROR("sa_key_header failed");
            keymgmt_free(key_data);
            return NULL;
        }
    } else {
        key_data = keymgmt_new(key_gen_context->type, key_gen_context->name, key_gen_context->provider_context);
        if (key_data == NULL) {
            ERROR("keymgmt_new failed");
            return NULL;
        }

        key_data->type = key_gen_context->type;
        key_data->name = key_gen_context->name;
        key_data->private_key = INVALID_HANDLE;
        key_data->private_key_header.size = key_gen_context->key_size;
        key_data->private_key_header.type_parameters = key_gen_context->type_parameters;
    }

    return key_data;
}

static void keymgmt_gen_cleanup(void* genctx) {
    if (genctx == NULL)
        return;

    OPENSSL_free(genctx);
}

static int keymgmt_gen_set_params(
        void* genctx,
        const OSSL_PARAM params[]) {

    if (genctx == NULL) {
        ERROR("NULL genctx");
        return 0;
    }

    if (params == NULL)
        return 1;

    sa_provider_key_gen_context* key_gen_context = genctx;
    const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (param != NULL) {
        size_t key_size;
        if (!OSSL_PARAM_get_size_t(param, &key_size)) {
            ERROR("OSSL_PARAM_get_size_t failed");
            return 0;
        }

        key_gen_context->key_size = key_size / 8;
    }

    char name[MAX_NAME_SIZE];
    char* p_name = name;
    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (param != NULL) {
        if (!OSSL_PARAM_get_utf8_string(param, &p_name, MAX_NAME_SIZE)) {
            ERROR("OSSL_PARAM_get_utf8_string failed");
            return 0;
        }

        key_gen_context->type_parameters.curve = ec_get_curve_from_name(name);
        if (key_gen_context->type_parameters.curve == UINT32_MAX) {
            ERROR("Unknown curve name");
            return 0;
        }
    }

    return 1;
}

ossl_unused static const OSSL_PARAM* keymgmt_rsa_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused static const OSSL_PARAM* keymgmt_ec_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            // Indicate support for compatibility, but ignore the field.
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused static const OSSL_PARAM* keymgmt_dh_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused static const OSSL_PARAM* keymgmt_x25519_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused static const OSSL_PARAM* keymgmt_x448_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused static const OSSL_PARAM* keymgmt_ed25519_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused static const OSSL_PARAM* keymgmt_ed448_gen_settable_params(
        ossl_unused void* genctx,
        ossl_unused void* provctx) {

    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_END};

    return settable;
}

ossl_unused sa_provider_key_data* sa_provider_key_data_dup(sa_provider_key_data* key_data) {
    atomic_fetch_add(&key_data->reference_count, 1);
    return key_data;
}

ossl_unused void sa_provider_key_data_free(sa_provider_key_data* key_data) {
    keymgmt_free(key_data);
}

#define SA_PROVIDER_KEYMGMT_FUNCTIONS(algorithm, type, name) \
    static void* keymgmt_##algorithm##_new(void* provctx) { \
        return keymgmt_new(type, name, provctx); \
    } \
\
    static const OSSL_PARAM* keymgmt_##algorithm##_gettable_params(void* provctx) { \
        return keymgmt_gettable_params(type); \
    } \
\
    static const char* keymgmt_##algorithm##_query_operation_name(int operation_id) { \
        return keymgmt_query_operation_name(type, operation_id); \
    } \
\
    static void* keymgmt_##algorithm##_gen_init( \
            void* provctx, \
            int selection, \
            const OSSL_PARAM params[]) { \
        return keymgmt_gen_init(type, name, provctx, selection, params); \
    } \
\
    static const OSSL_DISPATCH sa_provider_##algorithm##_keymgmt_functions[] = { \
            {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) keymgmt_##algorithm##_new}, \
            {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) keymgmt_free}, \
            {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void)) keymgmt_dup}, \
            {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) keymgmt_has}, \
            {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) keymgmt_match}, \
            {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) keymgmt_import}, \
            {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) keymgmt_import_types}, \
            {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) keymgmt_export}, \
            {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) keymgmt_##algorithm##_export_types}, \
            {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) keymgmt_get_params}, \
            {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) keymgmt_##algorithm##_gettable_params}, \
            {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) keymgmt_##algorithm##_query_operation_name}, \
            {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) keymgmt_##algorithm##_gen_init}, \
            {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void)) keymgmt_gen_set_template}, \
            {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) keymgmt_gen}, \
            {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) keymgmt_gen_cleanup}, \
            {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) keymgmt_gen_set_params}, \
            {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) keymgmt_##algorithm##_gen_settable_params}, \
            {0, NULL}}

SA_PROVIDER_KEYMGMT_FUNCTIONS(rsa, EVP_PKEY_RSA, "RSA");
SA_PROVIDER_KEYMGMT_FUNCTIONS(ec, EVP_PKEY_EC, "EC");
SA_PROVIDER_KEYMGMT_FUNCTIONS(dh, EVP_PKEY_DH, "DH");
SA_PROVIDER_KEYMGMT_FUNCTIONS(x25519, EVP_PKEY_X25519, "X25519");
SA_PROVIDER_KEYMGMT_FUNCTIONS(x448, EVP_PKEY_X448, "X448");
SA_PROVIDER_KEYMGMT_FUNCTIONS(ed25519, EVP_PKEY_ED25519, "ED25519");
SA_PROVIDER_KEYMGMT_FUNCTIONS(ed448, EVP_PKEY_ED448, "ED448");

ossl_unused const OSSL_ALGORITHM sa_provider_keymgmt[] = {
        {"RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=secapi3", sa_provider_rsa_keymgmt_functions, ""},
        {"EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=secapi3", sa_provider_ec_keymgmt_functions, ""},
        {"DH:dhKeyAgreement:1.2.840.113549.1.3.1", "provider=secapi3", sa_provider_dh_keymgmt_functions, ""},
        {"X25519:1.3.101.110", "provider=secapi3", sa_provider_x25519_keymgmt_functions, ""},
        {"X448:1.3.101.111", "provider=secapi3", sa_provider_x448_keymgmt_functions, ""},
        {"ED25519:1.3.101.112", "provider=secapi3", sa_provider_ed25519_keymgmt_functions, ""},
        {"ED448:1.3.101.113", "provider=secapi3", sa_provider_ed448_keymgmt_functions, ""},
        {NULL, NULL, NULL, NULL}};

#endif
