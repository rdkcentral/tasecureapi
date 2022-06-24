/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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

#include "dh.h"
#include "log.h"
#include "pkcs8.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#else
#include <openssl/dh.h>
#endif
#include <memory.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000
static void swap_native_binary(
        void* value,
        size_t length) {

    // Check little-endian.
    unsigned int ui = 1;
    char* c = (char*) &ui;

    if (*c == 1) {
        // If little-endian, reverse the array to go from native to binary or binary to native.
        char* array = (char*) value;
        for (size_t i = 0; i < length / 2; i++) {
            char temp = array[i];
            array[i] = array[length - 1 - i];
            array[length - 1 - i] = temp;
        }
    }

    // Do nothing for big-endian.
}
#endif

bool dh_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    bool status = false;
    EVP_PKEY* evp_pkey = NULL;
    do {
        const uint8_t* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_DH, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        int length = i2d_PUBKEY(evp_pkey, NULL);
        if (length <= 0) {
            ERROR("i2d_PUBKEY failed");
            break;
        }

        if (out == NULL) {
            *out_length = length;
            status = true;
            break;
        }

        if (*out_length < (size_t) length) {
            ERROR("Invalid out_length");
            break;
        }

        uint8_t* p_out = out;
        length = i2d_PUBKEY(evp_pkey, &p_out);
        if (length <= 0) {
            ERROR("i2d_PUBKEY failed");
            break;
        }

        *out_length = length;
        status = true;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    return status;
}

sa_status dh_compute_shared_secret(
        stored_key_t** stored_key_shared_secret,
        const sa_rights* rights,
        const void* other_public,
        size_t other_public_length,
        const stored_key_t* stored_key) {

    if (stored_key_shared_secret == NULL) {
        ERROR("NULL stored_key_shared_secret");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* shared_secret = NULL;
    size_t shared_secret_length = 0;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY* other_evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    do {
        const uint8_t* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_DH, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        const uint8_t* p_other_public = other_public;
        other_evp_pkey = d2i_PUBKEY(NULL, &p_other_public, (long) other_public_length);
        if (other_evp_pkey == NULL) {
            ERROR("d2i_PUBKEY failed");
            break;
        }

        if (EVP_PKEY_id(evp_pkey) != EVP_PKEY_id(other_evp_pkey)) {
            ERROR("Key type mismatch");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
        if (evp_pkey == NULL) {
            ERROR("EVP_PKEY_CTX_new failed");
            break;
        }

        if (EVP_PKEY_derive_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_derive_init failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        if (EVP_PKEY_CTX_set_dh_pad(evp_pkey_ctx, 1) != 1) {
            ERROR("EVP_PKEY_CTX_set_dh_pad failed");
            return false;
        }
#endif

        if (EVP_PKEY_derive_set_peer(evp_pkey_ctx, other_evp_pkey) != 1) {
            ERROR("EVP_PKEY_derive_set_peer failed");
            break;
        }

        if (EVP_PKEY_derive(evp_pkey_ctx, NULL, &shared_secret_length) != 1) {
            ERROR("EVP_PKEY_derive failed");
            break;
        }

        shared_secret = memory_secure_alloc(shared_secret_length);
        if (shared_secret == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (EVP_PKEY_derive(evp_pkey_ctx, shared_secret, &shared_secret_length) != 1) {
            ERROR("EVP_PKEY_derive failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000
        if (header->size != shared_secret_length) {
            memmove(shared_secret + header->size - shared_secret_length, shared_secret, shared_secret_length);
            memset(shared_secret, 0, header->size - shared_secret_length);
            shared_secret_length = header->size;
        }
#endif
        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        if (!stored_key_create(stored_key_shared_secret, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC,
                    &type_parameters, shared_secret_length, shared_secret, shared_secret_length)) {
            ERROR("stored_key_create failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (shared_secret != NULL) {
        memory_memset_unoptimizable(shared_secret, 0, shared_secret_length);
        memory_secure_free(shared_secret);
    }

    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(other_evp_pkey);
    return status;
}

bool dh_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        const void* p,
        size_t p_length,
        const void* g,
        size_t g_length) {

    if (stored_key == NULL) {
        ERROR("NULL key");
        return false;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (p == NULL) {
        ERROR("NULL p");
        return false;
    }

    if (g == NULL) {
        ERROR("NULL g");
        return false;
    }

    if (p_length > DH_MAX_MOD_SIZE || p_length == 0) {
        ERROR("Invalid length");
        return false;
    }

    if (g_length < 1 || g_length > p_length) {
        ERROR("Invalid p_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    bool status = false;
    uint8_t* key = NULL;
    size_t key_length;
    EVP_PKEY* evp_pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY* evp_pkey_parameters = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    EVP_PKEY_CTX* evp_pkey_parameters_ctx = NULL;
    uint8_t* key_p = NULL;
    uint8_t* key_g = NULL;
#else
    DH* dh = NULL;
    BIGNUM* bn_p = NULL;
    BIGNUM* bn_g = NULL;
#endif
    do {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        key_p = memory_secure_alloc(p_length);
        if (key_p == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(key_p, 0, p_length);

        key_g = memory_secure_alloc(g_length);
        if (key_g == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(key_g, 0, g_length);

        memcpy(key_p, p, p_length);
        swap_native_binary(key_p, p_length);
        memcpy(key_g, g, g_length);
        swap_native_binary(key_g, g_length);

        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, key_p, p_length),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, key_g, g_length),
                OSSL_PARAM_construct_end()};

        evp_pkey_parameters_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
        if (evp_pkey_parameters_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new_id failed");
            break;
        }

        if (EVP_PKEY_fromdata_init(evp_pkey_parameters_ctx) != 1) {
            ERROR("EVP_PKEY_fromdata_init failed");
            break;
        }

        if (EVP_PKEY_fromdata(evp_pkey_parameters_ctx, &evp_pkey_parameters, EVP_PKEY_KEY_PARAMETERS, params) != 1) {
            ERROR("EVP_PKEY_fromdata failed");
            break;
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey_parameters, NULL);
        if (evp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new failed");
            break;
        }

        if (EVP_PKEY_keygen_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_keygen_init failed");
            break;
        }

        if (EVP_PKEY_generate(evp_pkey_ctx, &evp_pkey) != 1) {
            ERROR("EVP_PKEY_generate failed");
            break;
        }

#else
        // set params
        bn_p = BN_bin2bn(p, (int) p_length, NULL);
        if (bn_p == NULL) {
            ERROR("BN_bin2bn failed");
            break;
        }

        bn_g = BN_bin2bn(g, (int) g_length, NULL);
        if (bn_g == NULL) {
            ERROR("BN_bin2bn failed");
            break;
        }

        dh = DH_new();
        if (dh == NULL) {
            ERROR("DH_new failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        dh->p = bn_p;
        dh->g = bn_g;
#else
        if (!DH_set0_pqg(dh, bn_p, NULL, bn_g)) {
            ERROR("DH_set0_pqg failed");
            break;
        }

#endif
        // at this point ownership of bns is passed to dh
        bn_p = NULL;
        bn_g = NULL;

        if (!DH_generate_key(dh)) {
            ERROR("DH_generate_key failed");
            break;
        }

        evp_pkey = EVP_PKEY_new();
        if (evp_pkey == NULL) {
            ERROR("EVP_PKEY_new failed");
            break;
        }

        if (EVP_PKEY_set1_DH(evp_pkey, dh) != 1) {
            ERROR("EVP_PKEY_set1_DH failed");
            break;
        }

#endif
        key_length = 0;
        if (!evp_pkey_to_pkcs8(NULL, &key_length, evp_pkey)) {
            ERROR("evp_pkey_to_pkcs8 failed");
            break;
        }

        key = memory_secure_alloc(key_length);
        if (key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!evp_pkey_to_pkcs8(key, &key_length, evp_pkey)) {
            ERROR("evp_pkey_to_pkcs8 failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(type_parameters));
        memcpy(type_parameters.dh_parameters.p, p, p_length);
        type_parameters.dh_parameters.p_length = p_length;
        memcpy(type_parameters.dh_parameters.g, g, g_length);
        type_parameters.dh_parameters.g_length = g_length;
        status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_DH, &type_parameters, p_length, key,
                key_length);
        if (!status) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (key != NULL) {
        memory_memset_unoptimizable(key, 0, key_length);
        memory_secure_free(key);
    }

    EVP_PKEY_free(evp_pkey);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY_free(evp_pkey_parameters);
    EVP_PKEY_CTX_free(evp_pkey_parameters_ctx);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    if (key_p != NULL)
        memory_secure_free(key_p);

    if (key_g != NULL)
        memory_secure_free(key_g);

#else
    DH_free(dh);
    BN_free(bn_p);
    BN_free(bn_g);
#endif
    return status;
}
