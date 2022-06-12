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
#include "porting/memory.h"
#include "stored_key_internal.h"
#include <openssl/dh.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#include <openssl/evp.h>
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

static bool bn_export(
        void* out,
        size_t out_length,
        const BIGNUM* bn) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (bn == NULL) {
        ERROR("NULL bn");
        return false;
    }

    memory_memset_unoptimizable(out, 0, out_length);
    uint8_t* out_bytes = (uint8_t*) out;

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    BN_bn2nativepad(bn, out_bytes, (int) out_length);
#else
    size_t written = BN_num_bytes(bn);
    if (written > out_length) {
        ERROR("Bad out_length");
        return false;
    }

    BN_bn2bin(bn, out_bytes + out_length - written);
#endif

    return true;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
static EVP_PKEY* dh_load(
        const void* private,
        const void* public,
        const void* p,
        size_t p_length,
        const void* g,
        size_t g_length) {

    bool status = false;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    uint8_t* key_p = NULL;
    uint8_t* key_g = NULL;
    do {
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
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, (unsigned char*) private, p_length),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, (unsigned char*) public, p_length),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, key_p, p_length),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, key_g, g_length),
                OSSL_PARAM_construct_end()};

        evp_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
        if (evp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new_id failed");
            break;
        }

        if (EVP_PKEY_fromdata_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_fromdata_init failed");
            break;
        }

        if (EVP_PKEY_fromdata(evp_pkey_ctx, &evp_pkey, EVP_PKEY_KEYPAIR, params) != 1) {
            ERROR("EVP_PKEY_fromdata failed");
            break;
        }

        status = true;
    } while (false);

    if (key_p != NULL)
        memory_secure_free(key_p);

    if (key_g != NULL)
        memory_secure_free(key_g);

    EVP_PKEY_CTX_free(evp_pkey_ctx);
    if (!status)
        EVP_PKEY_free(evp_pkey);

    return evp_pkey;
}
#else
static DH* dh_load(
        const void* private,
        const void* p,
        size_t p_length,
        const void* g,
        size_t g_length) {

    if (p == NULL) {
        ERROR("NULL p");
        return NULL;
    }

    if (g == NULL) {
        ERROR("NULL g");
        return NULL;
    }

    if (p_length > DH_MAX_MOD_SIZE || p_length == 0 || g_length > DH_MAX_MOD_SIZE || g_length == 0) {
        ERROR("Bad length");
        return NULL;
    }

    bool status = false;
    DH* dh = NULL;
    BIGNUM* bn_private = NULL;
    BIGNUM* bn_p = NULL;
    BIGNUM* bn_g = NULL;
    do {
        dh = DH_new();
        if (dh == NULL) {
            ERROR("DH_new failed");
            break;
        }

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

        // set private if passed in
        if (private != NULL) {
            bn_private = BN_bin2bn(private, (int) p_length, NULL);
            if (bn_private == NULL) {
                ERROR("BN_bin2bn failed");
                break;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            dh->priv_key = bn_private;
#else
            if (!DH_set0_key(dh, NULL, bn_private)) {
                ERROR("DH_set0_key failed");
                break;
            }
#endif
            // at this point ownership of bns is passed to dh
            bn_private = NULL;

            // compute public
            if (!DH_generate_key(dh)) {
                ERROR("DH_generate_key failed");
                break;
            }
        }

        status = true;
    } while (false);

    BN_free(bn_private);
    BN_free(bn_p);
    BN_free(bn_g);

    if (!status) {
        DH_free(dh);
        dh = NULL;
    }

    return dh;
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
    do {
        const uint8_t* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        // pub is at the offset stored_key->hdr.size
        memcpy(out, key + header->size, header->size);
        *out_length = header->size;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        swap_native_binary(out, *out_length);
#endif

        status = true;
    } while (false);

    return status;
}

bool dh_generate(
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
        ERROR("Bad length");
        return false;
    }

    if (g_length < 1 || g_length > p_length) {
        ERROR("Bad p_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    bool status = false;
    uint8_t* key = NULL;
    size_t key_length = p_length * 2;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY* evp_pkey_parameters = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    EVP_PKEY_CTX* evp_pkey_parameters_ctx = NULL;
    BIGNUM* bn_private = NULL;
    BIGNUM* bn_public = NULL;
    uint8_t* key_p = NULL;
    uint8_t* key_g = NULL;
    do {
        key = memory_secure_alloc(key_length);
        if (key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(key, 0, key_length);

        uint8_t* private = key;
        uint8_t* public = private + p_length;

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

        if (EVP_PKEY_get_bn_param(evp_pkey, "priv", &bn_private) != 1) {
            ERROR("EVP_PKEY_get_bn_param failed");
            break;
        }

        if (EVP_PKEY_get_bn_param(evp_pkey, "pub", &bn_public) != 1) {
            ERROR("EVP_PKEY_get_bn_param failed");
            break;
        }

        if (!bn_export(private, p_length, bn_private)) {
            ERROR("bn_export failed");
            break;
        }

        if (!bn_export(public, p_length, bn_public)) {
            ERROR("bn_export failed");
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

    EVP_PKEY_free(evp_pkey_parameters);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_parameters_ctx);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    BN_free(bn_private);
    BN_free(bn_public);
    if (key_p != NULL)
        memory_secure_free(key_p);

    if (key_g != NULL)
        memory_secure_free(key_g);
#else
    DH* dh = NULL;
    do {
        key = memory_secure_alloc(key_length);
        if (key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(key, 0, key_length);

        uint8_t* private = key;
        uint8_t* public = private + p_length;

        dh = dh_load(NULL, p, p_length, g, g_length);
        if (dh == NULL) {
            ERROR("dh_load failed");
            break;
        }

        if (!DH_generate_key(dh)) {
            ERROR("DH_generate_key failed");
            break;
        }

        const BIGNUM* bn_public = NULL;
        const BIGNUM* bn_private = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        bn_public = dh->pub_key;
        bn_private = dh->priv_key;
#else
        DH_get0_key(dh, &bn_public, &bn_private);
#endif

        if (!bn_export(private, p_length, bn_private)) {
            ERROR("bn_export failed");
            break;
        }

        if (!bn_export(public, p_length, bn_public)) {
            ERROR("bn_export failed");
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

    DH_free(dh);
#endif
    return status;
}

bool dh_compute(
        stored_key_t** shared_secret,
        const sa_rights* rights,
        const void* other_public,
        size_t other_public_length,
        const stored_key_t* stored_key_private) {

    if (shared_secret == NULL) {
        ERROR("NULL shared_secret");
        return false;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
        return false;
    }

    if (stored_key_private == NULL) {
        ERROR("NULL stored_key_private");
        return false;
    }

    if (other_public_length > DH_MAX_MOD_SIZE || other_public_length == 0) {
        ERROR("Bad other_public_length");
        return false;
    }

    bool status = false;
    uint8_t* temp = NULL;
    uint8_t* shared_secret_bytes = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY* other_evp_pkey = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* other_evp_pkey_ctx = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    uint8_t* key_p = NULL;
    uint8_t* key_g = NULL;
#else
    BIGNUM* bn_other_public = NULL;
#endif
    do {
        temp = memory_secure_alloc(DH_MAX_MOD_SIZE);
        if (temp == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_private);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        size_t modulus_size = header->size;
        size_t key_length = stored_key_get_length(stored_key_private);
        if (key_length != (modulus_size * 2)) {
            ERROR("Bad dh priv key");
            break;
        }

        if (other_public_length != modulus_size) {
            ERROR("Bad other_public_length");
            break;
        }

        const uint8_t* private = stored_key_get_key(stored_key_private);
        if (private == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        shared_secret_bytes = memory_secure_alloc(DH_MAX_MOD_SIZE);
        if (shared_secret_bytes == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER >= 0x30000000

        key_p = memory_secure_alloc(header->type_parameters.dh_parameters.p_length);
        if (key_p == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(key_p, 0, header->type_parameters.dh_parameters.p_length);

        key_g = memory_secure_alloc(header->type_parameters.dh_parameters.g_length);
        if (key_g == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(key_g, 0, header->type_parameters.dh_parameters.g_length);

        memcpy(key_p, header->type_parameters.dh_parameters.p, header->type_parameters.dh_parameters.p_length);
        swap_native_binary(key_p, header->type_parameters.dh_parameters.p_length);
        memcpy(key_g, header->type_parameters.dh_parameters.g, header->type_parameters.dh_parameters.g_length);
        swap_native_binary(key_g, header->type_parameters.dh_parameters.g_length);

        other_evp_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
        if (other_evp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new_id failed");
            break;
        }

        if (EVP_PKEY_fromdata_init(other_evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_fromdata_init failed");
            break;
        }

        memcpy(temp, other_public, other_public_length);
        swap_native_binary(temp, other_public_length);
        OSSL_PARAM other_params[] = {
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, (unsigned char*) temp, other_public_length),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, key_p, header->type_parameters.dh_parameters.p_length),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, key_g, header->type_parameters.dh_parameters.g_length),
                OSSL_PARAM_construct_end()};

        if (EVP_PKEY_fromdata(other_evp_pkey_ctx, &other_evp_pkey, EVP_PKEY_PUBLIC_KEY, other_params) != 1) {
            ERROR("EVP_PKEY_fromdata failed");
            break;
        }

        const uint8_t* public = private + modulus_size;
        evp_pkey = dh_load(private, public,
                header->type_parameters.dh_parameters.p, header->type_parameters.dh_parameters.p_length,
                header->type_parameters.dh_parameters.g, header->type_parameters.dh_parameters.g_length);
        if (evp_pkey == NULL) {
            ERROR("dh_load failed");
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

        if (EVP_PKEY_CTX_set_dh_pad(evp_pkey_ctx, 1) != 1) {
            ERROR("EVP_PKEY_CTX_set_dh_pad failed");
            return false;
        }

        if (EVP_PKEY_derive_set_peer(evp_pkey_ctx, other_evp_pkey) != 1) {
            ERROR("EVP_PKEY_derive_set_peer failed");
            break;
        }

        size_t written = DH_MAX_MOD_SIZE;
        if (EVP_PKEY_derive(evp_pkey_ctx, shared_secret_bytes, &written) != 1) {
            ERROR("EVP_PKEY_derive failed");
            break;
        }
#else
        DH* dh = dh_load(private,
                header->type_parameters.dh_parameters.p, header->type_parameters.dh_parameters.p_length,
                header->type_parameters.dh_parameters.g, header->type_parameters.dh_parameters.g_length);
        if (dh == NULL) {
            ERROR("dh_load failed");
            break;
        }

        bn_other_public = BN_bin2bn(other_public, (int) other_public_length, NULL);
        if (bn_other_public == NULL) {
            ERROR("BN_bin2bn failed");
            break;
        }

        int written = DH_compute_key_padded(shared_secret_bytes, bn_other_public, dh);
        DH_free(dh);
        if (written <= 0) {
            ERROR("DH_compute_key failed");
            break;
        }
#endif

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(shared_secret, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                modulus_size, shared_secret_bytes, modulus_size);
        if (!status) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (temp != NULL) {
        memory_memset_unoptimizable(temp, 0, DH_MAX_MOD_SIZE);
        memory_secure_free(temp);
    }

    if (shared_secret_bytes != NULL) {
        memory_memset_unoptimizable(shared_secret_bytes, 0, DH_MAX_MOD_SIZE);
        memory_secure_free(shared_secret_bytes);
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY_CTX_free(other_evp_pkey_ctx);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_free(other_evp_pkey);
    if (key_p != NULL)
        memory_secure_free(key_p);

    if (key_g != NULL)
        memory_secure_free(key_g);
#else
    BN_free(bn_other_public);
#endif

    return status;
}
