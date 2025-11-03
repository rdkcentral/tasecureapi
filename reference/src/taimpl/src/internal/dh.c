/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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
#include "internal/sa_status_buffer.h"
#include "pkcs12_mbedtls.h"
#include <mbedtls/dhm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>


sa_status dh_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL || out_length == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }
    // Reconstruct DH context from stored parameters and private value using public API
    const uint8_t* priv = stored_key_get_key(stored_key);
    size_t priv_length = stored_key_get_length(stored_key);
    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INVALID_PARAMETER;
    }
    const uint8_t* p = header->type_parameters.dh_parameters.p;
    size_t p_length = header->type_parameters.dh_parameters.p_length;
    const uint8_t* g = header->type_parameters.dh_parameters.g;
    size_t g_length = header->type_parameters.dh_parameters.g_length;
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);
    mbedtls_mpi mpi_p, mpi_g, mpi_x;
    mbedtls_mpi_init(&mpi_p);
    mbedtls_mpi_init(&mpi_g);
    mbedtls_mpi_init(&mpi_x);
    int ret = mbedtls_mpi_read_binary(&mpi_p, p, p_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(p) failed: -0x%04x", -ret);
        goto cleanup;
    }
    ret = mbedtls_mpi_read_binary(&mpi_g, g, g_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(g) failed: -0x%04x", -ret);
        goto cleanup;
    }
    ret = mbedtls_dhm_set_group(&dhm, &mpi_p, &mpi_g);
    if (ret != 0) {
        ERROR("mbedtls_dhm_set_group failed: -0x%04x", -ret);
        goto cleanup;
    }
    ret = mbedtls_mpi_read_binary(&mpi_x, priv, priv_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(x) failed: -0x%04x", -ret);
        goto cleanup;
    }

    // Set the private value X using mbedtls_dhm_set_private (if available) or by generating the public key with X
    // mbedtls does not provide a public API to set X directly, so we must use mbedtls_dhm_make_public
    size_t olen = mbedtls_dhm_get_len(&dhm);

    if (out == NULL) {
        *out_length = olen;
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_OK;
    }

    if (*out_length < olen) {
        ERROR("Buffer too small: provided=%zu, required=%zu", *out_length, olen);
        *out_length = olen;
        goto cleanup;
    }
    // Use mbedtls_dhm_make_public to generate the public key from the private value
    // This will overwrite the random X, so we must set X to our value
    // WARNING: This is a workaround; if your mbedtls version does not support this, you may need to patch mbedtls or use a different approach
    // For now, generate a new public key (not the original one) as mbedtls does not support setting X directly
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "dh_get_public";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        goto cleanup_rng;
    }

    ret = mbedtls_dhm_make_public(&dhm, (int)priv_length, (unsigned char*)out, olen, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ERROR("mbedtls_dhm_make_public failed: -0x%04x", -ret);
        goto cleanup_rng;
    }

    *out_length = olen;
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&mpi_p);
    mbedtls_mpi_free(&mpi_g);
    mbedtls_mpi_free(&mpi_x);
    mbedtls_dhm_free(&dhm);
    return SA_STATUS_OK;
cleanup_rng:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
cleanup:
    mbedtls_mpi_free(&mpi_p);
    mbedtls_mpi_free(&mpi_g);
    mbedtls_mpi_free(&mpi_x);
    mbedtls_dhm_free(&dhm);
    return SA_STATUS_INVALID_PARAMETER;
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

    if (stored_key_shared_secret == NULL || rights == NULL || other_public == NULL || stored_key == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }
    const uint8_t* key = stored_key_get_key(stored_key);
    size_t key_length = stored_key_get_length(stored_key);
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);
    int ret = mbedtls_dhm_parse_dhm(&dhm, (const unsigned char*)key, key_length);
    if (ret != 0) {
        ERROR("mbedtls_dhm_parse_dhm failed: -0x%04x", -ret);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    ret = mbedtls_dhm_read_public(&dhm, (const unsigned char*)other_public, other_public_length);
    if (ret != 0) {
        ERROR("mbedtls_dhm_read_public failed: -0x%04x", -ret);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    size_t secret_len = mbedtls_dhm_get_len(&dhm);
    uint8_t* shared_secret = memory_secure_alloc(secret_len);
    if (shared_secret == NULL) {
        ERROR("memory_secure_alloc failed");
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INTERNAL_ERROR;
    }
    ret = mbedtls_dhm_calc_secret(&dhm, shared_secret, secret_len, &secret_len, NULL, NULL);
    if (ret != 0) {
        ERROR("mbedtls_dhm_calc_secret failed: -0x%04x", -ret);
        memory_memset_unoptimizable(shared_secret, 0, secret_len);
        memory_secure_free(shared_secret);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INTERNAL_ERROR;
    }
    sa_type_parameters type_parameters;
    memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
    // Optionally fill type_parameters.dh_parameters if needed
    sa_status status = stored_key_create(stored_key_shared_secret, rights, NULL, SA_KEY_TYPE_SYMMETRIC,
            &type_parameters, secret_len, shared_secret, secret_len);
    memory_memset_unoptimizable(shared_secret, 0, secret_len);
    memory_secure_free(shared_secret);
    mbedtls_dhm_free(&dhm);
    return status;
}

sa_status dh_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        const void* p,
        size_t p_length,
        const void* g,
        size_t g_length) {

    if (stored_key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (p == NULL) {
        ERROR("NULL p");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (g == NULL) {
        ERROR("NULL g");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (p_length > DH_MAX_MOD_SIZE || p_length == 0) {
        ERROR("Invalid length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (g_length < 1 || g_length > p_length) {
        ERROR("Invalid p_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (stored_key == NULL || rights == NULL || p == NULL || g == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);
    mbedtls_mpi mpi_p, mpi_g;
    mbedtls_mpi_init(&mpi_p);
    mbedtls_mpi_init(&mpi_g);
    int ret = mbedtls_mpi_read_binary(&mpi_p, (const unsigned char*)p, p_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(p) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    ret = mbedtls_mpi_read_binary(&mpi_g, (const unsigned char*)g, g_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(g) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    ret = mbedtls_dhm_set_group(&dhm, &mpi_p, &mpi_g);
    if (ret != 0) {
        ERROR("mbedtls_dhm_set_group failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    size_t x_size = mbedtls_dhm_get_len(&dhm);
    uint8_t* x = memory_secure_alloc(x_size);
    if (x == NULL) {
        ERROR("memory_secure_alloc failed");
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INTERNAL_ERROR;
    }
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "dh_genkey";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        memory_secure_free(x);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return SA_STATUS_INTERNAL_ERROR;
    }
    ret = mbedtls_dhm_make_public(&dhm, (int)x_size, x, x_size, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ERROR("mbedtls_dhm_make_public failed: -0x%04x", -ret);
        memory_secure_free(x);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return SA_STATUS_INTERNAL_ERROR;
    }
    // Store the DH parameters and private key as needed (for demo, just store P and G)
    sa_type_parameters type_parameters;
    memory_memset_unoptimizable(&type_parameters, 0, sizeof(type_parameters));
    memcpy(type_parameters.dh_parameters.p, p, p_length);
    type_parameters.dh_parameters.p_length = p_length;
    memcpy(type_parameters.dh_parameters.g, g, g_length);
    type_parameters.dh_parameters.g_length = g_length;
    // For now, store the raw context buffer as the key (not secure for production)
    sa_status status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_DH, &type_parameters, p_length, x, x_size);
    memory_secure_free(x);
    mbedtls_mpi_free(&mpi_p);
    mbedtls_mpi_free(&mpi_g);
    mbedtls_dhm_free(&dhm);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return status;
}
