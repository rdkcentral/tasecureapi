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

#include "rsa.h" // NOLINT
#include "digest_util.h"
#include "digest_util_mbedtls.h"
#include "log.h"
#include "pkcs8.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include "pkcs12_mbedtls.h"
#include <memory.h>

/*
 * ============================================================================
 * CUSTOM RSA OAEP IMPLEMENTATION WITH DUAL HASH SUPPORT
 * ============================================================================
 * 
 * Background:
 * mbedTLS 2.16.10 only supports a single hash algorithm for both OAEP and MGF1
 * via the ctx->hash_id field. However, PKCS#1 v2.1 allows different hash
 * algorithms for OAEP label hashing and MGF1 mask generation.
 * 
 * This custom implementation is copied from mbedTLS 2.16.10 rsa.c and modified
 * to support separate OAEP hash and MGF1 hash parameters.
 * 
 * Source: mbedTLS 2.16.10 library/rsa.c
 * Functions: mgf_mask(), mbedtls_rsa_rsaes_oaep_decrypt()
 * Modified: Added separate hash parameters for OAEP and MGF1
 * 
 * Rationale:
 * While this enables full PKCS#1 v2.1 compliance in software, note that
 * hardware crypto accelerators in OP-TEE 3.18 deployments may still have
 * the same limitation. This implementation is primarily for testing and
 * validation purposes.
 * ============================================================================
 */

/**
 * Custom MGF1 mask generation function (copied from mbedTLS 2.16.10)
 * 
 * This is a direct copy of the static mgf_mask function from mbedTLS rsa.c.
 * No modifications needed - it accepts a pre-configured md_ctx.
 */
static int custom_mgf_mask(unsigned char *dst, size_t dlen, unsigned char *src,
                           size_t slen, mbedtls_md_context_t *md_ctx)
{
    unsigned char mask[MBEDTLS_MD_MAX_SIZE];
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;
    int ret = 0;

    memset(mask, 0, MBEDTLS_MD_MAX_SIZE);
    memset(counter, 0, 4);

    hlen = mbedtls_md_get_size(md_ctx->md_info);

    /* Generate and apply mask */
    p = dst;

    while (dlen > 0) {
        use_len = hlen;
        if (dlen < hlen)
            use_len = dlen;

        if ((ret = mbedtls_md_starts(md_ctx)) != 0)
            goto exit;
        if ((ret = mbedtls_md_update(md_ctx, src, slen)) != 0)
            goto exit;
        if ((ret = mbedtls_md_update(md_ctx, counter, 4)) != 0)
            goto exit;
        if ((ret = mbedtls_md_finish(md_ctx, mask)) != 0)
            goto exit;

        for (i = 0; i < use_len; ++i)
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }

exit:
    mbedtls_platform_zeroize(mask, sizeof(mask));

    return ret;
}

/**
 * Custom RSA OAEP decrypt with separate OAEP and MGF1 hash support
 * 
 * Based on mbedtls_rsa_rsaes_oaep_decrypt from mbedTLS 2.16.10, modified to
 * accept separate hash algorithms for OAEP label hashing and MGF1.
 * 
 * @param ctx              RSA context
 * @param f_rng           RNG function (for blinding)
 * @param p_rng           RNG context
 * @param oaep_hash_id    Hash algorithm for OAEP label hashing
 * @param mgf1_hash_id    Hash algorithm for MGF1 mask generation
 * @param label           Optional label
 * @param label_len       Label length
 * @param olen            Output length (returned)
 * @param input           Ciphertext
 * @param output          Plaintext output buffer
 * @param output_max_len  Maximum output buffer size
 * @return                0 on success, error code otherwise
 */
static int custom_rsa_oaep_decrypt_dual_hash(
        mbedtls_rsa_context *ctx,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng,
        mbedtls_md_type_t oaep_hash_id,
        mbedtls_md_type_t mgf1_hash_id,
        const unsigned char *label,
        size_t label_len,
        size_t *olen,
        const unsigned char *input,
        unsigned char *output,
        size_t output_max_len)
{
    int ret;
    size_t ilen, i, pad_len;
    unsigned char *p, bad, pad_done;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    unsigned char lhash[MBEDTLS_MD_MAX_SIZE];
    unsigned int oaep_hlen;
    const mbedtls_md_info_t *oaep_md_info;
    const mbedtls_md_info_t *mgf1_md_info;
    mbedtls_md_context_t mgf1_md_ctx;

    if (ctx == NULL || input == NULL || olen == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    
    if (output_max_len > 0 && output == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    
    if (label_len > 0 && label == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    /*
     * Get hash information for both OAEP and MGF1
     */
    oaep_md_info = mbedtls_md_info_from_type(oaep_hash_id);
    if (oaep_md_info == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mgf1_md_info = mbedtls_md_info_from_type(mgf1_hash_id);
    if (mgf1_md_info == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    oaep_hlen = mbedtls_md_get_size(oaep_md_info);

    ilen = ctx->len;

    if (ilen < 16 || ilen > sizeof(buf))
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    /*
     * Note: We use the OAEP hash length for padding structure validation
     * because the OAEP hash determines the DB structure, not MGF1
     */
    if (2 * oaep_hlen + 2 > ilen)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    /*
     * RSA operation - decrypt the ciphertext
     */
    ret = mbedtls_rsa_private(ctx, f_rng, p_rng, input, buf);
    if (ret != 0)
        goto cleanup;

    /*
     * Unmask data using MGF1 with the specified MGF1 hash
     */
    mbedtls_md_init(&mgf1_md_ctx);
    if ((ret = mbedtls_md_setup(&mgf1_md_ctx, mgf1_md_info, 0)) != 0) {
        mbedtls_md_free(&mgf1_md_ctx);
        goto cleanup;
    }

    /*
     * The unmasking uses the MGF1 hash and the structure defined by OAEP hash.
     * Note: buf structure is: 0x00 || maskedSeed || maskedDB
     * where len(maskedSeed) = oaep_hlen, len(maskedDB) = ilen - oaep_hlen - 1
     */

    /* seed: Apply seedMask to maskedSeed using MGF1 hash */
    if ((ret = custom_mgf_mask(buf + 1, oaep_hlen, buf + oaep_hlen + 1, 
                               ilen - oaep_hlen - 1, &mgf1_md_ctx)) != 0) {
        mbedtls_md_free(&mgf1_md_ctx);
        goto cleanup;
    }

    /* DB: Apply dbMask to maskedDB using MGF1 hash */
    if ((ret = custom_mgf_mask(buf + oaep_hlen + 1, ilen - oaep_hlen - 1, 
                               buf + 1, oaep_hlen, &mgf1_md_ctx)) != 0) {
        mbedtls_md_free(&mgf1_md_ctx);
        goto cleanup;
    }

    mbedtls_md_free(&mgf1_md_ctx);

    /*
     * Generate lHash using OAEP hash
     */
    if ((ret = mbedtls_md(oaep_md_info, label, label_len, lhash)) != 0)
        goto cleanup;

    /*
     * Check contents in constant-time
     * Structure after unmasking: 0x00 || seed || lHash || PS || 0x01 || M
     */
    p = buf;
    bad = 0;

    bad |= *p++; /* First byte must be 0 */

    p += oaep_hlen; /* Skip seed */

    /* Check lHash */
    for (i = 0; i < oaep_hlen; i++)
        bad |= lhash[i] ^ *p++;

    /* Get zero-padding len, but always read till end of buffer
     * (minus one, for the 0x01 byte) */
    pad_len = 0;
    pad_done = 0;
    for (i = 0; i < ilen - 2 * oaep_hlen - 2; i++) {
        pad_done |= p[i];
        pad_len += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
    if (bad != 0) {
        ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
        goto cleanup;
    }

    if (ilen - (p - buf) > output_max_len) {
        ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
        goto cleanup;
    }

    *olen = ilen - (p - buf);
    memcpy(output, p, *olen);
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    mbedtls_platform_zeroize(lhash, sizeof(lhash));

    return ret;
}

/*
 * ============================================================================
 * END OF CUSTOM RSA OAEP IMPLEMENTATION
 * ============================================================================
 */

/*
 * ============================================================================
 * CUSTOM RSA PSS IMPLEMENTATION WITH DUAL HASH SUPPORT
 * ============================================================================
 * 
 * Background:
 * mbedTLS 2.16.10 only supports a single hash algorithm for both PSS message
 * hashing and MGF1 mask generation via the ctx->hash_id field. However, 
 * PKCS#1 v2.1 allows different hash algorithms for these operations, and also
 * allows custom salt lengths.
 * 
 * This custom implementation is copied from mbedTLS 2.16.10 rsa.c and modified
 * to support:
 * 1. Separate PSS hash and MGF1 hash parameters
 * 2. Custom salt length specification
 * 
 * Source: mbedTLS 2.16.10 library/rsa.c
 * Function: mbedtls_rsa_rsassa_pss_sign() (lines 1822-1935)
 * Modified: Added pss_hash_id, mgf1_hash_id, and custom_salt_len parameters
 * 
 * Rationale:
 * While this enables full PKCS#1 v2.1 compliance in software, note that
 * hardware crypto accelerators in OP-TEE 3.18 deployments may still have
 * the same limitation. This implementation is primarily for testing and
 * validation purposes.
 * ============================================================================
 */

/**
 * Custom RSA PSS sign function with dual hash support
 * 
 * This function is based on mbedtls_rsa_rsassa_pss_sign() but accepts separate
 * hash algorithms for PSS encoding and MGF1, plus custom salt length.
 * 
 * @param ctx           RSA context (must be initialized)
 * @param f_rng         RNG function (required for salt generation)
 * @param p_rng         RNG parameter
 * @param mode          MBEDTLS_RSA_PRIVATE or MBEDTLS_RSA_PUBLIC
 * @param pss_hash_id   Hash algorithm for PSS encoding (H in EMSA-PSS)
 * @param mgf1_hash_id  Hash algorithm for MGF1 mask generation
 * @param custom_salt_len Custom salt length (-1 for automatic/hash length)
 * @param hashlen       Length of the hash to sign
 * @param hash          Buffer holding the message hash
 * @param sig           Buffer that will hold the signature (must be ctx->len bytes)
 * 
 * @return 0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 */
static int custom_rsa_pss_sign_dual_hash(
        mbedtls_rsa_context *ctx,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng,
        int mode,
        mbedtls_md_type_t pss_hash_id,
        mbedtls_md_type_t mgf1_hash_id,
        int custom_salt_len,
        unsigned int hashlen,
        const unsigned char *hash,
        unsigned char *sig)
{
    size_t olen;
    unsigned char *p = sig;
    unsigned char *salt = NULL;
    size_t slen, min_slen, hlen, offset = 0;
    int ret;
    size_t msb;
    const mbedtls_md_info_t *pss_md_info;
    const mbedtls_md_info_t *mgf1_md_info;
    mbedtls_md_context_t md_ctx;

    if (ctx == NULL || sig == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if (mode != MBEDTLS_RSA_PRIVATE && mode != MBEDTLS_RSA_PUBLIC)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if (hash == NULL && hashlen != 0)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if (mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if (f_rng == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    olen = ctx->len;

    // Get PSS hash info (for H in EMSA-PSS encoding)
    pss_md_info = mbedtls_md_info_from_type(pss_hash_id);
    if (pss_md_info == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    hlen = mbedtls_md_get_size(pss_md_info);

    // Get MGF1 hash info (for mask generation)
    mgf1_md_info = mbedtls_md_info_from_type(mgf1_hash_id);
    if (mgf1_md_info == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    // Determine salt length
    if (custom_salt_len < 0) {
        // Automatic: use hash length as salt length (standard behavior)
        // Calculate the largest possible salt length. Normally this is the hash
        // length, which is the maximum length the salt can have. If there is not
        // enough room, use the maximum salt length that fits. The constraint is
        // that the hash length plus the salt length plus 2 bytes must be at most
        // the key length. This complies with FIPS 186-4 §5.5 (e) and RFC 8017
        // (PKCS#1 v2.2) §9.1.1 step 3.
        min_slen = hlen - 2;
        if (olen < hlen + min_slen + 2)
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        else if (olen >= hlen + hlen + 2)
            slen = hlen;
        else
            slen = olen - hlen - 2;
    } else {
        // Custom salt length specified
        slen = (size_t)custom_salt_len;
        
        // Validate salt length fits in the RSA modulus
        if (olen < hlen + slen + 2)
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    INFO("custom_rsa_pss_sign_dual_hash: olen=%zu, hlen=%zu, slen=%zu, MBEDTLS_MD_MAX_SIZE=%d", 
         olen, hlen, slen, MBEDTLS_MD_MAX_SIZE);

    // Allocate salt buffer dynamically since slen can exceed MBEDTLS_MD_MAX_SIZE
    salt = mbedtls_calloc(1, slen);
    if (salt == NULL)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    memset(sig, 0, olen);

    // Generate salt of length slen
    INFO("custom_rsa_pss_sign_dual_hash: Generating %zu bytes of salt", slen);
    if ((ret = f_rng(p_rng, salt, slen)) != 0) {
        ret = MBEDTLS_ERR_RSA_RNG_FAILED + ret;
        goto cleanup;
    }
    INFO("custom_rsa_pss_sign_dual_hash: Salt generated successfully");

    // Note: EMSA-PSS encoding is over the length of N - 1 bits
    msb = mbedtls_mpi_bitlen(&ctx->N) - 1;
    p += olen - hlen - slen - 2;
    *p++ = 0x01;
    memcpy(p, salt, slen);
    p += slen;

    // Initialize MD context with PSS hash (for H = Hash(M'))
    mbedtls_md_init(&md_ctx);
    if ((ret = mbedtls_md_setup(&md_ctx, pss_md_info, 0)) != 0)
        goto cleanup;

    // Generate H = Hash(M') where M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    // The 8 zero bytes are at the beginning of the sig buffer (which was memset to 0)
    unsigned char zeros[8] = {0};
    if ((ret = mbedtls_md_starts(&md_ctx)) != 0)
        goto cleanup;
    if ((ret = mbedtls_md_update(&md_ctx, zeros, 8)) != 0)  // 8 zero bytes
        goto cleanup;
    if ((ret = mbedtls_md_update(&md_ctx, hash, hashlen)) != 0)  // mHash
        goto cleanup;
    if ((ret = mbedtls_md_update(&md_ctx, salt, slen)) != 0)  // salt
        goto cleanup;
    if ((ret = mbedtls_md_finish(&md_ctx, p)) != 0)  // Output H
        goto cleanup;

    // Free PSS hash context and reinitialize with MGF1 hash
    mbedtls_md_free(&md_ctx);
    mbedtls_md_init(&md_ctx);
    if ((ret = mbedtls_md_setup(&md_ctx, mgf1_md_info, 0)) != 0)
        goto cleanup;

    // Compensate for boundary condition when applying mask
    if (msb % 8 == 0)
        offset = 1;

    // maskedDB: Apply dbMask to DB using MGF1 with mgf1_hash_id
    // Uses custom_mgf_mask which accepts the MGF1-configured md_ctx
    if ((ret = custom_mgf_mask(sig + offset, olen - hlen - 1 - offset, p, hlen, &md_ctx)) != 0)
        goto cleanup;

    msb = mbedtls_mpi_bitlen(&ctx->N) - 1;
    sig[0] &= 0xFF >> (olen * 8 - msb);

    p += hlen;
    *p++ = 0xBC;

cleanup:
    if (salt != NULL) {
        mbedtls_platform_zeroize(salt, slen);
        mbedtls_free(salt);
    }
    mbedtls_md_free(&md_ctx);

    if (ret != 0)
        return ret;

    INFO("custom_rsa_pss_sign_dual_hash: Before RSA private operation (mode=%d)", mode);
    return (mode == MBEDTLS_RSA_PUBLIC)
            ? mbedtls_rsa_public(ctx, sig, sig)
            : mbedtls_rsa_private(ctx, f_rng, p_rng, sig, sig);
}

/*
 * ============================================================================
 * END OF CUSTOM RSA PSS IMPLEMENTATION
 * ============================================================================
 */

size_t rsa_validate_private(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    mbedtls_pk_context* pk = pk_from_pkcs8(MBEDTLS_PK_RSA, in, in_length);
    if (pk == NULL) {
        ERROR("pk_from_pkcs8 failed");
        return 0;
    }

    size_t key_size = mbedtls_pk_get_bitlen(pk) / 8;
    mbedtls_pk_free(pk);
    free(pk);
    return key_size;
}

sa_status rsa_get_public(
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

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_pk_context* pk = NULL;
    uint8_t* temp_buffer = NULL;
    
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        pk = pk_from_pkcs8(MBEDTLS_PK_RSA, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        // Allocate maximum size buffer for RSA public key DER encoding
        // Maximum RSA key is 4096 bits which needs about 550 bytes in DER format
        size_t max_pubkey_size = 1024;
        temp_buffer = memory_secure_alloc(max_pubkey_size);
        if (temp_buffer == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // mbedTLS writes DER from the end of buffer backwards
        int written = mbedtls_pk_write_pubkey_der(pk, temp_buffer, max_pubkey_size);
        if (written < 0) {
            ERROR("mbedtls_pk_write_pubkey_der failed: -0x%04x", -written);
            break;
        }

        if (out == NULL) {
            *out_length = written;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < (size_t)written) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // Copy to output (data is at end of buffer)
        memcpy(out, temp_buffer + max_pubkey_size - written, written);
        *out_length = written;
        status = SA_STATUS_OK;
    } while (false);

    if (temp_buffer != NULL)
        memory_secure_free(temp_buffer);
    
    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    return status;
}

sa_status rsa_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        void* parameters,
        const stored_key_t* stored_key) {

    DEBUG("rsa_verify_cipher: algorithm %d, mode %d, stored_key %p", cipher_algorithm, cipher_mode, stored_key);

    if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
        if (parameters == NULL) {
            ERROR("NULL parameters");
            return SA_STATUS_NULL_PARAMETER;
        }
    }

    return SA_STATUS_OK;
}

sa_status rsa_decrypt_pkcs1v15(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_pk_context* pk = NULL;
    
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        pk = pk_from_pkcs8(MBEDTLS_PK_RSA, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        size_t key_size = mbedtls_pk_get_bitlen(pk) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        if (in_length != key_size) {
            ERROR("Invalid in_length");
            break;
        }

        // Get RSA context from PK context
        mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
        if (rsa == NULL) {
            ERROR("mbedtls_pk_rsa failed");
            break;
        }

        // Set padding mode
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0);

        // Perform RSA private decrypt
        if (mbedtls_rsa_pkcs1_decrypt(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, 
                                       out_length, in, out, *out_length) != 0) {
            status = SA_STATUS_VERIFICATION_FAILED;
            ERROR("mbedtls_rsa_pkcs1_decrypt failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    return status;
}

sa_status rsa_decrypt_oaep(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        sa_digest_algorithm digest_algorithm,
        sa_digest_algorithm mgf1_digest_algorithm,
        const void* label,
        size_t label_length,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_pk_context* pk = NULL;
    
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        pk = pk_from_pkcs8(MBEDTLS_PK_RSA, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        size_t key_size = mbedtls_pk_get_bitlen(pk) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        if (in_length != key_size) {
            ERROR("Invalid in_length");
            break;
        }

        // Get RSA context from PK context
        mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
        if (rsa == NULL) {
            ERROR("mbedtls_pk_rsa failed");
            break;
        }

        // Get mbedTLS hash ID
        mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
        mbedtls_md_type_t mgf1_md_type = digest_mechanism_mbedtls(mgf1_digest_algorithm);

        // Check if we need custom dual-hash OAEP or standard OAEP
        if (mgf1_md_type != md_type) {
            // Different MGF1 hash - use custom implementation with dual hash support
            if (custom_rsa_oaep_decrypt_dual_hash(rsa, NULL, NULL,
                                                   md_type, mgf1_md_type,
                                                   (const unsigned char*) label, label_length,
                                                   out_length,
                                                   (const unsigned char*) in,
                                                   (unsigned char*) out,
                                                   *out_length) != 0) {
                ERROR("custom_rsa_oaep_decrypt_dual_hash failed");
                status = SA_STATUS_VERIFICATION_FAILED;
                break;
            }
        } else {
            // Same hash for OAEP and MGF1 - use standard mbedTLS implementation
            mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md_type);
            
            if (mbedtls_rsa_rsaes_oaep_decrypt(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
                                               (const unsigned char*) label, label_length,
                                               out_length,
                                               (const unsigned char*) in,
                                               (unsigned char*) out,
                                               *out_length) != 0) {
                ERROR("mbedtls_rsa_rsaes_oaep_decrypt failed");
                status = SA_STATUS_VERIFICATION_FAILED;
                break;
            }
        }

        status = SA_STATUS_OK;
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    return status;
}

sa_status rsa_sign_pkcs1v15(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_pk_context* pk = NULL;
    uint8_t hash[MBEDTLS_MD_MAX_SIZE];
    size_t hash_length = 0;
    
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        pk = pk_from_pkcs8(MBEDTLS_PK_RSA, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        size_t key_size = mbedtls_pk_get_bitlen(pk) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        // Get mbedTLS hash type
        mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        // Compute or use precomputed hash
        if (precomputed_digest) {
            if (in_length > sizeof(hash)) {
                ERROR("Hash too large");
                break;
            }
            memcpy(hash, in, in_length);
            hash_length = in_length;
        } else {
            // Compute hash
            if (mbedtls_md(md_info, in, in_length, hash) != 0) {
                ERROR("mbedtls_md failed");
                break;
            }
            hash_length = mbedtls_md_get_size(md_info);
        }

        // Get RSA context
        mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
        if (rsa == NULL) {
            ERROR("mbedtls_pk_rsa failed");
            break;
        }

        // Set PKCS#1 v1.5 padding
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0);

        // Sign with PKCS#1 v1.5
        if (mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
                                    md_type, hash_length, hash, out) != 0) {
            ERROR("mbedtls_rsa_pkcs1_sign failed");
            break;
        }

        *out_length = key_size;
        status = SA_STATUS_OK;
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }

    return status;
}

sa_status rsa_sign_pss(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        sa_digest_algorithm mgf1_digest_algorithm,
        size_t salt_length,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_pk_context* pk = NULL;
    uint8_t hash[MBEDTLS_MD_MAX_SIZE];
    size_t hash_length = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    INFO("rsa_sign_pss: Starting");
    
    do {
        // Initialize RNG (needed for PSS salt generation)
        INFO("rsa_sign_pss: Before mbedtls_ctr_drbg_seed");
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char*) "rsa_pss_sign", 12) != 0) {
            ERROR("mbedtls_ctr_drbg_seed failed");
            break;
        }
        INFO("rsa_sign_pss: After mbedtls_ctr_drbg_seed");

        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        pk = pk_from_pkcs8(MBEDTLS_PK_RSA, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        size_t key_size = mbedtls_pk_get_bitlen(pk) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        // Get mbedTLS hash types
        mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
        mbedtls_md_type_t mgf1_md_type = digest_mechanism_mbedtls(mgf1_digest_algorithm);
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        // Compute or use precomputed hash
        if (precomputed_digest) {
            if (in_length > sizeof(hash)) {
                ERROR("Hash too large");
                break;
            }
            memcpy(hash, in, in_length);
            hash_length = in_length;
        } else {
            // Compute hash
            if (mbedtls_md(md_info, in, in_length, hash) != 0) {
                ERROR("mbedtls_md failed");
                break;
            }
            hash_length = mbedtls_md_get_size(md_info);
        }

        // Get RSA context
        mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
        if (rsa == NULL) {
            ERROR("mbedtls_pk_rsa failed");
            break;
        }

        // Check if we need custom dual-hash PSS or standard PSS
        // Use custom implementation when:
        // 1. MGF1 hash differs from PSS hash, OR
        // 2. Custom salt length specified (not automatic and not equal to hash length)
        bool need_custom_pss = (mgf1_md_type != md_type) ||
                               (salt_length != hash_length && (int)salt_length != MBEDTLS_RSA_SALT_LEN_ANY);

        if (need_custom_pss) {
            // Use custom PSS implementation with dual hash and custom salt support
            // Set padding mode (required for RSA context)
            mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md_type);

            // Determine salt length parameter for custom function
            int custom_salt_len = ((int)salt_length == MBEDTLS_RSA_SALT_LEN_ANY) ? -1 : (int)salt_length;

            INFO("rsa_sign_pss: Before custom_rsa_pss_sign_dual_hash");
            if (custom_rsa_pss_sign_dual_hash(rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                              MBEDTLS_RSA_PRIVATE,
                                              md_type,        // PSS hash
                                              mgf1_md_type,   // MGF1 hash
                                              custom_salt_len, // Salt length (-1 = auto)
                                              hash_length,
                                              hash,
                                              out) != 0) {
                ERROR("custom_rsa_pss_sign_dual_hash failed");
                status = SA_STATUS_VERIFICATION_FAILED;
                break;
            }
            INFO("rsa_sign_pss: After custom_rsa_pss_sign_dual_hash");
        } else {
            // Same hash for PSS and MGF1, automatic salt - use standard mbedTLS
            mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md_type);

            INFO("rsa_sign_pss: Before mbedtls_rsa_pkcs1_sign");
            if (mbedtls_rsa_pkcs1_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE,
                                        md_type, hash_length, hash, out) != 0) {
                ERROR("mbedtls_rsa_pkcs1_sign failed");
                status = SA_STATUS_VERIFICATION_FAILED;
                break;
            }
            INFO("rsa_sign_pss: After mbedtls_rsa_pkcs1_sign");
        }

        *out_length = key_size;
        status = SA_STATUS_OK;
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return status;
}

sa_status rsa_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_generate_parameters_rsa* parameters) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* key = NULL;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    size_t key_length = 0;
    
    do {
        // Initialize entropy and DRBG
        const char* pers = "rsa_keygen";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char*)pers, strlen(pers)) != 0) {
            ERROR("mbedtls_ctr_drbg_seed failed");
            break;
        }

        // Setup RSA context
        if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
            ERROR("mbedtls_pk_setup failed");
            break;
        }

        mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
        if (rsa == NULL) {
            ERROR("mbedtls_pk_rsa failed");
            break;
        }

        // Generate RSA key pair (using default exponent 65537)
        if (mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                (unsigned int)(parameters->modulus_length * 8), 65537) != 0) {
            ERROR("mbedtls_rsa_gen_key failed");
            break;
        }

        // Convert to PKCS#8 format
        if (!pk_to_pkcs8(NULL, &key_length, &pk)) {
            ERROR("pk_to_pkcs8 failed");
            break;
        }

        key = memory_secure_alloc(key_length);
        if (key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!pk_to_pkcs8(key, &key_length, &pk)) {
            ERROR("pk_to_pkcs8 failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(type_parameters));
        status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_RSA, &type_parameters,
                parameters->modulus_length, key, key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (key != NULL) {
        memory_memset_unoptimizable(key, 0, key_length);
        memory_secure_free(key);
    }

    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return status;
}
