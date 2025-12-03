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

#include "pkcs12_mbedtls.h"
#include <string.h>

#include "mbedtls_header.h"


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

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_mpi mpi_p, mpi_g, mpi_x, mpi_gx;
    mbedtls_mpi_init(&mpi_p);
    mbedtls_mpi_init(&mpi_g);
    mbedtls_mpi_init(&mpi_x);
    mbedtls_mpi_init(&mpi_gx);
    
    uint8_t* der_buffer = NULL;
    
    do {
        // Get the stored key parameters
        const uint8_t* key_data = stored_key_get_key(stored_key);
        size_t key_data_length = stored_key_get_length(stored_key);
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }
        
        const uint8_t* p = header->type_parameters.dh_parameters.p;
        size_t p_length = header->type_parameters.dh_parameters.p_length;
        const uint8_t* g = header->type_parameters.dh_parameters.g;
        size_t g_length = header->type_parameters.dh_parameters.g_length;

        // Extract X from stored key data (format: [p_length(4)][g_length(4)][x_length(4)][P][G][X])
        if (key_data_length < 12) {
            ERROR("Invalid key data length");
            break;
        }
        const uint32_t* lengths = (const uint32_t*)key_data;
        size_t stored_p_length = lengths[0];
        size_t stored_g_length = lengths[1];
        size_t x_length = lengths[2];
        
        if (key_data_length != 12 + stored_p_length + stored_g_length + x_length) {
            ERROR("Key data length mismatch");
            break;
        }
        
        const uint8_t* x = key_data + 12 + stored_p_length + stored_g_length;

        // Compute the public key using mbedTLS: GX = G^X mod P
        int ret = mbedtls_mpi_read_binary(&mpi_p, p, p_length);
        if (ret != 0) {
            ERROR("mbedtls_mpi_read_binary(p) failed: -0x%04x", -ret);
            break;
        }
        
        ret = mbedtls_mpi_read_binary(&mpi_g, g, g_length);
        if (ret != 0) {
            ERROR("mbedtls_mpi_read_binary(g) failed: -0x%04x", -ret);
            break;
        }
        
        ret = mbedtls_mpi_read_binary(&mpi_x, x, x_length);
        if (ret != 0) {
            ERROR("mbedtls_mpi_read_binary(x) failed: -0x%04x", -ret);
            break;
        }
        
        ret = mbedtls_mpi_exp_mod(&mpi_gx, &mpi_g, &mpi_x, &mpi_p, NULL);
        if (ret != 0) {
            ERROR("mbedtls_mpi_exp_mod failed: -0x%04x", -ret);
            break;
        }

        // Encode to DER format manually using mbedTLS ASN.1 functions
        // DER structure for DH public key (SubjectPublicKeyInfo):
        // SEQUENCE {
        //   SEQUENCE {
        //     OBJECT IDENTIFIER dhKeyAgreement (1.2.840.113549.1.3.1)
        //     SEQUENCE {
        //       INTEGER p
        //       INTEGER g
        //     }
        //   }
        //   BIT STRING {
        //     INTEGER public_key
        //   }
        // }
        
        // Allocate buffer for DER encoding (generous size estimate)
        size_t der_max_size = 1024 + p_length + g_length + mbedtls_mpi_size(&mpi_gx);
        der_buffer = memory_secure_alloc(der_max_size);
        if (der_buffer == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        
        // Write DER from the end of the buffer (mbedTLS writes backwards)
        unsigned char* c = der_buffer + der_max_size;
        size_t len = 0;
        
        // Step 1: Write the public key as INTEGER
        ret = mbedtls_asn1_write_mpi(&c, der_buffer, &mpi_gx);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_mpi(gx) failed: -0x%04x", -ret);
            break;
        }
        size_t pubkey_integer_len = ret;
        
        // Step 2: Add unused bits byte (0x00) before the INTEGER
        if (c - der_buffer < 1) {
            ERROR("Buffer overflow");
            break;
        }
        *(--c) = 0x00;
        size_t bitstring_content_len = pubkey_integer_len + 1;  // INTEGER + unused bits byte
        
        // Step 3: Write BIT STRING tag and length
        ret = mbedtls_asn1_write_len(&c, der_buffer, bitstring_content_len);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_len(bitstring) failed: -0x%04x", -ret);
            break;
        }
        size_t bitstring_len = ret + bitstring_content_len;
        
        ret = mbedtls_asn1_write_tag(&c, der_buffer, MBEDTLS_ASN1_BIT_STRING);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_tag(bitstring) failed: -0x%04x", -ret);
            break;
        }
        bitstring_len += ret;
        
        // Step 4: Write algorithm parameters (SEQUENCE { p, g })
        // Write g INTEGER
        ret = mbedtls_asn1_write_mpi(&c, der_buffer, &mpi_g);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_mpi(g) failed: -0x%04x", -ret);
            break;
        }
        size_t params_len = ret;
        
        // Write p INTEGER
        ret = mbedtls_asn1_write_mpi(&c, der_buffer, &mpi_p);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_mpi(p) failed: -0x%04x", -ret);
            break;
        }
        params_len += ret;
        
        // Write SEQUENCE tag/length for parameters
        ret = mbedtls_asn1_write_len(&c, der_buffer, params_len);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_len(params) failed: -0x%04x", -ret);
            break;
        }
        params_len += ret;
        
        ret = mbedtls_asn1_write_tag(&c, der_buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_tag(params seq) failed: -0x%04x", -ret);
            break;
        }
        params_len += ret;
        
        // Step 5: Write algorithm OID (dhKeyAgreement 1.2.840.113549.1.3.1)
        // OID value: 1.2.840.113549.1.3.1
        const char dh_oid_value[] = "\x2a\x86\x48\x86\xf7\x0d\x01\x03\x01";
        ret = mbedtls_asn1_write_oid(&c, der_buffer, dh_oid_value, 9);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_oid failed: -0x%04x", -ret);
            break;
        }
        size_t oid_len = ret;
        
        // Step 6: Write algorithm identifier SEQUENCE { OID, params }
        ret = mbedtls_asn1_write_len(&c, der_buffer, oid_len + params_len);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_len(alg) failed: -0x%04x", -ret);
            break;
        }
        size_t alg_len = ret + oid_len + params_len;
        
        ret = mbedtls_asn1_write_tag(&c, der_buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_tag(alg seq) failed: -0x%04x", -ret);
            break;
        }
        alg_len += ret;
        
        // Step 7: Write outer SEQUENCE { algorithm, publicKey }
        len = alg_len + bitstring_len;
        ret = mbedtls_asn1_write_len(&c, der_buffer, len);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_len(outer) failed: -0x%04x", -ret);
            break;
        }
        len += ret;
        
        ret = mbedtls_asn1_write_tag(&c, der_buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret < 0) {
            ERROR("mbedtls_asn1_write_tag(outer seq) failed: -0x%04x", -ret);
            break;
        }
        len += ret;

        // Return length if just querying
        if (out == NULL) {
            *out_length = len;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < len) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // Copy DER data to output
        memcpy(out, c, len);
        *out_length = len;
        status = SA_STATUS_OK;
    } while (false);

    if (der_buffer != NULL) {
        memory_secure_free(der_buffer);
    }
    
    mbedtls_mpi_free(&mpi_p);
    mbedtls_mpi_free(&mpi_g);
    mbedtls_mpi_free(&mpi_x);
    mbedtls_mpi_free(&mpi_gx);

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

    if (stored_key_shared_secret == NULL || rights == NULL || other_public == NULL || stored_key == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }
    
    // Get the stored key data which contains P, G, and X concatenated
    // Format: [p_length(4)][g_length(4)][x_length(4)][P][G][X]
    const uint8_t* key_data = stored_key_get_key(stored_key);
    size_t key_data_length = stored_key_get_length(stored_key);
    
    if (key_data_length < 12) {  // Need at least 3 length fields
        ERROR("Invalid key data length");
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Extract lengths
    const uint32_t* lengths = (const uint32_t*)key_data;
    size_t p_length = lengths[0];
    size_t g_length = lengths[1];
    size_t x_length = lengths[2];
    
    if (key_data_length != 12 + p_length + g_length + x_length) {
        ERROR("Key data length mismatch");
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Extract P, G, X
    const uint8_t* p = key_data + 12;
    const uint8_t* g = p + p_length;
    const uint8_t* x = g + g_length;
    
    // Reconstruct the DH context with P, G, and X
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);
    
    mbedtls_mpi mpi_p, mpi_g, mpi_x;
    mbedtls_mpi_init(&mpi_p);
    mbedtls_mpi_init(&mpi_g);
    mbedtls_mpi_init(&mpi_x);
    
    int ret = mbedtls_mpi_read_binary(&mpi_p, p, p_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(p) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    ret = mbedtls_mpi_read_binary(&mpi_g, g, g_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(g) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    ret = mbedtls_mpi_read_binary(&mpi_x, x, x_length);
    if (ret != 0) {
        ERROR("mbedtls_mpi_read_binary(x) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Set the group (P and G)
    ret = mbedtls_dhm_set_group(&dhm, &mpi_p, &mpi_g);
    if (ret != 0) {
        ERROR("mbedtls_dhm_set_group failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Set the private key (X)
    ret = mbedtls_mpi_copy(&dhm.X, &mpi_x);
    if (ret != 0) {
        ERROR("mbedtls_mpi_copy(X) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Compute our public key GX = G^X mod P
    // This IS needed for DH calculation
    ret = mbedtls_mpi_exp_mod(&dhm.GX, &dhm.G, &dhm.X, &dhm.P, NULL);
    if (ret != 0) {
        ERROR("mbedtls_mpi_exp_mod(GX) failed: -0x%04x", -ret);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_mpi_free(&mpi_x);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    mbedtls_mpi_free(&mpi_p);
    mbedtls_mpi_free(&mpi_g);
    mbedtls_mpi_free(&mpi_x);
    
    // Read the other party's public key
    // The public key comes in DER format (from dh_get_public), so we need to parse it
    // DER format: SEQUENCE { algorithm, BIT STRING containing the public key integer }
    // We need to extract the raw public key value
    unsigned char* pub_key_raw = NULL;
    size_t pub_key_raw_len = 0;
    
    if (other_public_length == dhm.len) {
        pub_key_raw_len = other_public_length;
        pub_key_raw = (unsigned char*)other_public;
    } else {
        // Need to parse DER format 
        // Parse DER manually: Skip SEQUENCE header and algorithm identifier to get to BIT STRING
        unsigned char* p = (unsigned char*)other_public;
        unsigned char* end = p + other_public_length;
        size_t len;
        
        // Skip SEQUENCE tag and length
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            ERROR("Failed to parse DER SEQUENCE");
            mbedtls_dhm_free(&dhm);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        // Skip algorithm identifier SEQUENCE
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            ERROR("Failed to parse algorithm identifier");
            mbedtls_dhm_free(&dhm);
            return SA_STATUS_INVALID_PARAMETER;
        }
        p += len;  // Skip the algorithm identifier content
        
        // Get BIT STRING
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_BIT_STRING) != 0) {
            ERROR("Failed to parse BIT STRING");
            mbedtls_dhm_free(&dhm);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        // Skip the "number of unused bits" byte in BIT STRING
        if (len < 1 || *p != 0) {
            ERROR("Invalid BIT STRING format");
            mbedtls_dhm_free(&dhm);
            return SA_STATUS_INVALID_PARAMETER;
        }
        p++;
        len--;
        
        // Now p points to the INTEGER containing the public key
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER) != 0) {
            ERROR("Failed to parse public key INTEGER");
            mbedtls_dhm_free(&dhm);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        pub_key_raw = p;
        pub_key_raw_len = len;
        
        // The INTEGER might be shorter than dhm.len if there are leading zeros
        // Or it might be longer by 1 if there's a leading 0x00 to indicate positive number
        // We need to handle both cases
        if (pub_key_raw_len > dhm.len) {
            // Check if there's a leading 0x00 byte (ASN.1 uses this for positive numbers with high bit set)
            if (pub_key_raw_len == dhm.len + 1 && pub_key_raw[0] == 0x00) {
                pub_key_raw++;
                pub_key_raw_len--;
            } else {
                ERROR("Public key too long: %zu > %zu", pub_key_raw_len, dhm.len);
                mbedtls_dhm_free(&dhm);
                return SA_STATUS_INVALID_PARAMETER;
            }
        }
    }
    
    // mbedtls_dhm_read_public expects exactly dhm.len bytes
    // If the key is shorter, we need to pad it with leading zeros
    unsigned char* padded_pub_key = NULL;
    bool need_free = false;
    
    if (pub_key_raw_len < dhm.len) {
        // Allocate padded buffer
        padded_pub_key = memory_secure_alloc(dhm.len);
        if (padded_pub_key == NULL) {
            ERROR("memory_secure_alloc failed for padded_pub_key");
            mbedtls_dhm_free(&dhm);
            return SA_STATUS_INTERNAL_ERROR;
        }
        need_free = true;
        
        // Pad with leading zeros
        memset(padded_pub_key, 0, dhm.len - pub_key_raw_len);
        memcpy(padded_pub_key + (dhm.len - pub_key_raw_len), pub_key_raw, pub_key_raw_len);
        pub_key_raw = padded_pub_key;
        pub_key_raw_len = dhm.len;
    } else if (pub_key_raw_len > dhm.len) {
        ERROR("Public key length mismatch: %zu != %zu", pub_key_raw_len, dhm.len);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    ret = mbedtls_dhm_read_public(&dhm, pub_key_raw, pub_key_raw_len);
    if (need_free) {
        memory_secure_free(padded_pub_key);
    }
    if (ret != 0) {
        ERROR("mbedtls_dhm_read_public failed: -0x%04x (len=%zu, dhm.len=%zu)", -ret, pub_key_raw_len, dhm.len);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Calculate the shared secret
    size_t const modulus_len = dhm.len;  // Save the full modulus length
    size_t secret_len = modulus_len;
    uint8_t* shared_secret = memory_secure_alloc(modulus_len);
    if (shared_secret == NULL) {
        ERROR("memory_secure_alloc failed");
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    ret = mbedtls_dhm_calc_secret(&dhm, shared_secret, modulus_len, &secret_len, NULL, NULL);
    if (ret != 0) {
        ERROR("mbedtls_dhm_calc_secret failed: -0x%04x", -ret);
        memory_memset_unoptimizable(shared_secret, 0, modulus_len);
        memory_secure_free(shared_secret);
        mbedtls_dhm_free(&dhm);
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    // mbedtls_dhm_calc_secret may return a shorter secret if there are leading zeros
    // We need to pad it back to the full modulus size for consistent behavior
    if (secret_len < modulus_len) {
        // Move the secret to the end and pad with leading zeros
        memmove(shared_secret + (modulus_len - secret_len), shared_secret, secret_len);
        memset(shared_secret, 0, modulus_len - secret_len);
        secret_len = modulus_len;
    }
    
    sa_type_parameters type_parameters;
    memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
    // Optionally fill type_parameters.dh_parameters if needed
    sa_status status = stored_key_create(stored_key_shared_secret, rights, NULL, SA_KEY_TYPE_SYMMETRIC,
            &type_parameters, secret_len, shared_secret, secret_len);
    memory_memset_unoptimizable(shared_secret, 0, modulus_len);
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
    size_t x_size = dhm.len;
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
        // Check if it's a bad input parameter error (mbedTLS combines error codes)
        // MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED is -0x3280, and it may be combined with
        // low-level errors like MBEDTLS_ERR_MPI_BAD_INPUT_DATA to give -0x3284
        // Check if error is in the range for MAKE_PUBLIC_FAILED (between -0x3280 and -0x32FF)
        if ((ret <= -0x3200 && ret >= -0x32FF) ||
            ret == MBEDTLS_ERR_DHM_BAD_INPUT_DATA ||
            ret == MBEDTLS_ERR_DHM_INVALID_FORMAT) {
            return SA_STATUS_INVALID_PARAMETER;
        }
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    // NOTE: x buffer now contains GX (the public key), not X (the private key)
    // We need to extract the actual private key X from dhm.X
    // Get the actual size of X (it may be smaller than P)
    size_t actual_x_size = mbedtls_mpi_size(&dhm.X);
    
    // Clear the x buffer and write X to it (without leading zeros)
    memset(x, 0, x_size);
    ret = mbedtls_mpi_write_binary(&dhm.X, x, actual_x_size);
    if (ret != 0) {
        ERROR("mbedtls_mpi_write_binary(X) failed: -0x%04x", -ret);
        memory_secure_free(x);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    // Store P, G, and X together in format: [p_length(4)][g_length(4)][x_length(4)][P][G][X]
    // Use actual_x_size for the X length
    x_size = actual_x_size;
    size_t key_data_length = 12 + p_length + g_length + x_size;
    uint8_t* key_data = memory_secure_alloc(key_data_length);
    if (key_data == NULL) {
        ERROR("memory_secure_alloc failed");
        memory_secure_free(x);
        mbedtls_mpi_free(&mpi_p);
        mbedtls_mpi_free(&mpi_g);
        mbedtls_dhm_free(&dhm);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    // Write lengths
    uint32_t* lengths = (uint32_t*)key_data;
    lengths[0] = (uint32_t)p_length;
    lengths[1] = (uint32_t)g_length;
    lengths[2] = (uint32_t)x_size;
    
    // Copy P, G, X
    memcpy(key_data + 12, p, p_length);
    memcpy(key_data + 12 + p_length, g, g_length);
    memcpy(key_data + 12 + p_length + g_length, x, x_size);
    
    // Store the DH parameters for type_parameters
    sa_type_parameters type_parameters;
    memory_memset_unoptimizable(&type_parameters, 0, sizeof(type_parameters));
    memcpy(type_parameters.dh_parameters.p, p, p_length);
    type_parameters.dh_parameters.p_length = p_length;
    memcpy(type_parameters.dh_parameters.g, g, g_length);
    type_parameters.dh_parameters.g_length = g_length;
    
    // Create the stored key with combined P, G, X data
    sa_status status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_DH, &type_parameters, p_length, 
            key_data, key_data_length);
    
    memory_secure_free(key_data);
    memory_secure_free(x);
    mbedtls_mpi_free(&mpi_p);
    mbedtls_mpi_free(&mpi_g);
    mbedtls_dhm_free(&dhm);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return status;
}
