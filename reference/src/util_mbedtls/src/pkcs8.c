/*
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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

#include "pkcs8.h" // NOLINT
#include "log.h"
#include "mbedtls/asn1.h"
#include "mbedtls/ecp.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Maximum DER encoding size for a private key (generous buffer)
#define MAX_DER_KEY_SIZE 4096

// Manual PKCS#8 EC key parser for curves that mbedTLS 2.16.10 has trouble with
static mbedtls_pk_context* pk_from_pkcs8_ec_manual(
        const unsigned char* key_data,
        size_t key_len) {
    
    int ret;
    unsigned char *p = (unsigned char*)key_data;
    const unsigned char *end = p + key_len;
    size_t len;
    mbedtls_asn1_buf alg_oid, params;
    mbedtls_ecp_group_id grp_id;
    
    // Parse PKCS#8 PrivateKeyInfo structure
    // PrivateKeyInfo ::= SEQUENCE {
    //   version Version,
    //   privateKeyAlgorithm AlgorithmIdentifier,
    //   privateKey OCTET STRING
    // }
    
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ERROR("Failed to parse PKCS#8 SEQUENCE: -0x%04x", -ret);
        return NULL;
    }
    
    end = p + len;
    
    // Parse version (should be 0)
    int version;
    if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0) {
        ERROR("Failed to parse version: -0x%04x", -ret);
        return NULL;
    }
    
    if (version != 0) {
        ERROR("Unsupported PKCS#8 version: %d", version);
        return NULL;
    }
    
    // Parse AlgorithmIdentifier
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ERROR("Failed to parse AlgorithmIdentifier: -0x%04x", -ret);
        return NULL;
    }
    
    const unsigned char *alg_end = p + len;
    
    // Get algorithm OID
    if ((ret = mbedtls_asn1_get_tag(&p, alg_end, &len, MBEDTLS_ASN1_OID)) != 0) {
        ERROR("Failed to parse algorithm OID: -0x%04x", -ret);
        return NULL;
    }
    
    alg_oid.tag = MBEDTLS_ASN1_OID;
    alg_oid.len = len;
    alg_oid.p = p;
    p += len;
    
    // Get EC parameters (curve OID)
    if ((ret = mbedtls_asn1_get_tag(&p, alg_end, &len, MBEDTLS_ASN1_OID)) != 0) {
        ERROR("Failed to parse curve OID: -0x%04x", -ret);
        return NULL;
    }
    
    params.tag = MBEDTLS_ASN1_OID;
    params.len = len;
    params.p = p;
    p = (unsigned char*)alg_end;
    
    // Look up the curve from OID
    if ((ret = mbedtls_oid_get_ec_grp(&params, &grp_id)) != 0) {
        ERROR("Unknown EC curve OID: -0x%04x", -ret);
        return NULL;
    }
    
    // Parse privateKey OCTET STRING
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        ERROR("Failed to parse privateKey: -0x%04x", -ret);
        return NULL;
    }
    
    // The privateKey contains SEC1 ECPrivateKey structure
    const unsigned char *key_end = p + len;
    
    // Now we have the SEC1 private key, create and setup the PK context
    mbedtls_pk_context* pk = calloc(1, sizeof(mbedtls_pk_context));
    if (pk == NULL) {
        ERROR("calloc failed");
        return NULL;
    }
    
    mbedtls_pk_init(pk);
    
    // Setup EC key
    const mbedtls_pk_info_t *pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (pk_info == NULL) {
        ERROR("mbedtls_pk_info_from_type failed");
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
        ERROR("mbedtls_pk_setup failed: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pk);
    
    // Load the curve
    if ((ret = mbedtls_ecp_group_load(&ec->grp, grp_id)) != 0) {
        ERROR("mbedtls_ecp_group_load failed: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    // Parse SEC1 ECPrivateKey
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER,
    //   privateKey OCTET STRING,
    //   parameters [0] EXPLICIT ECParameters OPTIONAL,
    //   publicKey [1] EXPLICIT BIT STRING OPTIONAL
    // }
    
    if ((ret = mbedtls_asn1_get_tag(&p, key_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ERROR("Failed to parse SEC1 SEQUENCE: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    const unsigned char *sec1_end = p + len;
    
    // Parse version
    if ((ret = mbedtls_asn1_get_int(&p, sec1_end, &version)) != 0) {
        ERROR("Failed to parse SEC1 version: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    // Parse privateKey OCTET STRING
    if ((ret = mbedtls_asn1_get_tag(&p, sec1_end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        ERROR("Failed to parse SEC1 privateKey: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    // Load the private key value
    if ((ret = mbedtls_mpi_read_binary(&ec->d, p, len)) != 0) {
        ERROR("mbedtls_mpi_read_binary failed: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    p += len;
    
    // Try to parse optional publicKey if present
    if (p < sec1_end) {
        // Skip parameters [0] if present
        if (*p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) {
            if ((ret = mbedtls_asn1_get_tag(&p, sec1_end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) != 0) {
                // Not critical, continue
            } else {
                p += len;
            }
        }
        
        // Parse publicKey [1] if present
        if (p < sec1_end && *p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1)) {
            if ((ret = mbedtls_asn1_get_tag(&p, sec1_end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1)) != 0) {
                // Not critical, we can derive public key from private key
            } else {
                const unsigned char *pubkey_end = p + len;
                if ((ret = mbedtls_asn1_get_tag(&p, pubkey_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
                    // Not critical
                } else {
                    // Skip unused bits byte
                    if (len > 0) {
                        p++;
                        len--;
                        
                        // Read public key point
                        if ((ret = mbedtls_ecp_point_read_binary(&ec->grp, &ec->Q, p, len)) != 0) {
                            // Not critical, we can derive it
                        }
                    }
                }
            }
        }
    }
    
    // If we don't have the public key, derive it from private key
    if (mbedtls_ecp_is_zero(&ec->Q)) {
        if ((ret = mbedtls_ecp_mul(&ec->grp, &ec->Q, &ec->d, &ec->grp.G, NULL, NULL)) != 0) {
            ERROR("mbedtls_ecp_mul failed: -0x%04x", -ret);
            mbedtls_pk_free(pk);
            free(pk);
            return NULL;
        }
    }
    
    // Verify the key
    if ((ret = mbedtls_ecp_check_privkey(&ec->grp, &ec->d)) != 0) {
        ERROR("mbedtls_ecp_check_privkey failed: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    if ((ret = mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q)) != 0) {
        ERROR("mbedtls_ecp_check_pubkey failed: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }
    
    return pk;
}

bool pk_to_pkcs8(
        void* out,
        size_t* out_length,
        mbedtls_pk_context* pk) {

    if (pk == NULL) {
        ERROR("NULL pk");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    // Allocate temporary buffer for DER encoding
    // mbedTLS writes data at the END of the buffer
    unsigned char temp_buf[MAX_DER_KEY_SIZE];
    int length = mbedtls_pk_write_key_der(pk, temp_buf, sizeof(temp_buf));
    if (length < 0) {
        ERROR("mbedtls_pk_write_key_der failed: -0x%04x", -length);
        return false;
    }

    // If out is NULL, just return the required size
    if (out == NULL) {
        *out_length = length;
        return true;
    }

    // Check if output buffer is large enough
    if (*out_length < (size_t)length) {
        ERROR("out_length too short: have %zu, need %d", *out_length, length);
        return false;
    }

    // Copy data from end of temp buffer to output
    // mbedTLS writes at the end, so data starts at (temp_buf + sizeof(temp_buf) - length)
    memcpy(out, temp_buf + sizeof(temp_buf) - length, length);
    *out_length = length;
    return true;
}

mbedtls_pk_context* pk_from_pkcs8(
        mbedtls_pk_type_t expected_type,
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return NULL;
    }

    if (in_length == 0) {
        ERROR("Empty input");
        return NULL;
    }

    mbedtls_pk_context* pk = calloc(1, sizeof(mbedtls_pk_context));
    if (pk == NULL) {
        ERROR("calloc failed");
        return NULL;
    }

    mbedtls_pk_init(pk);

    // Try standard mbedTLS PKCS#8 parsing first
    int ret = mbedtls_pk_parse_key(pk, (const unsigned char*)in, in_length, NULL, 0);
    
    // If parsing failed and we expect an EC key, try manual EC-specific parsing
    // This works around mbedTLS 2.16.10 issues with P-192 and P-224 PKCS#8 parsing
    if (ret != 0 && (expected_type == MBEDTLS_PK_ECKEY || expected_type == MBEDTLS_PK_ECKEY_DH || 
                     expected_type == MBEDTLS_PK_ECDSA || expected_type == MBEDTLS_PK_NONE)) {
        
        // Clean up failed attempt
        mbedtls_pk_free(pk);
        free(pk);
        
        // Try manual PKCS#8 EC parser
        pk = pk_from_pkcs8_ec_manual((const unsigned char*)in, in_length);
        if (pk == NULL) {
            ERROR("Both mbedtls_pk_parse_key and manual parser failed for EC key");
            ERROR("Original error: -0x%04x, key length: %zu bytes", -ret, in_length);
            return NULL;
        }
        
        // Manual parser succeeded
        ret = 0;
    }
    
    if (ret != 0) {
        ERROR("mbedtls_pk_parse_key failed: -0x%04x", -ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }

    // Verify key type if expected_type is specified
    if (expected_type != MBEDTLS_PK_NONE && mbedtls_pk_get_type(pk) != expected_type) {
        ERROR("wrong key type: expected %d, got %d", expected_type, mbedtls_pk_get_type(pk));
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }

    return pk;
}
