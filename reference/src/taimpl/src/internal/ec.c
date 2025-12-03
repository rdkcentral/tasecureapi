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

#include "ec.h" // NOLINT
#include "common.h"
#include "digest_util.h"
#include "digest_util_mbedtls.h"
#include "log.h"
#include "pkcs8.h"
#include "porting/memory.h"
#include "porting/rand.h"
#include "stored_key_internal.h"
#include "mbedtls_header.h"
#include <memory.h>

// ed25519-donna for ED25519 EdDSA signing and public key derivation
#include "ed25519.h"

// curve25519-donna for X25519 ECDH
#include "curve25519-donna.h"

// libdecaf (ed448-goldilocks) for ED448/X448
#include <decaf/ed448.h>
#include <decaf/point_448.h>

// X25519 and X448 key/public key/shared secret sizes
#define X25519_KEY_SIZE 32
#define X25519_PUBLIC_KEY_SIZE 32
#define X25519_SHARED_SECRET_SIZE 32
#define X448_KEY_SIZE 56
#define X448_PUBLIC_KEY_SIZE 56
#define X448_SHARED_SECRET_SIZE 56

#define MAX_EC_SIGNATURE 256 // NOLINT

static inline bool is_pcurve(sa_elliptic_curve curve) {
    return curve == SA_ELLIPTIC_CURVE_NIST_P192 || curve == SA_ELLIPTIC_CURVE_NIST_P224 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P256 || curve == SA_ELLIPTIC_CURVE_NIST_P384 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P521;
}

static mbedtls_ecp_group_id ec_get_group_id(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P192:
            return MBEDTLS_ECP_DP_SECP192R1;

        case SA_ELLIPTIC_CURVE_NIST_P224:
            return MBEDTLS_ECP_DP_SECP224R1;

        case SA_ELLIPTIC_CURVE_NIST_P256:
            return MBEDTLS_ECP_DP_SECP256R1;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return MBEDTLS_ECP_DP_SECP384R1;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return MBEDTLS_ECP_DP_SECP521R1;

        default:
            ERROR("Unknown EC curve encountered");
            return MBEDTLS_ECP_DP_NONE;
    }
}

static const char* ec_curve_name(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P192:
            return "NIST P-192";
        case SA_ELLIPTIC_CURVE_NIST_P224:
            return "NIST P-224";
        case SA_ELLIPTIC_CURVE_NIST_P256:
            return "NIST P-256";
        case SA_ELLIPTIC_CURVE_NIST_P384:
            return "NIST P-384";
        case SA_ELLIPTIC_CURVE_NIST_P521:
            return "NIST P-521";
        case SA_ELLIPTIC_CURVE_ED25519:
            return "Ed25519";
        case SA_ELLIPTIC_CURVE_ED448:
            return "Ed448";
        case SA_ELLIPTIC_CURVE_X25519:
            return "X25519";
        case SA_ELLIPTIC_CURVE_X448:
            return "X448";
        default:
            return "Unknown";
    }
}

static mbedtls_pk_type_t ec_get_pk_type(sa_elliptic_curve curve) {
    if (is_pcurve(curve)) {
        return MBEDTLS_PK_ECKEY;
    }
    // Ed25519, Ed448, X25519, X448 not supported in mbedTLS 2.16.10 via pk_context
    const char* curve_name = ec_curve_name(curve);
    ERROR("Unsupported curve for pk_type: %d (%s)", curve, curve_name);
    return MBEDTLS_PK_NONE;
}

size_t ec_key_size_from_curve(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P192:
            return EC_P192_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P224:
            return EC_P224_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P256:
            return EC_P256_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return EC_P384_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return EC_P521_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_ED25519:
        case SA_ELLIPTIC_CURVE_X25519:
            return EC_25519_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_ED448:
            return EC_ED448_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_X448:
            return EC_X448_KEY_SIZE;

        default:
            return 0;
    }
}

size_t ec_validate_private(
        sa_elliptic_curve curve,
        const void* private,
        size_t private_length) {

    if (private == NULL) {
        ERROR("NULL private");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t result = 0;
    mbedtls_pk_context* pk = NULL;
    
    do {
        // For P-curves, use mbedTLS pk_context
        if (is_pcurve(curve)) {
            mbedtls_pk_type_t expected_type = ec_get_pk_type(curve);
            pk = pk_from_pkcs8(expected_type, private, private_length);
            if (pk == NULL) {
                ERROR("pk_from_pkcs8 failed");
                break;
            }

            // Verify it's an EC key
            if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY &&
                mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY_DH) {
                ERROR("Not an EC key");
                break;
            }

            // Get the EC key context and verify group
            mbedtls_ecp_keypair* keypair = mbedtls_pk_ec(*pk);
            if (keypair == NULL) {
                ERROR("mbedtls_pk_ec failed");
                break;
            }

            mbedtls_ecp_group_id expected_grp_id = ec_get_group_id(curve);
            if (keypair->grp.id != expected_grp_id) {
                ERROR("EC group mismatch: expected %d, got %d", expected_grp_id, keypair->grp.id);
                break;
            }

            result = ec_key_size_from_curve(curve);
        } else {
            // ED25519, ED448, X25519, X448 - validate PKCS#8 structure
            // mbedTLS 2.16.10 doesn't support parsing these curves with pk_from_pkcs8,
            // but we can validate the PKCS#8 DER structure manually
            size_t expected_size = ec_key_size_from_curve(curve);
            if (expected_size == 0) {
                ERROR("Invalid curve: %d", curve);
                break;
            }
            
            // Try to parse as PKCS#8: PrivateKeyInfo ::= SEQUENCE {
            //   version Version,
            //   privateKeyAlgorithm AlgorithmIdentifier,
            //   privateKey OCTET STRING (contains nested OCTET STRING with raw key)
            // }
            unsigned char* p = (unsigned char*)private;
            const unsigned char* end = p + private_length;
            size_t len;
            
            int ret = mbedtls_asn1_get_tag(&p, end, &len,
                                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            if (ret != 0) {
                ERROR("Failed to parse PKCS#8 SEQUENCE: -0x%04x", -ret);
                break;
            }
            
            // Skip version
            ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
            if (ret != 0) {
                ERROR("Failed to parse version: -0x%04x", -ret);
                break;
            }
            p += len;
            
            // Skip AlgorithmIdentifier
            ret = mbedtls_asn1_get_tag(&p, end, &len,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            if (ret != 0) {
                ERROR("Failed to parse AlgorithmIdentifier: -0x%04x", -ret);
                break;
            }
            p += len;
            
            // Parse privateKey OCTET STRING
            ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
            if (ret != 0) {
                ERROR("Failed to parse privateKey OCTET STRING: -0x%04x", -ret);
                break;
            }
            
            if (curve == SA_ELLIPTIC_CURVE_X25519 || curve == SA_ELLIPTIC_CURVE_X448) {
                // X25519/X448: raw key directly in OCTET STRING (RFC 8410)
                // BUT: OpenSSL may use double wrapping (like EdDSA) for compatibility
                if (len == expected_size) {
                    // Single wrapping (RFC 8410 compliant)
                    result = expected_size;
                } else {
                    // Try double wrapping (OpenSSL format)
                    const unsigned char* key_end = p + len;
                    ret = mbedtls_asn1_get_tag(&p, key_end, &len, MBEDTLS_ASN1_OCTET_STRING);
                    if (ret != 0) {
                        ERROR("Failed to parse inner OCTET STRING: -0x%04x", -ret);
                        break;
                    }
                    
                    if (len != expected_size) {
                        ERROR("Invalid key size for curve %d: expected %zu, got %zu", 
                              curve, expected_size, len);
                        break;
                    }
                    
                    result = expected_size;
                }
            } else {
                // EdDSA: extract inner OCTET STRING containing raw key bytes
                const unsigned char* key_end = p + len;
                ret = mbedtls_asn1_get_tag(&p, key_end, &len, MBEDTLS_ASN1_OCTET_STRING);
                if (ret != 0) {
                    ERROR("Failed to parse inner OCTET STRING: -0x%04x", -ret);
                    break;
                }
                
                // Verify raw key size
                if (len != expected_size) {
                    ERROR("Invalid key size for curve %d: expected %zu, got %zu", 
                          curve, expected_size, len);
                    break;
                }
                
                result = expected_size;
            }
        }
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }

    return result;
}

/**
 * @brief Extract raw private key bytes from PKCS#8 DER encoding.
 * This is a helper for ED/X curves which store keys as OCTET STRING within OCTET STRING.
 * 
 * @param curve The elliptic curve type
 * @param pkcs8_data The PKCS#8 DER-encoded private key
 * @param pkcs8_length Length of PKCS#8 data
 * @param raw_key_out Buffer to store extracted raw key bytes
 * @param raw_key_size Expected size of raw key (will be verified)
 * @return SA_STATUS_OK on success, error code otherwise
 */
static sa_status ec_extract_raw_private_key(
        sa_elliptic_curve curve,
        const void* pkcs8_data,
        size_t pkcs8_length,
        uint8_t* raw_key_out,
        size_t raw_key_size) {
    
    if (pkcs8_data == NULL || raw_key_out == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }
    
    // Parse PKCS#8: PrivateKeyInfo ::= SEQUENCE {
    //   version Version,
    //   privateKeyAlgorithm AlgorithmIdentifier,
    //   privateKey OCTET STRING (contains nested OCTET STRING with raw key)
    // }
    unsigned char* p = (unsigned char*)pkcs8_data;
    const unsigned char* end = p + pkcs8_length;
    size_t len;
    
    int ret = mbedtls_asn1_get_tag(&p, end, &len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        ERROR("Failed to parse PKCS#8 SEQUENCE: -0x%04x", -ret);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    // Skip version
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (ret != 0) {
        ERROR("Failed to parse version: -0x%04x", -ret);
        return SA_STATUS_INVALID_PARAMETER;
    }
    p += len;
    
    // Skip AlgorithmIdentifier
    ret = mbedtls_asn1_get_tag(&p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        ERROR("Failed to parse AlgorithmIdentifier: -0x%04x", -ret);
        return SA_STATUS_INVALID_PARAMETER;
    }
    p += len;
    
    // Parse privateKey OCTET STRING
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) {
        ERROR("Failed to parse privateKey OCTET STRING: -0x%04x", -ret);
        return SA_STATUS_INVALID_PARAMETER;
    }
    
    if (curve == SA_ELLIPTIC_CURVE_X25519 || curve == SA_ELLIPTIC_CURVE_X448) {
        // X25519/X448: RFC 8410 specifies single OCTET STRING, but OpenSSL uses double wrapping
        if (len == raw_key_size) {
            // Single wrapping (RFC 8410 compliant)
            memcpy(raw_key_out, p, len);
        } else {
            // Try double wrapping (OpenSSL format)
            const unsigned char* key_end = p + len;
            ret = mbedtls_asn1_get_tag(&p, key_end, &len, MBEDTLS_ASN1_OCTET_STRING);
            if (ret != 0) {
                ERROR("Failed to parse inner OCTET STRING: -0x%04x", -ret);
                return SA_STATUS_INVALID_PARAMETER;
            }
            
            if (len != raw_key_size) {
                ERROR("Invalid key size for curve %d: expected %zu, got %zu", 
                      curve, raw_key_size, len);
                return SA_STATUS_INVALID_PARAMETER;
            }
            memcpy(raw_key_out, p, len);
        }
    } else {
        // EdDSA: extract inner OCTET STRING containing raw key bytes
        const unsigned char* key_end = p + len;
        ret = mbedtls_asn1_get_tag(&p, key_end, &len, MBEDTLS_ASN1_OCTET_STRING);
        if (ret != 0) {
            ERROR("Failed to parse inner OCTET STRING: -0x%04x", -ret);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        // Verify raw key size
        if (len != raw_key_size) {
            ERROR("Invalid key size for curve %d: expected %zu, got %zu", 
                  curve, raw_key_size, len);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        // Copy raw key bytes
        memcpy(raw_key_out, p, len);
    }
    return SA_STATUS_OK;
}

/**
 * @brief Encode a raw EdDSA private key to PKCS#8 format.
 * 
 * PKCS#8 structure for EdDSA:
 * SEQUENCE {
 *   version INTEGER (0)
 *   AlgorithmIdentifier SEQUENCE {
 *     algorithm OBJECT IDENTIFIER (1.3.101.112 for Ed25519, 1.3.101.113 for Ed448)
 *   }
 *   privateKey OCTET STRING {
 *     OCTET STRING (raw private key bytes)
 *   }
 * }
 */
static sa_status ec_encode_raw_to_pkcs8(
        sa_elliptic_curve curve,
        const uint8_t* raw_private_key,
        size_t raw_key_size,
        uint8_t** pkcs8_out,
        size_t* pkcs8_length) {
    
    if (raw_private_key == NULL || pkcs8_out == NULL || pkcs8_length == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }

    // OID for Ed25519: 1.3.101.112
    const unsigned char ed25519_oid[] = {0x06, 0x03, 0x2b, 0x65, 0x70};
    // OID for Ed448: 1.3.101.113  
    const unsigned char ed448_oid[] = {0x06, 0x03, 0x2b, 0x65, 0x71};
    // OID for X25519: 1.3.101.110
    const unsigned char x25519_oid[] = {0x06, 0x03, 0x2b, 0x65, 0x6e};
    // OID for X448: 1.3.101.111
    const unsigned char x448_oid[] = {0x06, 0x03, 0x2b, 0x65, 0x6f};

    const unsigned char* oid;
    size_t oid_len;

    if (curve == SA_ELLIPTIC_CURVE_ED25519) {
        oid = ed25519_oid;
        oid_len = sizeof(ed25519_oid);
    } else if (curve == SA_ELLIPTIC_CURVE_ED448) {
        oid = ed448_oid;
        oid_len = sizeof(ed448_oid);
    } else if (curve == SA_ELLIPTIC_CURVE_X25519) {
        oid = x25519_oid;
        oid_len = sizeof(x25519_oid);
    } else if (curve == SA_ELLIPTIC_CURVE_X448) {
        oid = x448_oid;
        oid_len = sizeof(x448_oid);
    } else {
        ERROR("Unsupported curve for PKCS#8 encoding: %d", curve);
        return SA_STATUS_INVALID_PARAMETER;
    }

    // Calculate total PKCS#8 size
    // X25519/X448: version (3) + AlgorithmIdentifier (2 + oid_len) + privateKey (2 + raw_key_size)
    // EdDSA: version (3) + AlgorithmIdentifier (2 + oid_len) + privateKey (2 + 2 + raw_key_size)
    size_t alg_id_len = oid_len;
    size_t private_key_len;
    if (curve == SA_ELLIPTIC_CURVE_X25519 || curve == SA_ELLIPTIC_CURVE_X448) {
        // X25519/X448: single OCTET STRING containing raw key
        private_key_len = raw_key_size;
    } else {
        // EdDSA: double OCTET STRING wrapping
        private_key_len = 2 + raw_key_size;  // Inner tag + length + raw key
    }
    size_t content_len = 3 + (2 + alg_id_len) + (2 + private_key_len);
    size_t total_len = 2 + content_len;  // Outer SEQUENCE tag + length + content

    uint8_t* pkcs8 = memory_secure_alloc(total_len);
    if (pkcs8 == NULL) {
        ERROR("memory_secure_alloc failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    size_t offset = 0;

    // Outer SEQUENCE
    pkcs8[offset++] = 0x30;  // SEQUENCE tag
    pkcs8[offset++] = (uint8_t)content_len;

    // Version INTEGER (0)
    pkcs8[offset++] = 0x02;  // INTEGER tag
    pkcs8[offset++] = 0x01;  // length
    pkcs8[offset++] = 0x00;  // value = 0

    // AlgorithmIdentifier SEQUENCE
    pkcs8[offset++] = 0x30;  // SEQUENCE tag
    pkcs8[offset++] = (uint8_t)alg_id_len;
    memcpy(pkcs8 + offset, oid, oid_len);
    offset += oid_len;

    // privateKey OCTET STRING
    pkcs8[offset++] = 0x04;  // OCTET STRING tag
    pkcs8[offset++] = (uint8_t)private_key_len;

    if (curve == SA_ELLIPTIC_CURVE_X25519 || curve == SA_ELLIPTIC_CURVE_X448) {
        // X25519/X448: raw key directly in OCTET STRING
        memcpy(pkcs8 + offset, raw_private_key, raw_key_size);
        offset += raw_key_size;
    } else {
        // EdDSA: nested OCTET STRING containing raw key
        pkcs8[offset++] = 0x04;  // Inner OCTET STRING tag
        pkcs8[offset++] = (uint8_t)raw_key_size;
        memcpy(pkcs8 + offset, raw_private_key, raw_key_size);
        offset += raw_key_size;
    }

    *pkcs8_out = pkcs8;
    *pkcs8_length = total_len;
    return SA_STATUS_OK;
}

/**
 * @brief Wrap raw ED25519 public key in DER SubjectPublicKeyInfo format.
 * 
 * ED25519 public keys use the following DER structure:
 * SEQUENCE (42 bytes total for ED25519)
 *   SEQUENCE (algorithm identifier)
 *     OBJECT IDENTIFIER 1.3.101.112 (id-Ed25519)
 *   BIT STRING (public key bytes)
 */
static sa_status ed25519_wrap_public_key_der(
        uint8_t* der_out,
        size_t* der_length,
        const uint8_t* raw_public_key) {
    
    // DER encoding for ED25519 public key (44 bytes total)
    // SEQUENCE tag + length
    der_out[0] = 0x30;  // SEQUENCE
    der_out[1] = 0x2A;  // length = 42 bytes
    
    // AlgorithmIdentifier SEQUENCE
    der_out[2] = 0x30;  // SEQUENCE  
    der_out[3] = 0x05;  // length = 5 bytes
    
    // OID for id-Ed25519 (1.3.101.112)
    der_out[4] = 0x06;  // OBJECT IDENTIFIER
    der_out[5] = 0x03;  // length = 3 bytes
    der_out[6] = 0x2B;  // 1.3 (43 = 1*40 + 3)
    der_out[7] = 0x65;  // 101
    der_out[8] = 0x70;  // 112
    
    // BIT STRING containing public key
    der_out[9] = 0x03;   // BIT STRING
    der_out[10] = 0x21;  // length = 33 bytes (32 + 1 for unused bits)
    der_out[11] = 0x00;  // unused bits = 0
    
    // Copy 32-byte raw public key
    memcpy(&der_out[12], raw_public_key, 32);
    
    *der_length = 44;  // Total DER encoding length
    return SA_STATUS_OK;
}

// Wrap X25519 32-byte public key in DER SubjectPublicKeyInfo format
static sa_status x25519_wrap_public_key_der(
        uint8_t* der_out,
        size_t* der_length,
        const uint8_t* public_key) {
    
    if (der_out == NULL || der_length == NULL || public_key == NULL) {
        return SA_STATUS_NULL_PARAMETER;
    }
    
    // SubjectPublicKeyInfo for X25519:
    // SEQUENCE(44) {
    //   SEQUENCE(5) { OID(1.3.101.110) }
    //   BIT STRING(33) { 0x00 || 32-byte public key }
    // }
    
    // OID 1.3.101.110 = 0x06 0x03 0x2b 0x65 0x6e
    static const uint8_t oid[] = {0x06, 0x03, 0x2b, 0x65, 0x6e};
    
    uint8_t* p = der_out;
    *p++ = 0x30;  // SEQUENCE
    *p++ = 0x2a;  // Length 42
    *p++ = 0x30;  // SEQUENCE (AlgorithmIdentifier)
    *p++ = 0x05;  // Length 5
    memcpy(p, oid, sizeof(oid));
    p += sizeof(oid);
    *p++ = 0x03;  // BIT STRING
    *p++ = 0x21;  // Length 33
    *p++ = 0x00;  // No unused bits
    memcpy(p, public_key, 32);
    p += 32;
    
    *der_length = 44;
    return SA_STATUS_OK;
}

// Wrap ED448 57-byte public key in DER SubjectPublicKeyInfo format
static sa_status ed448_wrap_public_key_der(
        uint8_t* der_out,
        size_t* der_length,
        const uint8_t* public_key) {
    
    if (der_out == NULL || der_length == NULL || public_key == NULL) {
        return SA_STATUS_NULL_PARAMETER;
    }
    
    // SubjectPublicKeyInfo for ED448:
    // SEQUENCE(69) {
    //   SEQUENCE(5) { OID(1.3.101.113) }
    //   BIT STRING(58) { 0x00 || 57-byte public key }
    // }
    
    // OID 1.3.101.113 = 0x06 0x03 0x2b 0x65 0x71
    static const uint8_t oid[] = {0x06, 0x03, 0x2b, 0x65, 0x71};
    
    uint8_t* p = der_out;
    *p++ = 0x30;  // SEQUENCE
    *p++ = 0x43;  // Length 67
    *p++ = 0x30;  // SEQUENCE (AlgorithmIdentifier)
    *p++ = 0x05;  // Length 5
    memcpy(p, oid, sizeof(oid));
    p += sizeof(oid);
    *p++ = 0x03;  // BIT STRING
    *p++ = 0x3a;  // Length 58
    *p++ = 0x00;  // No unused bits
    memcpy(p, public_key, 57);
    p += 57;
    
    *der_length = 69;
    return SA_STATUS_OK;
}

// Wrap X448 56-byte public key in DER SubjectPublicKeyInfo format
static sa_status x448_wrap_public_key_der(
        uint8_t* der_out,
        size_t* der_length,
        const uint8_t* public_key) {
    
    if (der_out == NULL || der_length == NULL || public_key == NULL) {
        return SA_STATUS_NULL_PARAMETER;
    }
    
    // SubjectPublicKeyInfo for X448:
    // SEQUENCE(68) {
    //   SEQUENCE(5) { OID(1.3.101.111) }
    //   BIT STRING(57) { 0x00 || 56-byte public key }
    // }
    
    // OID 1.3.101.111 = 0x06 0x03 0x2b 0x65 0x6f
    static const uint8_t oid[] = {0x06, 0x03, 0x2b, 0x65, 0x6f};
    
    uint8_t* p = der_out;
    *p++ = 0x30;  // SEQUENCE
    *p++ = 0x42;  // Length 66
    *p++ = 0x30;  // SEQUENCE (AlgorithmIdentifier)
    *p++ = 0x05;  // Length 5
    memcpy(p, oid, sizeof(oid));
    p += sizeof(oid);
    *p++ = 0x03;  // BIT STRING
    *p++ = 0x39;  // Length 57
    *p++ = 0x00;  // No unused bits
    memcpy(p, public_key, 56);
    p += 56;
    
    *der_length = 68;
    return SA_STATUS_OK;
}

sa_status ec_get_public(
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
    unsigned char* der_buf = NULL;
    uint8_t* raw_private_key = NULL;
    uint8_t* public_key = NULL;
    
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

        size_t key_length = stored_key_get_length(stored_key);
        sa_elliptic_curve curve = header->type_parameters.curve;
        
        // Handle P-curves using mbedTLS
        if (is_pcurve(curve)) {
            mbedtls_pk_type_t expected_type = ec_get_pk_type(curve);
            pk = pk_from_pkcs8(expected_type, key, key_length);
            if (pk == NULL) {
                ERROR("pk_from_pkcs8 failed");
                break;
            }

            // Allocate buffer for public key DER encoding
            // mbedTLS writes data at the END of the buffer
            der_buf = memory_secure_alloc(4096);
            if (der_buf == NULL) {
                ERROR("malloc failed");
                break;
            }

            int length = mbedtls_pk_write_pubkey_der(pk, der_buf, 4096);
            if (length < 0) {
                ERROR("mbedtls_pk_write_pubkey_der failed: -0x%04x", -length);
                break;
            }

            if (out == NULL) {
                *out_length = length;
                status = SA_STATUS_OK;
                break;
            }

            if (*out_length < (size_t)length) {
                ERROR("Invalid out_length");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            // Copy from end of buffer where mbedTLS wrote the data
            memcpy(out, der_buf + 4096 - length, length);
            *out_length = length;
            status = SA_STATUS_OK;
        } else {
            // Handle ED/X curves using decaf library functions
            size_t private_key_size;
            size_t public_key_size;
            size_t der_buffer_size;
            
            // Determine key sizes based on curve
            switch (curve) {
                case SA_ELLIPTIC_CURVE_ED25519:
                    private_key_size = 32;
                    public_key_size = 32;
                    der_buffer_size = 64;
                    break;
                case SA_ELLIPTIC_CURVE_X25519:
                    private_key_size = 32;
                    public_key_size = 32;
                    der_buffer_size = 64;
                    break;
                case SA_ELLIPTIC_CURVE_ED448:
                    private_key_size = 57;
                    public_key_size = 57;
                    der_buffer_size = 80;
                    break;
                case SA_ELLIPTIC_CURVE_X448:
                    private_key_size = 56;
                    public_key_size = 56;
                    der_buffer_size = 80;
                    break;
                default: {
                    mbedtls_ecp_group_id group_id = ec_get_group_id(curve);
                    const char* curve_name = ec_curve_name(curve);
                    ERROR("Unsupported curve %d (%s, group_id: %d)", 
                          curve, curve_name, group_id);
                    status = SA_STATUS_OPERATION_NOT_SUPPORTED;
                    break;
                }
            }
            
            if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
                break;
            }
            
            // Extract raw private key from PKCS#8
            raw_private_key = memory_secure_alloc(private_key_size);
            if (raw_private_key == NULL) {
                ERROR("memory_secure_alloc failed for raw private key");
                break;
            }
            
            status = ec_extract_raw_private_key(curve, key, key_length, 
                                                raw_private_key, private_key_size);
            if (status != SA_STATUS_OK) {
                ERROR("ec_extract_raw_private_key failed");
                break;
            }
            
            // Allocate buffer for public key
            public_key = memory_secure_alloc(public_key_size);
            if (public_key == NULL) {
                ERROR("memory_secure_alloc failed for public key");
                break;
            }
            
            // Derive public key using appropriate library function
            switch (curve) {
                case SA_ELLIPTIC_CURVE_ED25519:
                    // Use ed25519-donna for ED25519 (already working)
                    ed25519_publickey(raw_private_key, public_key);
                    break;
                    
                case SA_ELLIPTIC_CURVE_X25519: {
                    // Use curve25519-donna for X25519
                    // Standard Curve25519 basepoint is {9, 0, 0, ..., 0}
                    uint8_t basepoint[32] = {9};
                    curve25519_donna(public_key, raw_private_key, basepoint);
                    break;
                }
                    
                case SA_ELLIPTIC_CURVE_ED448:
                    decaf_ed448_derive_public_key(public_key, raw_private_key);
                    break;
                    
                case SA_ELLIPTIC_CURVE_X448:
                    decaf_x448_derive_public_key(public_key, raw_private_key);
                    break;
                    
                default:
                    ERROR("Unreachable: unsupported curve");
                    status = SA_STATUS_OPERATION_NOT_SUPPORTED;
                    break;
            }
            
            if (status != SA_STATUS_OK) {
                break;
            }
            
            // Wrap in DER format for compatibility with OpenSSL output
            uint8_t* der_buffer = memory_secure_alloc(der_buffer_size);
            if (der_buffer == NULL) {
                ERROR("memory_secure_alloc failed for DER buffer");
                break;
            }
            
            size_t der_length = 0;
            switch (curve) {
                case SA_ELLIPTIC_CURVE_ED25519:
                    status = ed25519_wrap_public_key_der(der_buffer, &der_length, public_key);
                    break;
                case SA_ELLIPTIC_CURVE_X25519:
                    status = x25519_wrap_public_key_der(der_buffer, &der_length, public_key);
                    break;
                case SA_ELLIPTIC_CURVE_ED448:
                    status = ed448_wrap_public_key_der(der_buffer, &der_length, public_key);
                    break;
                case SA_ELLIPTIC_CURVE_X448:
                    status = x448_wrap_public_key_der(der_buffer, &der_length, public_key);
                    break;
                default:
                    ERROR("Unreachable: unsupported curve");
                    status = SA_STATUS_OPERATION_NOT_SUPPORTED;
                    break;
            }
            
            if (status != SA_STATUS_OK) {
                ERROR("DER wrapping failed");
                memory_secure_free(der_buffer);
                break;
            }
            
            // Return DER-encoded public key
            if (out == NULL) {
                *out_length = der_length;
                status = SA_STATUS_OK;
                memory_secure_free(der_buffer);
                break;
            }

            if (*out_length < der_length) {
                ERROR("Invalid out_length");
                status = SA_STATUS_INVALID_PARAMETER;
                memory_secure_free(der_buffer);
                break;
            }

            memcpy(out, der_buffer, der_length);
            *out_length = der_length;
            memory_secure_free(der_buffer);  // Free the DER buffer after copying
            status = SA_STATUS_OK;
        }
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    if (der_buf != NULL) {
        memory_secure_free(der_buf);
    }
    if (raw_private_key != NULL) {
        memory_memset_unoptimizable(raw_private_key, 0, ec_key_size_from_curve(
            stored_key_get_header(stored_key)->type_parameters.curve));
        memory_secure_free(raw_private_key);
    }
    if (public_key != NULL) {
        memory_secure_free(public_key);
    }

    return status;
}

sa_status ec_verify_cipher(
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key) {

    DEBUG("ec_verify_cipher: mode %d, stored_key %p", cipher_mode, stored_key);

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (!is_pcurve(header->type_parameters.curve)) {
        ERROR("ED & X curves cannot be used for ECDSA");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    return SA_STATUS_OK;
}

sa_status ec_decrypt_elgamal(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (!is_pcurve(header->type_parameters.curve)) {
        ERROR("ED & X curves cannot be used for El Gamal");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    // mbedTLS implementation for P-curves
    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_point c1, c2, shared_secret, message_point;
    mbedtls_mpi neg_one;
    uint8_t* point_buffer = NULL;
    
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_point_init(&c1);
    mbedtls_ecp_point_init(&c2);
    mbedtls_ecp_point_init(&shared_secret);
    mbedtls_ecp_point_init(&message_point);
    mbedtls_mpi_init(&neg_one);

    do {
        // SEC1 standard uncompressed point format: 0x04 || X || Y
        // ElGamal ciphertext: C1 || C2 (two points)
        // Each point: 1 + key_size + key_size bytes
        size_t point_size = 1 + (header->size * 2);  // SEC1 uncompressed format
        size_t expected_input_length = point_size * 2;  // Two points
        
        // If out is NULL, return required buffer size
        if (out == NULL) {
            *out_length = header->size;  // El Gamal output is just X coordinate
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < header->size) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (in_length != expected_input_length) {
            ERROR("Invalid in_length: expected %zu, got %zu", expected_input_length, in_length);
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // Import private key - handle both PKCS#8 and raw format
        // Keys generated by ec_generate are in PKCS#8 format
        // Keys imported from test/external sources may be raw bytes
        const uint8_t* key_bytes = (const uint8_t*)key;
        size_t stored_key_length = stored_key_get_length(stored_key);
        
        mbedtls_pk_context* pk = NULL;
        bool key_loaded = false;
        
        // Try PKCS#8 first if the length suggests it (PKCS#8 is larger than raw key)
        if (stored_key_length > header->size) {
            mbedtls_pk_type_t expected_type = ec_get_pk_type(header->type_parameters.curve);
            pk = pk_from_pkcs8(expected_type, key, stored_key_length);
            if (pk != NULL) {
                // Extract EC keypair from pk_context
                mbedtls_ecp_keypair* keypair_ptr = mbedtls_pk_ec(*pk);
                if (keypair_ptr == NULL) {
                    ERROR("mbedtls_pk_ec failed");
                    free(pk);
                    break;
                }
                
                // Copy keypair data to local keypair structure
                if (mbedtls_ecp_group_copy(&keypair.grp, &keypair_ptr->grp) != 0 ||
                    mbedtls_mpi_copy(&keypair.d, &keypair_ptr->d) != 0) {
                    ERROR("Failed to copy keypair from PKCS#8");
                    free(pk);
                    break;
                }
                free(pk);
                key_loaded = true;
            }
        }
        
        // If PKCS#8 parsing failed or key is raw format, construct from raw bytes
        if (!key_loaded) {
            if (stored_key_length != header->size) {
                ERROR("Key length mismatch: stored %zu, expected %zu", stored_key_length, (size_t)header->size);
                break;
            }
            
            // Create EC keypair from raw private key bytes
            mbedtls_ecp_group_id grp_id = ec_get_group_id(header->type_parameters.curve);
            if (grp_id == MBEDTLS_ECP_DP_NONE) {
                ERROR("ec_get_group_id failed");
                break;
            }
            
            int ret = mbedtls_ecp_group_load(&keypair.grp, grp_id);
            if (ret != 0) {
                ERROR("mbedtls_ecp_group_load failed: -0x%04x", -ret);
                break;
            }
            
            ret = mbedtls_mpi_read_binary(&keypair.d, key_bytes, header->size);
            if (ret != 0) {
                ERROR("mbedtls_mpi_read_binary failed: -0x%04x", -ret);
                break;
            }
            
            // Derive public key from private key
            ret = mbedtls_ecp_mul(&keypair.grp, &keypair.Q, &keypair.d, &keypair.grp.G, NULL, NULL);
            if (ret != 0) {
                ERROR("mbedtls_ecp_mul failed: -0x%04x", -ret);
                break;
            }
        }

        // Read C1 point (first point) - SEC1 standard format already includes 0x04
        if (mbedtls_ecp_point_read_binary(&keypair.grp, &c1, in, point_size) != 0) {
            ERROR("mbedtls_ecp_point_read_binary failed for C1");
            break;
        }

        // Read C2 point (second point) - SEC1 standard format already includes 0x04
        if (mbedtls_ecp_point_read_binary(&keypair.grp, &c2, (const uint8_t*)in + point_size, point_size) != 0) {
            ERROR("mbedtls_ecp_point_read_binary failed for C2");
            break;
        }

        // Compute shared_secret = C1 * private_key
        if (mbedtls_ecp_mul(&keypair.grp, &shared_secret, &keypair.d, &c1, NULL, NULL) != 0) {
            ERROR("mbedtls_ecp_mul failed");
            break;
        }

        // Compute message_point = C2 - shared_secret
        // mbedTLS doesn't have subtraction, so use muladd: message_point = -1*shared_secret + 1*C2
        if (mbedtls_mpi_lset(&neg_one, -1) != 0) {
            ERROR("mbedtls_mpi_lset failed");
            break;
        }

        // muladd computes: R = m*P + n*Q, so: message_point = (-1)*shared_secret + 1*C2
        mbedtls_mpi one;
        mbedtls_mpi_init(&one);
        if (mbedtls_mpi_lset(&one, 1) != 0) {
            ERROR("mbedtls_mpi_lset failed for one");
            mbedtls_mpi_free(&one);
            break;
        }

        if (mbedtls_ecp_muladd(&keypair.grp, &message_point, &neg_one, &shared_secret, &one, &c2) != 0) {
            ERROR("mbedtls_ecp_muladd failed");
            mbedtls_mpi_free(&one);
            break;
        }
        mbedtls_mpi_free(&one);

        // Export message_point X coordinate
        size_t x_size = mbedtls_mpi_size(&message_point.X);
        if (x_size > header->size) {
            ERROR("X coordinate too large");
            break;
        }

        // Write X coordinate to output (big-endian, zero-padded)
        memset(out, 0, header->size);
        if (mbedtls_mpi_write_binary(&message_point.X, (uint8_t*)out + (header->size - x_size), x_size) != 0) {
            ERROR("mbedtls_mpi_write_binary failed");
            break;
        }

        *out_length = header->size;
        status = SA_STATUS_OK;
    } while (false);

    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecp_point_free(&c1);
    mbedtls_ecp_point_free(&c2);
    mbedtls_ecp_point_free(&shared_secret);
    mbedtls_ecp_point_free(&message_point);
    mbedtls_mpi_free(&neg_one);
    
    if (point_buffer != NULL) {
        memory_secure_free(point_buffer);
    }

    return status;
}

// Decode PKCS#8 encoded key to extract raw private key (for X25519/X448/ED25519/ED448)
static sa_status ec_decode_pkcs8_to_raw(
        uint8_t* raw_key_out,
        size_t* raw_key_size_out,
        size_t raw_key_buffer_size,
        sa_elliptic_curve curve,
        const void* pkcs8,
        size_t pkcs8_length) {

    if (raw_key_out == NULL || raw_key_size_out == NULL || pkcs8 == NULL) {
        ERROR("NULL parameter");
        return SA_STATUS_NULL_PARAMETER;
    }

    const uint8_t* p = (const uint8_t*)pkcs8;
    size_t offset = 0;

    // Skip outer SEQUENCE tag and length
    if (offset + 2 > pkcs8_length || p[offset++] != 0x30) {
        ERROR("Invalid PKCS#8: missing outer SEQUENCE");
        return SA_STATUS_INVALID_PARAMETER;
    }
    size_t content_len __attribute__((unused)) = p[offset++];
    
    // Skip version INTEGER
    if (offset + 3 > pkcs8_length || p[offset++] != 0x02 || p[offset++] != 0x01 || p[offset++] != 0x00) {
        ERROR("Invalid PKCS#8: bad version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    // Skip AlgorithmIdentifier SEQUENCE
    if (offset + 2 > pkcs8_length || p[offset++] != 0x30) {
        ERROR("Invalid PKCS#8: missing AlgorithmIdentifier");
        return SA_STATUS_INVALID_PARAMETER;
    }
    size_t alg_len = p[offset++];
    offset += alg_len;  // Skip OID

    // Read privateKey OCTET STRING
    if (offset + 2 > pkcs8_length || p[offset++] != 0x04) {
        ERROR("Invalid PKCS#8: missing privateKey OCTET STRING");
        return SA_STATUS_INVALID_PARAMETER;
    }
    size_t private_key_len = p[offset++];

    if (curve == SA_ELLIPTIC_CURVE_X25519 || curve == SA_ELLIPTIC_CURVE_X448) {
        // X25519/X448: RFC 8410 specifies single OCTET STRING, but OpenSSL uses double wrapping
        size_t expected_size = (curve == SA_ELLIPTIC_CURVE_X25519) ? EC_25519_KEY_SIZE : EC_X448_KEY_SIZE;
        
        if (private_key_len == expected_size) {
            // Single wrapping (RFC 8410 compliant) - raw key directly
            if (offset + private_key_len > pkcs8_length) {
                ERROR("Invalid PKCS#8: truncated private key");
                return SA_STATUS_INVALID_PARAMETER;
            }
            
            memcpy(raw_key_out, p + offset, private_key_len);
            *raw_key_size_out = private_key_len;
        } else {
            // Double wrapping (OpenSSL format) - nested OCTET STRING
            if (offset + 2 > pkcs8_length || p[offset++] != 0x04) {
                ERROR("Invalid PKCS#8: missing inner OCTET STRING for X25519/X448");
                return SA_STATUS_INVALID_PARAMETER;
            }
            size_t raw_key_size = p[offset++];

            if (offset + raw_key_size > pkcs8_length) {
                ERROR("Invalid PKCS#8: truncated private key");
                return SA_STATUS_INVALID_PARAMETER;
            }

            if (raw_key_size > raw_key_buffer_size) {
                ERROR("Raw key buffer too small: need %zu, have %zu", raw_key_size, raw_key_buffer_size);
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(raw_key_out, p + offset, raw_key_size);
            *raw_key_size_out = raw_key_size;
        }
    } else {
        // EdDSA: nested OCTET STRING containing raw key
        // Read inner OCTET STRING tag and length
        if (offset + 2 > pkcs8_length || p[offset++] != 0x04) {
            ERROR("Invalid PKCS#8: missing inner OCTET STRING for EdDSA");
            return SA_STATUS_INVALID_PARAMETER;
        }
        size_t raw_key_size = p[offset++];

        if (offset + raw_key_size > pkcs8_length) {
            ERROR("Invalid PKCS#8: truncated private key");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (raw_key_size > raw_key_buffer_size) {
            ERROR("Raw key buffer too small: need %zu, have %zu", raw_key_size, raw_key_buffer_size);
            return SA_STATUS_INVALID_PARAMETER;
        }

        memcpy(raw_key_out, p + offset, raw_key_size);
        *raw_key_size_out = raw_key_size;
    }
    
    return SA_STATUS_OK;
}

sa_status ec_compute_ecdh_shared_secret(
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
    mbedtls_pk_context* pk = NULL;
    mbedtls_pk_context* other_pk = NULL;
    mbedtls_ecdh_context ecdh;
    
    mbedtls_ecdh_init(&ecdh);
    
    do {
        const void* key = stored_key_get_key(stored_key);
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

        if (header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED448) {
            ERROR("ED curves cannot be used for ECDH");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        // Handle X25519/X448 using curve25519-donna/libdecaf
        if (header->type_parameters.curve == SA_ELLIPTIC_CURVE_X25519) {
            // X25519 ECDH
            // The public key comes in SubjectPublicKeyInfo format (DER encoded)
            // For X25519, this is typically 44 bytes (12 byte header + 32 byte raw key)
            // We need to extract the raw 32 bytes
            
            const uint8_t* other_public_bytes = (const uint8_t*)other_public;
            const uint8_t* raw_other_public = NULL;
            size_t raw_other_public_size = 0;
            
            // Simple DER parser: find BIT STRING containing the raw public key
            // X25519 SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
            if (other_public_length >= 44 && other_public_bytes[0] == 0x30) {
                // Skip SEQUENCE and AlgorithmIdentifier, find BIT STRING (tag 0x03)
                for (size_t i = 0; i < other_public_length - 33; i++) {
                    if (other_public_bytes[i] == 0x03 && other_public_bytes[i + 1] == 0x21 && 
                        other_public_bytes[i + 2] == 0x00) {
                        // Found BIT STRING with 33 bytes (0x21), first byte is unused bits (0x00)
                        raw_other_public = &other_public_bytes[i + 3];
                        raw_other_public_size = 32;
                        break;
                    }
                }
            } else if (other_public_length == X25519_PUBLIC_KEY_SIZE) {
                // Raw format
                raw_other_public = other_public_bytes;
                raw_other_public_size = other_public_length;
            }
            
            if (raw_other_public == NULL || raw_other_public_size != X25519_PUBLIC_KEY_SIZE) {
                ERROR("Invalid X25519 public key format, length: %zu", other_public_length);
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            shared_secret_length = X25519_SHARED_SECRET_SIZE;
            shared_secret = memory_secure_alloc(shared_secret_length);
            if (shared_secret == NULL) {
                ERROR("memory_secure_alloc failed");
                break;
            }

            // Extract raw private key from PKCS#8
            uint8_t raw_private_key[X25519_KEY_SIZE];
            size_t raw_key_size;
            status = ec_decode_pkcs8_to_raw(raw_private_key, &raw_key_size, sizeof(raw_private_key),
                    header->type_parameters.curve, key, key_length);
            if (status != SA_STATUS_OK) {
                ERROR("ec_decode_pkcs8_to_raw failed");
                break;
            }

            if (raw_key_size != X25519_KEY_SIZE) {
                ERROR("Invalid X25519 private key size: %zu", raw_key_size);
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            // Compute shared secret: curve25519(private_key, other_public)
            curve25519_donna(shared_secret, raw_private_key, raw_other_public);
            memory_memset_unoptimizable(raw_private_key, 0, sizeof(raw_private_key));

            // Skip to stored_key_create
            goto create_stored_key;
        }

        if (header->type_parameters.curve == SA_ELLIPTIC_CURVE_X448) {
            // X448 ECDH using libdecaf
            // The public key comes in SubjectPublicKeyInfo format (DER encoded)
            // For X448, this is typically 68 bytes (12 byte header + 56 byte raw key)
            
            const uint8_t* other_public_bytes = (const uint8_t*)other_public;
            const uint8_t* raw_other_public = NULL;
            size_t raw_other_public_size = 0;
            
            // Simple DER parser: find BIT STRING containing the raw public key
            if (other_public_length >= 68 && other_public_bytes[0] == 0x30) {
                // Skip SEQUENCE and AlgorithmIdentifier, find BIT STRING (tag 0x03)
                for (size_t i = 0; i < other_public_length - 57; i++) {
                    if (other_public_bytes[i] == 0x03 && other_public_bytes[i + 1] == 0x39 && 
                        other_public_bytes[i + 2] == 0x00) {
                        // Found BIT STRING with 57 bytes (0x39), first byte is unused bits (0x00)
                        raw_other_public = &other_public_bytes[i + 3];
                        raw_other_public_size = 56;
                        break;
                    }
                }
            } else if (other_public_length == X448_PUBLIC_KEY_SIZE) {
                // Raw format
                raw_other_public = other_public_bytes;
                raw_other_public_size = other_public_length;
            }
            
            if (raw_other_public == NULL || raw_other_public_size != X448_PUBLIC_KEY_SIZE) {
                ERROR("Invalid X448 public key format, length: %zu", other_public_length);
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            shared_secret_length = X448_SHARED_SECRET_SIZE;
            shared_secret = memory_secure_alloc(shared_secret_length);
            if (shared_secret == NULL) {
                ERROR("memory_secure_alloc failed");
                break;
            }

            // Extract raw private key from PKCS#8
            uint8_t raw_private_key[EC_X448_KEY_SIZE];
            size_t raw_key_size;
            status = ec_decode_pkcs8_to_raw(raw_private_key, &raw_key_size, sizeof(raw_private_key),
                    header->type_parameters.curve, key, key_length);
            if (status != SA_STATUS_OK) {
                ERROR("ec_decode_pkcs8_to_raw failed");
                break;
            }

            if (raw_key_size != EC_X448_KEY_SIZE) {
                ERROR("Invalid X448 private key size: %zu", raw_key_size);
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            // Compute shared secret using libdecaf's X448 function
            // X448 uses decaf_x448 which is simpler than point operations
            if (decaf_x448(shared_secret, raw_other_public, raw_private_key) != DECAF_SUCCESS) {
                ERROR("decaf_x448 failed");
                memory_memset_unoptimizable(raw_private_key, 0, sizeof(raw_private_key));
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
            memory_memset_unoptimizable(raw_private_key, 0, sizeof(raw_private_key));

            // Skip to stored_key_create
            goto create_stored_key;
        }

        if (!is_pcurve(header->type_parameters.curve)) {
            ERROR("Only P-curves supported for ECDH in mbedTLS");
            status = SA_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        mbedtls_pk_type_t expected_type = ec_get_pk_type(header->type_parameters.curve);
        pk = pk_from_pkcs8(expected_type, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        // Parse other public key
        other_pk = calloc(1, sizeof(mbedtls_pk_context));
        if (other_pk == NULL) {
            ERROR("calloc failed");
            break;
        }
        mbedtls_pk_init(other_pk);
        
        int ret = mbedtls_pk_parse_public_key(other_pk, (const unsigned char*)other_public, other_public_length);
        if (ret != 0) {
            ERROR("mbedtls_pk_parse_public_key failed: -0x%04x", -ret);
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // Verify key types match
        if (mbedtls_pk_get_type(pk) != mbedtls_pk_get_type(other_pk)) {
            ERROR("Key type mismatch");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // Get EC keypairs
        mbedtls_ecp_keypair* our_keypair = mbedtls_pk_ec(*pk);
        mbedtls_ecp_keypair* their_keypair = mbedtls_pk_ec(*other_pk);
        if (our_keypair == NULL || their_keypair == NULL) {
            ERROR("mbedtls_pk_ec failed");
            break;
        }

        // Setup ECDH context with our private key
        ret = mbedtls_ecdh_get_params(&ecdh, our_keypair, MBEDTLS_ECDH_OURS);
        if (ret != 0) {
            ERROR("mbedtls_ecdh_get_params(OURS) failed: -0x%04x", -ret);
            break;
        }

        // Setup ECDH context with their public key
        ret = mbedtls_ecdh_get_params(&ecdh, their_keypair, MBEDTLS_ECDH_THEIRS);
        if (ret != 0) {
            ERROR("mbedtls_ecdh_get_params(THEIRS) failed: -0x%04x", -ret);
            break;
        }

        // Compute shared secret
        size_t olen = 0;
        shared_secret_length = (header->size > 66) ? header->size : 66; // Max P-521 size
        shared_secret = memory_secure_alloc(shared_secret_length);
        if (shared_secret == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // Get DRBG context for random number generation
        void* drbg_ctx = rand_get_drbg_context();
        if (drbg_ctx == NULL) {
            ERROR("rand_get_drbg_context failed");
            break;
        }

        ret = mbedtls_ecdh_calc_secret(&ecdh, &olen, shared_secret, 
                                       shared_secret_length, mbedtls_ctr_drbg_random, drbg_ctx);
        if (ret != 0) {
            ERROR("mbedtls_ecdh_calc_secret failed: -0x%04x", -ret);
            break;
        }
        shared_secret_length = olen;

create_stored_key:
        ; // Label needs a statement
        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_shared_secret, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC,
                &type_parameters, shared_secret_length, shared_secret, shared_secret_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (shared_secret != NULL) {
        memory_memset_unoptimizable(shared_secret, 0, shared_secret_length);
        memory_secure_free(shared_secret);
    }

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    if (other_pk != NULL) {
        mbedtls_pk_free(other_pk);
        free(other_pk);
    }
    mbedtls_ecdh_free(&ecdh);

    return status;
}

sa_status ec_sign_ecdsa(
        void* signature,
        size_t* signature_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_pk_context* pk = NULL;
    mbedtls_md_context_t md_ctx;
    uint8_t hash_buf[64]; // Max SHA-512
    uint8_t* hash_to_sign = NULL;
    size_t hash_len = 0;
    mbedtls_mpi r, s;
    
    mbedtls_md_init(&md_ctx);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    
    do {
        const void* key = stored_key_get_key(stored_key);
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

        if (!is_pcurve(header->type_parameters.curve)) {
            ERROR("ED & X curves cannot be used for ECDSA");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        mbedtls_pk_type_t expected_type = ec_get_pk_type(header->type_parameters.curve);
        pk = pk_from_pkcs8(expected_type, key, key_length);
        if (pk == NULL) {
            ERROR("pk_from_pkcs8 failed");
            break;
        }

        if (in == NULL && in_length > 0) {
            ERROR("NULL in");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        size_t ec_signature_length = (size_t) header->size * 2;
        if (signature == NULL) {
            *signature_length = ec_signature_length;
            status = SA_STATUS_OK;
            break;
        }

        if (*signature_length < ec_signature_length) {
            ERROR("Invalid signature_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }
        *signature_length = ec_signature_length;

        mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
        if (md_info == NULL) {
            ERROR("mbedtls_md_info_from_type failed");
            break;
        }

        if (precomputed_digest) {
            // Input is already a hash
            hash_to_sign = (uint8_t*)in;
            hash_len = in_length;
        } else {
            // Need to hash the input first
            int ret = mbedtls_md_setup(&md_ctx, md_info, 0);
            if (ret != 0) {
                ERROR("mbedtls_md_setup failed: -0x%04x", -ret);
                break;
            }

            ret = mbedtls_md_starts(&md_ctx);
            if (ret != 0) {
                ERROR("mbedtls_md_starts failed: -0x%04x", -ret);
                break;
            }

            ret = mbedtls_md_update(&md_ctx, (const unsigned char*)in, in_length);
            if (ret != 0) {
                ERROR("mbedtls_md_update failed: -0x%04x", -ret);
                break;
            }

            ret = mbedtls_md_finish(&md_ctx, hash_buf);
            if (ret != 0) {
                ERROR("mbedtls_md_finish failed: -0x%04x", -ret);
                break;
            }

            hash_to_sign = hash_buf;
            hash_len = mbedtls_md_get_size(md_info);
        }

        // Sign the hash using ECDSA
        mbedtls_ecp_keypair* keypair = mbedtls_pk_ec(*pk);
        if (keypair == NULL) {
            ERROR("mbedtls_pk_ec failed");
            break;
        }

        // Get DRBG context for random number generation
        void* drbg_ctx = rand_get_drbg_context();
        if (drbg_ctx == NULL) {
            ERROR("rand_get_drbg_context failed");
            break;
        }

        int ret = mbedtls_ecdsa_sign(&keypair->grp, &r, &s, &keypair->d,
                                     hash_to_sign, hash_len, mbedtls_ctr_drbg_random, drbg_ctx);
        if (ret != 0) {
            ERROR("mbedtls_ecdsa_sign failed: -0x%04x", -ret);
            break;
        }

        // Export r and s as fixed-size big-endian integers
        uint8_t* signature_bytes = (uint8_t*) signature;
        memory_memset_unoptimizable(signature_bytes, 0, ec_signature_length);
        
        size_t r_len = mbedtls_mpi_size(&r);
        size_t s_len = mbedtls_mpi_size(&s);
        
        if (r_len > header->size || s_len > header->size) {
            ERROR("Signature component too large");
            break;
        }

        // Write r, padded to header->size
        ret = mbedtls_mpi_write_binary(&r, signature_bytes + header->size - r_len, r_len);
        if (ret != 0) {
            ERROR("mbedtls_mpi_write_binary(r) failed: -0x%04x", -ret);
            break;
        }

        // Write s, padded to header->size
        ret = mbedtls_mpi_write_binary(&s, signature_bytes + header->size + header->size - s_len, s_len);
        if (ret != 0) {
            ERROR("mbedtls_mpi_write_binary(s) failed: -0x%04x", -ret);
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (pk != NULL) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    mbedtls_md_free(&md_ctx);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return status;
}

sa_status ec_sign_eddsa(
        void* signature,
        size_t* signature_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_elliptic_curve curve = header->type_parameters.curve;
    if (curve != SA_ELLIPTIC_CURVE_ED25519 && curve != SA_ELLIPTIC_CURVE_ED448) {
        ERROR("Only ED25519 and ED448 curves are supported for EdDSA signing");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* raw_private_key = NULL;
    uint8_t* public_key = NULL;
    
    do {
        // Determine signature size
        size_t expected_signature_length = (curve == SA_ELLIPTIC_CURVE_ED25519) ? 64 : 114;
        
        if (signature == NULL) {
            *signature_length = expected_signature_length;
            status = SA_STATUS_OK;
            break;
        }

        if (*signature_length < expected_signature_length) {
            ERROR("Invalid signature_length: expected %zu, got %zu", expected_signature_length, *signature_length);
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (in == NULL && in_length > 0) {
            ERROR("NULL in with non-zero length");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        // Extract raw private key from PKCS#8 format
        size_t raw_key_size = (curve == SA_ELLIPTIC_CURVE_ED25519) ? 32 : 57;
        raw_private_key = memory_secure_alloc(raw_key_size);
        if (raw_private_key == NULL) {
            ERROR("memory_secure_alloc failed for raw_private_key");
            break;
        }

        const void* key_data = stored_key_get_key(stored_key);
        if (key_data == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        status = ec_extract_raw_private_key(curve, key_data, key_length, raw_private_key, raw_key_size);
        if (status != SA_STATUS_OK) {
            ERROR("ec_extract_raw_private_key failed");
            break;
        }

        // Derive public key
        public_key = memory_secure_alloc(raw_key_size);
        if (public_key == NULL) {
            ERROR("memory_secure_alloc failed for public_key");
            break;
        }

        if (curve == SA_ELLIPTIC_CURVE_ED25519) {
            // ED25519 signing using ed25519-donna
            ed25519_publickey(raw_private_key, public_key);
            ed25519_sign(in, in_length, raw_private_key, public_key, signature);
            *signature_length = 64;
            status = SA_STATUS_OK;
        } else {
            // ED448 signing using libdecaf
            decaf_eddsa_448_keypair_t keypair;
            decaf_ed448_derive_keypair(keypair, raw_private_key);
            decaf_ed448_keypair_sign(signature, keypair, in, in_length, 0, NULL, 0);
            *signature_length = 114; // DECAF_EDDSA_448_SIGNATURE_BYTES
            status = SA_STATUS_OK;
        }
    } while (false);

    if (raw_private_key != NULL) {
        memory_memset_unoptimizable(raw_private_key, 0, (curve == SA_ELLIPTIC_CURVE_ED25519) ? 32 : 57);
        memory_secure_free(raw_private_key);
    }

    if (public_key != NULL) {
        memory_memset_unoptimizable(public_key, 0, (curve == SA_ELLIPTIC_CURVE_ED25519) ? 32 : 57);
        memory_secure_free(public_key);
    }

    return status;
}

sa_status ec_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_generate_parameters_ec* parameters) {

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

    size_t key_size = ec_key_size_from_curve(parameters->curve);
    if (key_size == 0) {
        ERROR("Unknown curve");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* key = NULL;
    size_t key_length = 0;
    mbedtls_pk_context pk;
    mbedtls_ecp_keypair* keypair = NULL;
    
    mbedtls_pk_init(&pk);
    
    do {
        // Handle EdDSA curves (ED25519, ED448) and Montgomery curves (X25519, X448) using external providers
        if (parameters->curve == SA_ELLIPTIC_CURVE_ED25519 || parameters->curve == SA_ELLIPTIC_CURVE_ED448 ||
            parameters->curve == SA_ELLIPTIC_CURVE_X25519 || parameters->curve == SA_ELLIPTIC_CURVE_X448) {
            
            size_t raw_key_size;
            if (parameters->curve == SA_ELLIPTIC_CURVE_ED25519 || parameters->curve == SA_ELLIPTIC_CURVE_X25519)
                raw_key_size = EC_25519_KEY_SIZE;
            else if (parameters->curve == SA_ELLIPTIC_CURVE_ED448)
                raw_key_size = EC_ED448_KEY_SIZE;
            else  // X448
                raw_key_size = EC_X448_KEY_SIZE;
            
            uint8_t* raw_private_key = memory_secure_alloc(raw_key_size);
            if (raw_private_key == NULL) {
                ERROR("memory_secure_alloc failed for raw_private_key");
                break;
            }

            // Generate random private key
            if (!rand_bytes(raw_private_key, raw_key_size)) {
                ERROR("rand_bytes failed");
                memory_memset_unoptimizable(raw_private_key, 0, raw_key_size);
                memory_secure_free(raw_private_key);
                break;
            }

            // Encode to PKCS#8 format
            status = ec_encode_raw_to_pkcs8(parameters->curve, raw_private_key, raw_key_size, &key, &key_length);
            memory_memset_unoptimizable(raw_private_key, 0, raw_key_size);
            memory_secure_free(raw_private_key);

            if (status != SA_STATUS_OK) {
                ERROR("ec_encode_raw_to_pkcs8 failed");
                break;
            }

            // Create stored key
            sa_type_parameters type_parameters;
            memory_memset_unoptimizable(&type_parameters, 0, sizeof(type_parameters));
            type_parameters.curve = parameters->curve;
            status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_EC, &type_parameters, key_size, key,
                    key_length);
            if (status != SA_STATUS_OK) {
                ERROR("stored_key_create failed");
                break;
            }

            status = SA_STATUS_OK;
            break;
        }

        // Handle P-curves using mbedTLS
        if (!is_pcurve(parameters->curve)) {
            const char* curve_name = ec_curve_name(parameters->curve);
            ERROR("Unsupported curve: %d (%s)", parameters->curve, curve_name);
            status = SA_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        mbedtls_ecp_group_id grp_id = ec_get_group_id(parameters->curve);
        if (grp_id == MBEDTLS_ECP_DP_NONE) {
            ERROR("ec_get_group_id failed");
            break;
        }

        // Setup pk_context for EC key
        int ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0) {
            ERROR("mbedtls_pk_setup failed: -0x%04x", -ret);
            break;
        }

        keypair = mbedtls_pk_ec(pk);
        if (keypair == NULL) {
            ERROR("mbedtls_pk_ec failed");
            break;
        }

        // Get DRBG context for random number generation
        void* drbg_ctx = rand_get_drbg_context();
        if (drbg_ctx == NULL) {
            ERROR("rand_get_drbg_context failed");
            break;
        }

        // Generate keypair
        ret = mbedtls_ecp_gen_key(grp_id, keypair, mbedtls_ctr_drbg_random, drbg_ctx);
        if (ret != 0) {
            ERROR("mbedtls_ecp_gen_key failed: -0x%04x", -ret);
            break;
        }

        // Export to PKCS8
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
        type_parameters.curve = parameters->curve;
        status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_EC, &type_parameters, key_size, key,
                key_length);
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
    return status;
}
