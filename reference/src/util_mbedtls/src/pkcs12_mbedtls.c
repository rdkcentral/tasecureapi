/*
 * Copyright 2019-2025 Comcast Cable Communications Management, LLC
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
 * PKCS#12 Parser using mbedTLS
 * 
 * This implements PKCS#12 file parsing using only mbedTLS APIs,
 * replacing OpenSSL dependency for load_pkcs12_secret_key().
 */

#include "pkcs12_mbedtls.h"
#include "mbedtls_header.h"
#include "root_keystore.h"

/* ========== PKCS Standards ========== */

#include <mbedtls/pkcs5.h>
#include <mbedtls/pkcs12.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// Helper to extract relative path from __FILE__
// Returns last 2 path components (e.g., "src/pkcs12_mbedtls.c")
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static inline const char* get_filename(const char* path) {
    const char* file = path;
    const char* last_slash = NULL;
    const char* second_last_slash = NULL;
    
    // Find the last two '/' characters
    for (const char* p = path; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            second_last_slash = last_slash;
            last_slash = p;
        }
    }
    
    // If we found at least 2 slashes, return from the second-to-last one
    if (second_last_slash != NULL) {
        file = second_last_slash + 1;
    } else if (last_slash != NULL) {
        // Only 1 slash found, return from the last one
        file = last_slash + 1;
    }
    // else: no slashes, return the original path (just filename)
    
    return file;
}
#pragma GCC diagnostic pop

// Debug logging macro - controlled by VERBOSE_LOG
#ifdef VERBOSE_LOG
#define DEBUG_PRINT(fmt, ...) \
    printf("[%s:%d:%s] " fmt, get_filename(__FILE__), __LINE__, __func__, ##__VA_ARGS__)
// Print hex bytes without prefix or newline, for inline hex dumps
#define DEBUG_PRINT_HEX(fmt, ...) \
    printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while(0)
#define DEBUG_PRINT_HEX(...) do {} while(0)
#endif

// PKCS#12 Object Identifiers
#define OID_PKCS7_DATA              "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01"
#define OID_PKCS7_ENCRYPTED_DATA    "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06"
#define OID_PKCS9_FRIENDLY_NAME     "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x14"
#define OID_PKCS12_SECRET_BAG       "\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x05"
#define OID_PKCS12_PKCS8_KEY_BAG    "\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x02"
#define OID_PBES2                   "\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0D"
#define OID_PBKDF2                  "\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C"
#define OID_AES128_CBC              "\x60\x86\x48\x01\x65\x03\x04\x01\x02"
#define OID_AES256_CBC              "\x60\x86\x48\x01\x65\x03\x04\x01\x2A"
#define OID_DES_EDE3_CBC            "\x2A\x86\x48\x86\xF7\x0D\x03\x07"

// PKCS#12 ID types for key derivation
#define PKCS12_KEY_ID    1
#define PKCS12_IV_ID     2
#define PKCS12_MAC_ID    3

/**
 * @brief PKCS#12 format version identifier
 * 
 * Defines the version number for the PKCS#12 personal information exchange
 * syntax standard. This value indicates which version of the PKCS#12
 * specification is being used for encoding/decoding operations.
 * 
 * @note PKCS#12 v1.1 is the current standard (RFC 7292)
 */
#define PKCS12_VERSION    3

typedef struct {
    unsigned char *data;
    size_t len;
} pkcs12_buf_t;

typedef struct {
    char name[256];
    size_t name_len;
    unsigned char key_data[512];
    size_t key_len;
} pkcs12_secret_t;

/**
 * Convert ASCII password to BMPString (UTF-16BE with null terminator)
 * PKCS#12 requires passwords in BMPString format for key derivation.
 * 
 * @param ascii_pwd  ASCII password string
 * @param bmp_pwd    Output buffer for BMPString (must be at least (strlen(ascii_pwd)+1)*2 bytes)
 * @param bmp_len    Output: length of BMPString in bytes
 * @return 0 on success, negative on error
 */
static int convert_to_bmpstring(const char *ascii_pwd, unsigned char *bmp_pwd, size_t *bmp_len)
{
    size_t ascii_len = strlen(ascii_pwd);
    
    // Convert each ASCII character to UTF-16BE (2 bytes, big-endian)
    for (size_t i = 0; i < ascii_len; i++) {
        bmp_pwd[i * 2] = 0x00;
        bmp_pwd[i * 2 + 1] = (unsigned char)ascii_pwd[i];
    }
    
    // Add null terminator (0x00 0x00)
    bmp_pwd[ascii_len * 2] = 0x00;
    bmp_pwd[ascii_len * 2 + 1] = 0x00;
    
    *bmp_len = (ascii_len + 1) * 2;  // +1 for null terminator
    return 0;
}

/**
 * Parse ASN.1 algorithm identifier and extract parameters
 */
static int parse_algorithm_identifier(unsigned char **p, 
                                      const unsigned char *end,
                                      mbedtls_asn1_buf *alg_oid,
                                      mbedtls_asn1_buf *params)
{
    int ret;
    size_t len;

    // AlgorithmIdentifier ::= SEQUENCE {
    //     algorithm   OBJECT IDENTIFIER,
    //     parameters  ANY DEFINED BY algorithm OPTIONAL
    // }
    
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    const unsigned char *alg_end = *p + len;

    // Get algorithm OID
    if ((ret = mbedtls_asn1_get_tag(p, alg_end, &alg_oid->len,
            MBEDTLS_ASN1_OID)) != 0) {
        return ret;
    }
    alg_oid->p = *p;
    *p += alg_oid->len;

    // Get parameters if present
    if (*p < alg_end) {
        params->p = *p;
        params->len = alg_end - *p;
        *p = (unsigned char *)alg_end;
    } else {
        params->p = NULL;
        params->len = 0;
    }

    return 0;
}

/**
 * Derive PKCS#12 key using mbedTLS
 */
static int pkcs12_derive_key(const char *password,
                             const unsigned char *salt,
                             size_t salt_len,
                             int iterations,
                             int id,
                             mbedtls_md_type_t md_type,
                             unsigned char *output,
                             size_t output_len)
{
    // Convert ASCII password to BMPString (UTF-16BE with null terminator)
    unsigned char bmp_pwd[512];
    size_t bmp_len;
    int ret = convert_to_bmpstring(password, bmp_pwd, &bmp_len);
    if (ret != 0) {
        return ret;
    }
    
    DEBUG_PRINT("DEBUG: Password length = %zu, BMPString length = %zu\n", 
           strlen(password), bmp_len);
    DEBUG_PRINT("DEBUG: BMPString = ");
    for (size_t i = 0; i < bmp_len && i < 36; i++) {
        DEBUG_PRINT_HEX("%02x", bmp_pwd[i]);
    }
    DEBUG_PRINT("\n");
    
    ret = mbedtls_pkcs12_derivation(output, output_len,
                                    bmp_pwd, bmp_len,
                                    salt, salt_len,
                                    md_type,
                                    id, iterations);
    
    // Clear sensitive data
    mbedtls_platform_zeroize(bmp_pwd, sizeof(bmp_pwd));
    
    return ret;
}

/**
 * Decrypt PKCS#8 EncryptedPrivateKeyInfo using PKCS#12 PBE
 */
static int decrypt_pkcs8_pbe(const unsigned char *enc_data,
                             size_t enc_len,
                             const char *password,
                             const unsigned char *salt,
                             size_t salt_len,
                             int iterations,
                             const char *cipher_oid,
                             size_t cipher_oid_len,
                             unsigned char *output,
                             size_t *output_len)
{
    int ret;
    mbedtls_cipher_type_t cipher_type;
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t cipher_ctx;
    unsigned char key[32];
    unsigned char iv[16];
    size_t key_len, iv_len;

    // Determine cipher type from OID
    if (cipher_oid_len == 9 && memcmp(cipher_oid, OID_AES128_CBC, 9) == 0) {
        cipher_type = MBEDTLS_CIPHER_AES_128_CBC;
        key_len = 16;
        iv_len = 16;
    } else if (cipher_oid_len == 9 && memcmp(cipher_oid, OID_AES256_CBC, 9) == 0) {
        cipher_type = MBEDTLS_CIPHER_AES_256_CBC;
        key_len = 32;
        iv_len = 16;
    } else if (cipher_oid_len == 8 && memcmp(cipher_oid, OID_DES_EDE3_CBC, 8) == 0) {
        cipher_type = MBEDTLS_CIPHER_DES_EDE3_CBC;
        key_len = 24;
        iv_len = 8;
    } else {
        printf("Unsupported cipher OID\n");
        return -1;
    }

    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    if (cipher_info == NULL) {
        return -1;
    }

    // Derive key and IV using PKCS#12 KDF
    ret = pkcs12_derive_key(password, salt, salt_len, iterations,
                           PKCS12_KEY_ID, MBEDTLS_MD_SHA1,
                           key, key_len);
    if (ret != 0) {
        return ret;
    }

    ret = pkcs12_derive_key(password, salt, salt_len, iterations,
                           PKCS12_IV_ID, MBEDTLS_MD_SHA1,
                           iv, iv_len);
    if (ret != 0) {
        return ret;
    }

    // Decrypt
    mbedtls_cipher_init(&cipher_ctx);
    
    ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_cipher_setkey(&cipher_ctx, key, key_len * 8,
                                MBEDTLS_DECRYPT);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_cipher_set_padding_mode(&cipher_ctx, 
                                          MBEDTLS_PADDING_PKCS7);
    if (ret != 0) {
        goto cleanup;
    }

    size_t olen;
    ret = mbedtls_cipher_update(&cipher_ctx, enc_data, enc_len, 
                                output, &olen);
    if (ret != 0) {
        goto cleanup;
    }

    size_t final_len;
    ret = mbedtls_cipher_finish(&cipher_ctx, output + olen, &final_len);
    if (ret != 0) {
        goto cleanup;
    }

    *output_len = olen + final_len;

cleanup:
    mbedtls_cipher_free(&cipher_ctx);
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    
    return ret;
}

/**
 * Parse PKCS#12 MAC data and verify password
 */
static int verify_pkcs12_mac(const unsigned char *auth_safe_data,
                            size_t auth_safe_len,
                            unsigned char **p,
                            const unsigned char *end,
                            const char *password)
{
    int ret;
    size_t len;
    mbedtls_asn1_buf mac_oid, params;
    unsigned char *salt;
    size_t salt_len;
    int iterations = 1;
    unsigned char stored_mac[64];
    size_t mac_len;
    unsigned char computed_mac[64];
    unsigned int computed_mac_len = 0;  // Initialize to avoid unused warning
    (void)computed_mac_len; // Suppress unused warning

    // MacData ::= SEQUENCE {
    //     mac         DigestInfo,
    //     macSalt     OCTET STRING,
    //     iterations  INTEGER DEFAULT 1
    // }

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    const unsigned char *mac_end = *p + len;

    // Parse DigestInfo
    if ((ret = mbedtls_asn1_get_tag(p, mac_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    const unsigned char *digest_end = *p + len;

    // Get digest algorithm
    ret = parse_algorithm_identifier(p, digest_end, &mac_oid, &params);
    if (ret != 0) {
        return ret;
    }

    // Get MAC value
    if ((ret = mbedtls_asn1_get_tag(p, digest_end, &mac_len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return ret;
    }
    memcpy(stored_mac, *p, mac_len);
    *p += mac_len;

    // Get salt
    if ((ret = mbedtls_asn1_get_tag(p, mac_end, &salt_len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return ret;
    }
    salt = *p;
    *p += salt_len;

    // Get iterations (optional)
    if (*p < mac_end) {
        if ((ret = mbedtls_asn1_get_int(p, mac_end, &iterations)) != 0) {
            return ret;
        }
    }

    // Determine hash algorithm from OID
    mbedtls_md_type_t md_type;
    DEBUG_PRINT("DEBUG: MAC OID length = %zu\n", mac_oid.len);
    DEBUG_PRINT("DEBUG: MAC OID = ");
    for (size_t i = 0; i < mac_oid.len; i++) {
        DEBUG_PRINT_HEX("%02x", mac_oid.p[i]);
    }
    DEBUG_PRINT("\n");
    DEBUG_PRINT("DEBUG: Iterations = %d\n", iterations);
    DEBUG_PRINT("DEBUG: Salt length = %zu\n", salt_len);
    
    if (mac_oid.len == 9 && memcmp(mac_oid.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 9) == 0) {
        md_type = MBEDTLS_MD_SHA256;  // OID for SHA-256
        DEBUG_PRINT("DEBUG: Using SHA-256 for MAC\n");
    } else if (mac_oid.len == 5 && memcmp(mac_oid.p, "\x2b\x0e\x03\x02\x1a", 5) == 0) {
        md_type = MBEDTLS_MD_SHA1;    // OID for SHA-1
        DEBUG_PRINT("DEBUG: Using SHA-1 for MAC\n");
    } else if (mac_oid.len == 9 && memcmp(mac_oid.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", 9) == 0) {
        md_type = MBEDTLS_MD_SHA224;  // OID for SHA-224
        DEBUG_PRINT("DEBUG: Using SHA-224 for MAC\n");
    } else if (mac_oid.len == 9 && memcmp(mac_oid.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", 9) == 0) {
        md_type = MBEDTLS_MD_SHA384;  // OID for SHA-384
        DEBUG_PRINT("DEBUG: Using SHA-384 for MAC\n");
    } else if (mac_oid.len == 9 && memcmp(mac_oid.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 9) == 0) {
        md_type = MBEDTLS_MD_SHA512;  // OID for SHA-512
        DEBUG_PRINT("DEBUG: Using SHA-512 for MAC\n");
    } else {
        // Default to SHA-1 for compatibility
        md_type = MBEDTLS_MD_SHA1;
        DEBUG_PRINT("DEBUG: Unknown MAC OID, defaulting to SHA-1\n");
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }
    size_t md_size = mbedtls_md_get_size(md_info);
    
    unsigned char mac_key[64];
    ret = pkcs12_derive_key(password, salt, salt_len, iterations,
                           PKCS12_MAC_ID, md_type,
                           mac_key, md_size);
    if (ret != 0) {
        return ret;
    }

    // Compute HMAC
    ret = mbedtls_md_hmac(md_info, mac_key, md_size,
                         auth_safe_data, auth_safe_len,
                         computed_mac);
    if (ret != 0) {
        mbedtls_platform_zeroize(mac_key, sizeof(mac_key));
        return ret;
    }

    mbedtls_platform_zeroize(mac_key, sizeof(mac_key));

    // Compare MACs
    DEBUG_PRINT("DEBUG: Stored MAC length = %zu, computed length = %zu\n", mac_len, md_size);
    DEBUG_PRINT("DEBUG: Stored MAC = ");
    for (size_t i = 0; i < mac_len; i++) DEBUG_PRINT_HEX("%02x", stored_mac[i]);
    printf("\n");
    DEBUG_PRINT("DEBUG: Computed MAC = ");
    for (size_t i = 0; i < md_size; i++) DEBUG_PRINT_HEX("%02x", computed_mac[i]);
    printf("\n");
    
    if (mac_len != md_size || 
        memcmp(stored_mac, computed_mac, mac_len) != 0) {
        DEBUG_PRINT("DEBUG: MAC mismatch!\n");
        return MBEDTLS_ERR_CIPHER_AUTH_FAILED;
    }

    DEBUG_PRINT("DEBUG: MAC verified successfully!\n");
    return 0;
}

/**
 * Parse PKCS#12 attributes (friendlyName, localKeyId, etc.)
 */
static int parse_safebag_attributes(unsigned char **p,
                                   const unsigned char *end,
                                   char *friendly_name,
                                   size_t *name_len)
{
    int ret;
    size_t len;

    DEBUG_PRINT("DEBUG: parse_safebag_attributes called, p=%p, end=%p\n", (void*)*p, (void*)end);
    *name_len = 0;

    // Attributes are optional
    if (*p >= end) {
        DEBUG_PRINT("DEBUG: No attributes (p >= end)\n");
        return 0;
    }

    // SET OF Attribute
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
        DEBUG_PRINT("DEBUG: No attributes SET found, ret=%d\n", ret);
        return 0; // Attributes are optional
    }

    DEBUG_PRINT("DEBUG: Found attributes SET, length=%zu\n", len);

    const unsigned char *attrs_end = *p + len;

    while (*p < attrs_end) {
        // Attribute ::= SEQUENCE
        if ((ret = mbedtls_asn1_get_tag(p, attrs_end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return ret;
        }

        const unsigned char *attr_end = *p + len;

        // Get attribute type OID
        size_t oid_len;
        if ((ret = mbedtls_asn1_get_tag(p, attr_end, &oid_len,
                MBEDTLS_ASN1_OID)) != 0) {
            return ret;
        }

        unsigned char *oid = *p;
        *p += oid_len;

        // Get attribute value SET
        if ((ret = mbedtls_asn1_get_tag(p, attr_end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
            return ret;
        }

        // Check if this is friendlyName
        if (oid_len == 9 && memcmp(oid, OID_PKCS9_FRIENDLY_NAME, 9) == 0) {
            DEBUG_PRINT("DEBUG: Found friendlyName attribute!\n");
            // FriendlyName is BMPString (UCS-2)
            size_t bmp_len;
            if ((ret = mbedtls_asn1_get_tag(p, attr_end, &bmp_len,
                    MBEDTLS_ASN1_BMP_STRING)) != 0) {
                DEBUG_PRINT("DEBUG: Failed to parse BMPString, ret=%d\n", ret);
                return ret;
            }

            DEBUG_PRINT("DEBUG: BMPString length=%zu\n", bmp_len);
            
            // Debug: Print raw BMPString bytes
            DEBUG_PRINT("DEBUG: BMPString raw bytes: ");
            for (size_t i = 0; i < bmp_len && i < 64; i++) {
                DEBUG_PRINT_HEX("%02x", (*p)[i]);
            }
  
            
            // Convert UCS-2 to ASCII (simple conversion, only works for ASCII chars)
            size_t out_len = 0;
            for (size_t i = 0; i < bmp_len && i < 510; i += 2) {
                if ((*p)[i] == 0 && out_len < 255) {
                    friendly_name[out_len++] = (*p)[i + 1];
                }
            }
            friendly_name[out_len] = '\0';
            
            // Note: Don't truncate - tests expect full length names
            // Note: Keep original case - don't convert to uppercase
            
            *name_len = out_len;
            DEBUG_PRINT("DEBUG: Extracted friendlyName: '%s', length=%zu (truncated to match OpenSSL)\n", friendly_name, out_len);
            
            // Debug: Print extracted name as hex bytes
            DEBUG_PRINT("DEBUG: friendlyName hex bytes: ");
            for (size_t i = 0; i < out_len; i++) {
                DEBUG_PRINT_HEX("%02x ", (unsigned char)friendly_name[i]);
            }
            DEBUG_PRINT("\n");
            *p += bmp_len;
        } else {
            DEBUG_PRINT("DEBUG: Skipping non-friendlyName attribute (OID len=%zu)\n", oid_len);
            *p = (unsigned char *)attr_end;
        }
    }

    return 0;
}

/**
 * Parse and decrypt a SafeBag containing a secret key
 */
static int parse_secret_safebag(unsigned char **p,
                               const unsigned char *end,
                               const char *password,
                               pkcs12_secret_t *secret)
{
    int ret;
    size_t len;
    mbedtls_asn1_buf bag_oid;

    DEBUG_PRINT("DEBUG: parse_secret_safebag called, p=%p, end=%p\n", (void*)*p, (void*)end);

    // SafeBag ::= SEQUENCE {
    //     bagId          OBJECT IDENTIFIER,
    //     bagValue       [0] EXPLICIT ANY DEFINED BY bagId,
    //     bagAttributes  SET OF PKCS12Attribute OPTIONAL
    // }

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get SafeBag SEQUENCE, ret = %d\n", ret);
        return ret;
    }

    DEBUG_PRINT("DEBUG: SafeBag SEQUENCE length = %zu\n", len);
    const unsigned char *safebag_end = *p + len;

    // Get bagId
    if ((ret = mbedtls_asn1_get_tag(p, safebag_end, &bag_oid.len,
            MBEDTLS_ASN1_OID)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get bagId OID, ret = %d\n", ret);
        return ret;
    }
    bag_oid.p = *p;
    *p += bag_oid.len;

    DEBUG_PRINT("DEBUG: bagId length = %zu, first bytes = %02x %02x %02x\n", 
           bag_oid.len, bag_oid.p[0], bag_oid.p[1], bag_oid.p[2]);

    // Check if this is a secretBag
    if (bag_oid.len != 11 || 
        memcmp(bag_oid.p, OID_PKCS12_SECRET_BAG, 11) != 0) {
        // Not a secret bag, skip it
        DEBUG_PRINT("DEBUG: Not a secretBag, skipping to end\n");
        *p = (unsigned char *)safebag_end;
        return -1;
    }

    DEBUG_PRINT("DEBUG: Found secretBag!\n");

    // Get [0] EXPLICIT wrapper
    if ((ret = mbedtls_asn1_get_tag(p, safebag_end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get [0] EXPLICIT wrapper, ret = %d\n", ret);
        return ret;
    }

    DEBUG_PRINT("DEBUG: Got [0] wrapper, length = %zu\n", len);
    const unsigned char *bagvalue_end = *p + len;

    // SecretBag ::= SEQUENCE {
    //     secretTypeId   OBJECT IDENTIFIER,
    //     secretValue    [0] EXPLICIT OCTET STRING
    // }

    if ((ret = mbedtls_asn1_get_tag(p, bagvalue_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get SecretBag SEQUENCE, ret = %d\n", ret);
        return ret;
    }

    DEBUG_PRINT("DEBUG: SecretBag SEQUENCE length = %zu\n", len);
    const unsigned char *secretbag_end = *p + len;

    // Skip secretTypeId OID
    size_t oid_len;
    if ((ret = mbedtls_asn1_get_tag(p, secretbag_end, &oid_len,
            MBEDTLS_ASN1_OID)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get secretTypeId OID, ret = %d\n", ret);
        return ret;
    }
    DEBUG_PRINT("DEBUG: secretTypeId OID length = %zu\n", oid_len);
    *p += oid_len;

    // Get [0] EXPLICIT wrapper for encrypted data
    if ((ret = mbedtls_asn1_get_tag(p, secretbag_end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get [0] wrapper for encrypted data, ret = %d\n", ret);
        return ret;
    }

    DEBUG_PRINT("DEBUG: Got [0] wrapper for encrypted data, length = %zu\n", len);
    const unsigned char *enc_wrapper_end = *p + len;

    // The encrypted data might be wrapped in an OCTET STRING
    // Try to get OCTET STRING first
    size_t octet_len;
    int octet_ret = mbedtls_asn1_get_tag(p, enc_wrapper_end, &octet_len,
            MBEDTLS_ASN1_OCTET_STRING);
    
    if (octet_ret == 0) {
        DEBUG_PRINT("DEBUG: Found OCTET STRING wrapper, length = %zu\n", octet_len);
        DEBUG_PRINT("DEBUG: Next byte after OCTET STRING tag: 0x%02x\n", **p);
        enc_wrapper_end = *p + octet_len;
    } else {
        DEBUG_PRINT("DEBUG: No OCTET STRING wrapper, first byte = 0x%02x\n", **p);
    }

    // This contains PKCS#8 EncryptedPrivateKeyInfo
    // EncryptedPrivateKeyInfo ::= SEQUENCE {
    //     encryptionAlgorithm  AlgorithmIdentifier,
    //     encryptedData        OCTET STRING
    // }

    if ((ret = mbedtls_asn1_get_tag(p, enc_wrapper_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get EncryptedPrivateKeyInfo SEQUENCE, ret = %d\n", ret);
        DEBUG_PRINT("DEBUG: Current byte: 0x%02x\n", **p);
        return ret;
    }

    const unsigned char *enc_end = *p + len;

    // Parse encryption algorithm
    mbedtls_asn1_buf enc_alg_oid, enc_params;
    ret = parse_algorithm_identifier(p, enc_end, &enc_alg_oid, &enc_params);
    if (ret != 0) {
        return ret;
    }

    // Get encrypted data
    size_t enc_data_len;
    if ((ret = mbedtls_asn1_get_tag(p, enc_end, &enc_data_len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return ret;
    }
    unsigned char *enc_data = *p;
    DEBUG_PRINT("DEBUG: enc_data first 16 bytes: ");
    for (size_t i = 0; i < (enc_data_len < 16 ? enc_data_len : 16); i++) {
        DEBUG_PRINT_HEX("%02x", enc_data[i]);
    }
    printf("\n");
    *p += enc_data_len;

    // Parse encryption parameters to get salt and iterations
    unsigned char *param_p = enc_params.p;
    const unsigned char *param_end = enc_params.p + enc_params.len;

    DEBUG_PRINT("DEBUG: enc_params length = %zu\n", enc_params.len);

    // PBES2-params ::= SEQUENCE {
    //     keyDerivationFunc AlgorithmIdentifier,
    //     encryptionScheme  AlgorithmIdentifier
    // }

    if ((ret = mbedtls_asn1_get_tag(&param_p, param_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        DEBUG_PRINT("DEBUG: Not PBES2, trying simpler PBE scheme\n");
        // Try simpler PBE scheme
        param_p = enc_params.p;
        
        // Get salt
        size_t salt_len;
        if ((ret = mbedtls_asn1_get_tag(&param_p, param_end, &salt_len,
                MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }
        unsigned char *salt = param_p;
        param_p += salt_len;

        // Get iterations
        int iterations;
        if ((ret = mbedtls_asn1_get_int(&param_p, param_end, &iterations)) != 0) {
            return ret;
        }

        DEBUG_PRINT("DEBUG: Attempting decryption with salt_len=%zu, iterations=%d\n", salt_len, iterations);

        // Decrypt using PKCS#12 PBE
        size_t output_len;
        unsigned char decrypted[512];
        ret = decrypt_pkcs8_pbe(enc_data, enc_data_len, password,
                               salt, salt_len, iterations,
                               (const char *)enc_alg_oid.p, enc_alg_oid.len,
                               decrypted, &output_len);
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: Decryption failed, ret = %d\n", ret);
            return ret;
        }

        DEBUG_PRINT("DEBUG: Decryption succeeded, output_len = %zu\n", output_len);

        // Extract the actual key from PKCS#8 PrivateKeyInfo
        // PrivateKeyInfo ::= SEQUENCE {
        //     version             INTEGER,
        //     privateKeyAlgorithm AlgorithmIdentifier,
        //     privateKey          OCTET STRING
        // }

        unsigned char *key_p = decrypted;
        const unsigned char *key_end = decrypted + output_len;

        if ((ret = mbedtls_asn1_get_tag(&key_p, key_end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return ret;
        }

        // Skip version
        int version;
        if ((ret = mbedtls_asn1_get_int(&key_p, key_end, &version)) != 0) {
            return ret;
        }

        // Skip algorithm identifier
        mbedtls_asn1_buf alg_oid, alg_params;
        ret = parse_algorithm_identifier(&key_p, key_end, &alg_oid, &alg_params);
        if (ret != 0) {
            return ret;
        }

        // Get privateKey OCTET STRING
        size_t key_len;
        if ((ret = mbedtls_asn1_get_tag(&key_p, key_end, &key_len,
                MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }

        // Copy key data
        if (key_len > sizeof(secret->key_data)) {
            return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        }

        DEBUG_PRINT("DEBUG: Extracting key, key_len = %zu\n", key_len);
        memcpy(secret->key_data, key_p, key_len);
        secret->key_len = key_len;
        DEBUG_PRINT("DEBUG: Key extracted, secret->key_len = %zu\n", secret->key_len);
    } else {
        DEBUG_PRINT("DEBUG: Found PBES2, implementing decryption...\n");
        
        // PBES2: param_p is now pointing at the content of the PBES2-params SEQUENCE
        // which contains: keyDerivationFunc and encryptionScheme
        
        const unsigned char *pbes2_end = param_p + len;
        
        // Parse keyDerivationFunc (PBKDF2)
        mbedtls_asn1_buf kdf_oid, kdf_params;
        ret = parse_algorithm_identifier(&param_p, pbes2_end, &kdf_oid, &kdf_params);
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: Failed to parse KDF algorithm, ret = %d\n", ret);
            return ret;
        }
        
        // Parse encryptionScheme (e.g., AES-CBC)
        mbedtls_asn1_buf enc_scheme_oid, enc_scheme_params;
        ret = parse_algorithm_identifier(&param_p, pbes2_end, &enc_scheme_oid, &enc_scheme_params);
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: Failed to parse encryption scheme, ret = %d\n", ret);
            return ret;
        }
        
        DEBUG_PRINT("DEBUG: Encryption scheme OID length = %zu, bytes: ", enc_scheme_oid.len);
        for (size_t i = 0; i < enc_scheme_oid.len; i++) {
            DEBUG_PRINT_HEX("%02x", enc_scheme_oid.p[i]);
        }
        printf("\n");
        
        // Determine algorithm and key length from OID
        // AES-128-CBC: 2.16.840.1.101.3.4.1.2  (last byte = 0x02)
        // AES-192-CBC: 2.16.840.1.101.3.4.1.22 (last byte = 0x16)
        // AES-256-CBC: 2.16.840.1.101.3.4.1.42 (last byte = 0x2a)
        size_t key_len_needed = 16; // Default to AES-128
        mbedtls_cipher_type_t cipher_type = MBEDTLS_CIPHER_AES_128_CBC;
        
        if (enc_scheme_oid.len == 9 && memcmp(enc_scheme_oid.p, "\x60\x86\x48\x01\x65\x03\x04\x01", 8) == 0) {
            if (enc_scheme_oid.p[8] == 0x02) {
                key_len_needed = 16;
                cipher_type = MBEDTLS_CIPHER_AES_128_CBC;
                DEBUG_PRINT("DEBUG: Detected AES-128-CBC\n");
            } else if (enc_scheme_oid.p[8] == 0x16) {
                key_len_needed = 24;
                cipher_type = MBEDTLS_CIPHER_AES_192_CBC;
                DEBUG_PRINT("DEBUG: Detected AES-192-CBC\n");
            } else if (enc_scheme_oid.p[8] == 0x2a) {
                key_len_needed = 32;
                cipher_type = MBEDTLS_CIPHER_AES_256_CBC;
                DEBUG_PRINT("DEBUG: Detected AES-256-CBC\n");
            }
        }
        
        // Parse PBKDF2 parameters: SEQUENCE { salt OCTET STRING, iterationCount INTEGER, ... }
        unsigned char *kdf_p = kdf_params.p;
        const unsigned char *kdf_end = kdf_params.p + kdf_params.len;
        
        if ((ret = mbedtls_asn1_get_tag(&kdf_p, kdf_end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return ret;
        }
        
        // Get salt
        size_t salt_len;
        if ((ret = mbedtls_asn1_get_tag(&kdf_p, kdf_end, &salt_len,
                MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }
        unsigned char *salt = kdf_p;
        kdf_p += salt_len;
        
        // Get iterations
        int iterations;
        if ((ret = mbedtls_asn1_get_int(&kdf_p, kdf_end, &iterations)) != 0) {
            return ret;
        }
        
        DEBUG_PRINT("DEBUG: PBES2 - salt_len=%zu, iterations=%d\n", salt_len, iterations);
        
        // Parse encryption scheme parameters (IV)
        unsigned char *enc_p = enc_scheme_params.p;
        size_t iv_len;
        if ((ret = mbedtls_asn1_get_tag(&enc_p, enc_scheme_params.p + enc_scheme_params.len, &iv_len,
                MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }
        unsigned char *iv = enc_p;
        
        DEBUG_PRINT("DEBUG: PBES2 - IV length=%zu\n", iv_len);
        
        // Derive key using PBKDF2
        // Try UTF-8 password (standard for PBES2) instead of BMPString
        
        unsigned char derived_key[64]; // Make room for 256-bit keys
        // Try SHA-256 (matching the MAC algorithm) - mbedTLS 2.16.10 API
        mbedtls_md_context_t md_ctx;
        mbedtls_md_init(&md_ctx);
        ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: mbedtls_md_setup failed, ret = %d\n", ret);
            mbedtls_md_free(&md_ctx);
            return ret;
        }
        
        ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
                                        (const unsigned char *)password, strlen(password),
                                        salt, salt_len, iterations,
                                        key_len_needed, derived_key);
        mbedtls_md_free(&md_ctx);
        
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: PBKDF2 failed, ret = %d\n", ret);
            return ret;
        }
        
        DEBUG_PRINT("DEBUG: PBKDF2 succeeded, key derived (%zu bytes)\n", key_len_needed);
        DEBUG_PRINT("DEBUG: Derived key: ");
        for (size_t i = 0; i < key_len_needed; i++) {
            DEBUG_PRINT_HEX("%02x", derived_key[i]);
        }
        printf("\n");
        DEBUG_PRINT("DEBUG: IV: ");
        for (size_t i = 0; i < iv_len; i++) {
            DEBUG_PRINT_HEX("%02x", iv[i]);
        }
        printf("\n");
        DEBUG_PRINT("DEBUG: Encrypted data length: %zu\n", enc_data_len);
        
        // Decrypt using detected cipher
        mbedtls_cipher_context_t ctx;
        mbedtls_cipher_init(&ctx);
        
        const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        ret = mbedtls_cipher_setup(&ctx, cipher_info);
        if (ret != 0) {
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        
        ret = mbedtls_cipher_setkey(&ctx, derived_key, key_len_needed * 8, MBEDTLS_DECRYPT);
        if (ret != 0) {
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        
        ret = mbedtls_cipher_set_iv(&ctx, iv, iv_len);
        if (ret != 0) {
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        
        ret = mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);
        if (ret != 0) {
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        
        unsigned char decrypted[512];
        size_t output_len = 0;
        ret = mbedtls_cipher_update(&ctx, enc_data, enc_data_len, decrypted, &output_len);
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: Cipher update failed, ret = %d\n", ret);
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        
        DEBUG_PRINT("DEBUG: Cipher update succeeded, output_len = %zu\n", output_len);
        
        size_t final_len = 0;
        ret = mbedtls_cipher_finish(&ctx, decrypted + output_len, &final_len);
        if (ret != 0) {
            DEBUG_PRINT("DEBUG: Cipher finish failed, ret = %d\n", ret);
            DEBUG_PRINT("DEBUG: Decrypted so far (first 32 bytes): ");
            for (size_t i = 0; i < (output_len < 32 ? output_len : 32); i++) {
                DEBUG_PRINT_HEX("%02x", decrypted[i]);
            }
            printf("\n");
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        mbedtls_cipher_free(&ctx);
        
        output_len += final_len;
        DEBUG_PRINT("DEBUG: Decryption succeeded, output_len = %zu\n", output_len);
        
        // Extract the actual key from PKCS#8 PrivateKeyInfo
        unsigned char *key_p = decrypted;
        const unsigned char *key_end = decrypted + output_len;

        if ((ret = mbedtls_asn1_get_tag(&key_p, key_end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return ret;
        }

        // Skip version
        int version;
        if ((ret = mbedtls_asn1_get_int(&key_p, key_end, &version)) != 0) {
            return ret;
        }

        // Skip algorithm identifier
        mbedtls_asn1_buf alg_oid, alg_params;
        ret = parse_algorithm_identifier(&key_p, key_end, &alg_oid, &alg_params);
        if (ret != 0) {
            return ret;
        }

        // Get privateKey OCTET STRING
        size_t priv_key_len;
        if ((ret = mbedtls_asn1_get_tag(&key_p, key_end, &priv_key_len,
                MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }

        // Copy key data
        if (priv_key_len > sizeof(secret->key_data)) {
            return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        }

        DEBUG_PRINT("DEBUG: Extracting key, key_len = %zu\n", priv_key_len);
        memcpy(secret->key_data, key_p, priv_key_len);
        secret->key_len = priv_key_len;
        DEBUG_PRINT("DEBUG: Key extracted, secret->key_len = %zu\n", secret->key_len);
    }

    // Parse attributes (friendlyName) - *p should already be positioned after bagValue
    DEBUG_PRINT("DEBUG: About to parse attributes, p=%p, safebag_end=%p\n", (void*)*p, (void*)safebag_end);
    ret = parse_safebag_attributes(p, safebag_end,
                                   secret->name, &secret->name_len);
    DEBUG_PRINT("DEBUG: parse_safebag_attributes returned %d, name_len=%zu\n", ret, secret->name_len);

    return 0;
}

/**
 * Parse PKCS#7 Data (unencrypted SafeBags)
 */
static int parse_pkcs7_data(unsigned char **p,
                           const unsigned char *end,
                           const char *password,
                           bool requested_common_root,
                           pkcs12_secret_t *secret)
{
    int ret;
    size_t len;

    DEBUG_PRINT("DEBUG: parse_pkcs7_data called, requested_common_root = %s\n", 
                requested_common_root ? "true" : "false");

    // Get OCTET STRING containing SafeBags
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get OCTET STRING, ret = %d\n", ret);
        return ret;
    }

    DEBUG_PRINT("DEBUG: OCTET STRING length = %zu\n", len);
    const unsigned char *data_end = *p + len;

    // SafeContents ::= SEQUENCE OF SafeBag
    if ((ret = mbedtls_asn1_get_tag(p, data_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to get SafeContents SEQUENCE, ret = %d\n", ret);
        return ret;
    }

    DEBUG_PRINT("DEBUG: SafeContents SEQUENCE length = %zu\n", len);
    const unsigned char *safebags_end = *p + len;

    // Parse each SafeBag
    int bag_count = 0;
    while (*p < safebags_end) {
        bag_count++;
        unsigned char *bag_start = *p;
        DEBUG_PRINT("DEBUG: Parsing SafeBag #%d, offset = %ld\n", bag_count, *p - (end - 1000));
        (void)bag_start; // Suppress unused warning
        (void)bag_count; // Suppress unused warning when DEBUG_PRINT is disabled
        
        pkcs12_secret_t temp_secret = {0};
        
        ret = parse_secret_safebag(p, safebags_end, password, &temp_secret);
        
        DEBUG_PRINT("DEBUG: parse_secret_safebag returned %d, key_len = %zu\n", ret, temp_secret.key_len);
        
        if (ret == 0 && temp_secret.key_len > 0) {
            // OpenSSL-compatible logic: check if this key is a common root
            // Use case-insensitive comparison to handle uppercase conversion
            bool is_common_root = (temp_secret.name_len >= strlen("commonroot") && 
                                  strncasecmp(temp_secret.name, "commonroot", strlen("commonroot")) == 0);
            
            DEBUG_PRINT("DEBUG: Found key with name: %.*s, is_common_root = %s\n", 
                       (int)temp_secret.name_len, temp_secret.name, is_common_root ? "true" : "false");
            
            // Apply OpenSSL-style selection logic
            if (is_common_root == requested_common_root) {
                DEBUG_PRINT("DEBUG: Key matches requested type (common_root=%s)!\n", 
                           requested_common_root ? "true" : "false");
                memcpy(secret, &temp_secret, sizeof(pkcs12_secret_t));
                return 0;
            }
        }
        
        // Safety check: if pointer didn't advance, break to avoid infinite loop
        if (*p == bag_start) {
            DEBUG_PRINT("DEBUG: Pointer didn't advance, breaking loop\n");
            break;
        }
    }

    DEBUG_PRINT("DEBUG: No matching key found in parse_pkcs7_data\n");
    return MBEDTLS_ERR_ASN1_INVALID_DATA;
}

/**
 * Parse PKCS#7 EncryptedData (encrypted SafeBags)
 */
static int parse_pkcs7_encrypted_data(unsigned char **p,
                                     const unsigned char *end,
                                     const char *password,
                                     bool requested_common_root,
                                     pkcs12_secret_t *secret)
{
    int ret;
    size_t len;

    // EncryptedData ::= SEQUENCE {
    //     version              INTEGER,
    //     encryptedContentInfo EncryptedContentInfo
    // }

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    const unsigned char *enc_end = *p + len;

    // Skip version
    int version;
    if ((ret = mbedtls_asn1_get_int(p, enc_end, &version)) != 0) {
        return ret;
    }

    // EncryptedContentInfo ::= SEQUENCE {
    //     contentType                 OBJECT IDENTIFIER,
    //     contentEncryptionAlgorithm  AlgorithmIdentifier,
    //     encryptedContent            [0] IMPLICIT OCTET STRING OPTIONAL
    // }

    if ((ret = mbedtls_asn1_get_tag(p, enc_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    const unsigned char *content_end = *p + len;

    // Skip contentType OID
    size_t oid_len;
    if ((ret = mbedtls_asn1_get_tag(p, content_end, &oid_len,
            MBEDTLS_ASN1_OID)) != 0) {
        return ret;
    }
    *p += oid_len;

    // Parse encryption algorithm
    mbedtls_asn1_buf enc_alg_oid, enc_params;
    ret = parse_algorithm_identifier(p, content_end, &enc_alg_oid, &enc_params);
    if (ret != 0) {
        return ret;
    }

    // Get encrypted content [0] IMPLICIT
    size_t enc_data_len;
    if ((ret = mbedtls_asn1_get_tag(p, content_end, &enc_data_len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0)) != 0) {
        return ret;
    }

    unsigned char *enc_data = *p;
    *p += enc_data_len;

    // Decrypt the content (similar to above)
    unsigned char *param_p = enc_params.p;
    const unsigned char *param_end = enc_params.p + enc_params.len;

    // Get salt
    size_t salt_len;
    if ((ret = mbedtls_asn1_get_tag(&param_p, param_end, &salt_len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return ret;
    }
    unsigned char *salt = param_p;
    param_p += salt_len;

    // Get iterations
    int iterations;
    if ((ret = mbedtls_asn1_get_int(&param_p, param_end, &iterations)) != 0) {
        return ret;
    }

    // Decrypt
    size_t output_len;
    unsigned char decrypted[4096];
    ret = decrypt_pkcs8_pbe(enc_data, enc_data_len, password,
                           salt, salt_len, iterations,
                           (const char *)enc_alg_oid.p, enc_alg_oid.len,
                           decrypted, &output_len);
    if (ret != 0) {
        return ret;
    }

    // Parse the decrypted SafeBags
    unsigned char *data_p = decrypted;
    return parse_pkcs7_data(&data_p, decrypted + output_len,
                           password, requested_common_root, secret);
}

/**
 * Main function to load PKCS#12 secret key using mbedTLS
 */
bool load_pkcs12_secret_key_mbedtls(
        void* key,
        size_t* key_length,
        char* name,
        size_t* name_length)
{
    int ret;
    FILE *f = NULL;
    unsigned char *buf = NULL;
    size_t file_len;

    // Get password from environment (matching OpenSSL behavior)
    const char* password = getenv("ROOT_KEYSTORE_PASSWORD");
    if (password == NULL)
        password = DEFAULT_ROOT_KEYSTORE_PASSWORD;

    // OpenSSL-compatible logic: determine requested_common_root from input name
    size_t in_name_length = *name_length;
    bool requested_common_root = (name != NULL && in_name_length > 0 && 
                                 strncmp(name, COMMON_ROOT_NAME, strlen(COMMON_ROOT_NAME)) == 0);

    DEBUG_PRINT("DEBUG: requested_common_root = %s\n", requested_common_root ? "true" : "false");

    // Check if using file or embedded keystore
    const char* filename = getenv("ROOT_KEYSTORE");
    if (filename != NULL) {
        // Read file
        f = fopen(filename, "rb");
        if (f == NULL) {
            printf("Failed to open file: %s\n", filename);
            return false;
        }

        fseek(f, 0, SEEK_END);
        file_len = ftell(f);
        fseek(f, 0, SEEK_SET);

        buf = mbedtls_calloc(1, file_len);
        if (buf == NULL) {
            fclose(f);
            return MBEDTLS_ERR_ASN1_ALLOC_FAILED;
        }

        if (fread(buf, 1, file_len, f) != file_len) {
            mbedtls_free(buf);
            fclose(f);
            return -1;
        }
        fclose(f);
    } else {
        // Use embedded keystore
        file_len = sizeof(default_root_keystore);
        buf = mbedtls_calloc(1, file_len);
        if (buf == NULL) {
            return MBEDTLS_ERR_ASN1_ALLOC_FAILED;
        }
        memcpy(buf, default_root_keystore, file_len);
    }

    // Parse PKCS#12
    // PFX ::= SEQUENCE {
    //     version     INTEGER {v3(3)}(v3,...),
    //     authSafe    ContentInfo,
    //     macData     MacData OPTIONAL
    // }

    unsigned char *p = buf;
    const unsigned char *end = buf + file_len;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    const unsigned char *pfx_end = p + len;

    // Get version
    int version;
    if ((ret = mbedtls_asn1_get_int(&p, pfx_end, &version)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    if (version != PKCS12_VERSION) {
        mbedtls_free(buf);
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }

    // Parse authSafe ContentInfo
    // ContentInfo ::= SEQUENCE {
    //     contentType OBJECT IDENTIFIER,
    //     content     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
    // }

    if ((ret = mbedtls_asn1_get_tag(&p, pfx_end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    const unsigned char *authsafe_end = p + len;

    // Get content type OID (should be pkcs7-data)
    size_t oid_len;
    if ((ret = mbedtls_asn1_get_tag(&p, authsafe_end, &oid_len,
            MBEDTLS_ASN1_OID)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    if (oid_len != 9 || memcmp(p, OID_PKCS7_DATA, 9) != 0) {
        mbedtls_free(buf);
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }
    p += oid_len;

    // Get [0] EXPLICIT content
    if ((ret = mbedtls_asn1_get_tag(&p, authsafe_end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    // Get OCTET STRING containing authSafes
    size_t authsafes_len;
    if ((ret = mbedtls_asn1_get_tag(&p, authsafe_end, &authsafes_len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    unsigned char *authsafes_data = p;
    p += authsafes_len;

    // Verify MAC if present
    if (p < pfx_end) {
        ret = verify_pkcs12_mac(authsafes_data, authsafes_len,
                               &p, pfx_end, password);
        if (ret != 0) {
            printf("MAC verification failed (wrong password?)\n");
            mbedtls_free(buf);
            return ret;
        }
    }

    // Parse AuthenticatedSafe
    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo

    p = authsafes_data;
    end = authsafes_data + authsafes_len;

    DEBUG_PRINT("DEBUG: Parsing AuthenticatedSafe, length = %zu\n", authsafes_len);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        DEBUG_PRINT("DEBUG: Failed to parse AuthenticatedSafe SEQUENCE, ret = %d\n", ret);
        mbedtls_free(buf);
        return ret;
    }

    DEBUG_PRINT("DEBUG: AuthenticatedSafe SEQUENCE length = %zu\n", len);
    const unsigned char *safe_end = p + len;

    pkcs12_secret_t found_secret = {0};
    int found = 0;

    DEBUG_PRINT("DEBUG: Starting ContentInfo iteration\n");

    // Iterate through ContentInfo structures
    int ci_count = 0;
    while (p < safe_end && !found) {
        ci_count++;
        DEBUG_PRINT("DEBUG: Parsing ContentInfo #%d\n", ci_count);
        (void)ci_count; // Suppress unused warning when DEBUG_PRINT is disabled
        
        // ContentInfo
        if ((ret = mbedtls_asn1_get_tag(&p, safe_end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            DEBUG_PRINT("DEBUG: Failed to parse ContentInfo SEQUENCE, ret = %d\n", ret);
            break;
        }

        DEBUG_PRINT("DEBUG: ContentInfo length = %zu\n", len);
        const unsigned char *ci_end = p + len;

        // Get content type OID
        if ((ret = mbedtls_asn1_get_tag(&p, ci_end, &oid_len,
                MBEDTLS_ASN1_OID)) != 0) {
            DEBUG_PRINT("DEBUG: Failed to parse OID, ret = %d\n", ret);
            break;
        }

        DEBUG_PRINT("DEBUG: Content type OID length = %zu\n", oid_len);
        
        unsigned char *content_oid = p;
        p += oid_len;

        // Get [0] EXPLICIT content
        if ((ret = mbedtls_asn1_get_tag(&p, ci_end, &len,
                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) != 0) {
            DEBUG_PRINT("DEBUG: Failed to parse [0] EXPLICIT, ret = %d\n", ret);
            break;
        }

        DEBUG_PRINT("DEBUG: Content length = %zu\n", len);
        
        unsigned char *content = p;
        const unsigned char *content_end = p + len;
        p += len;

        // Check content type
        if (oid_len == 9 && memcmp(content_oid, OID_PKCS7_DATA, 9) == 0) {
            DEBUG_PRINT("DEBUG: Found pkcs7-data\n");
            ret = parse_pkcs7_data(&content, content_end, password,
                                  requested_common_root, &found_secret);
            DEBUG_PRINT("DEBUG: parse_pkcs7_data returned %d, key_len = %zu\n", ret, found_secret.key_len);
            if (ret == 0 && found_secret.key_len > 0) {
                found = 1;
            }
        } else if (oid_len == 9 && 
                   memcmp(content_oid, OID_PKCS7_ENCRYPTED_DATA, 9) == 0) {
            DEBUG_PRINT("DEBUG: Found pkcs7-encryptedData\n");
            ret = parse_pkcs7_encrypted_data(&content, content_end, password,
                                            requested_common_root, &found_secret);
            DEBUG_PRINT("DEBUG: parse_pkcs7_encrypted_data returned %d, key_len = %zu\n", ret, found_secret.key_len);
            if (ret == 0 && found_secret.key_len > 0) {
                found = 1;
            }
        } else {
            DEBUG_PRINT("DEBUG: Unknown content type OID\n");
        }
    }

    DEBUG_PRINT("DEBUG: Finished iteration, found = %d\n", found);

    mbedtls_free(buf);

    if (!found || found_secret.key_len == 0) {
        DEBUG_PRINT("DEBUG: No key found, returning false\n");
        return false;
    }

    DEBUG_PRINT("DEBUG: Key found! Length = %zu, name length = %zu\n", 
           found_secret.key_len, found_secret.name_len);

    // Copy results
    if (found_secret.key_len > *key_length) {
        return false;
    }

    memcpy(key, found_secret.key_data, found_secret.key_len);
    *key_length = found_secret.key_len;

    DEBUG_PRINT("DEBUG: found_secret.name_len = %zu\n", found_secret.name_len);
    DEBUG_PRINT("DEBUG: name pointer = %p, name_length pointer = %p\n", (void*)name, (void*)name_length);
    if (name_length != NULL) {
        DEBUG_PRINT("DEBUG: input *name_length = %zu\n", *name_length);
    }

    if (found_secret.name_len > 0 && name != NULL && name_length != NULL) {
        size_t copy_len = found_secret.name_len < *name_length ? 
                         found_secret.name_len : *name_length - 1;
        memcpy(name, found_secret.name, copy_len);
        name[copy_len] = '\0';
        *name_length = copy_len;
        DEBUG_PRINT("DEBUG: set *name_length = %zu\n", copy_len);
    } else {
        DEBUG_PRINT("DEBUG: NOT updating name_length. found_secret.name_len=%zu, name=%p, name_length=%p\n", 
                   found_secret.name_len, (void*)name, (void*)name_length);
    }

    return true;
}
