/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

/**
 * @file sa_types.h
 *
 * This file contains the types and enumerations for SecAPI supported algorithms. The enumerated
 * algorithms and key types are not meant to be all encompassing and instead are continuously
 * updated as use cases demanding new support emerge.
 */

#ifndef SA_TYPES_H
#define SA_TYPES_H

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

/* clang-format off */
/**
 * Create bit mask for specified bit.
 */
#define SA_USAGE_BIT_MASK(b) ((uint64_t) 1 << ((b) % (sizeof(uint64_t) * 8)))

/**
 * Set specified bit in bitfield.
 */
#define SA_USAGE_BIT_SET(a, b) ((a) |= SA_USAGE_BIT_MASK(b))

/**
 * Clear specified bit from bitfield.
 */
#define SA_USAGE_BIT_CLEAR(a, b) ((a) &= ~SA_USAGE_BIT_MASK(b))

/**
 * Test if specified bit is set in bitfield.
 */
#define SA_USAGE_BIT_TEST(a, b) ((a) & SA_USAGE_BIT_MASK(b))

/**
 * Create bit mask of all video output protection bits.
 */
#define SA_USAGE_OUTPUT_PROTECTIONS_MASK \
    (SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_SVP_OPTIONAL))

#define SA_KEY_USAGE_MASK \
    (SA_USAGE_BIT_MASK(SA_USAGE_FLAG_KEY_EXCHANGE) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_DERIVE) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_UNWRAP) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ENCRYPT) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_DECRYPT) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_SIGN))
/* clang-format on */

/**
 * Generic handle type.
 */
typedef uint32_t sa_handle;

#define INVALID_HANDLE (sa_handle) UINT32_MAX

#define NUM_MAGIC 4

/**
 * Key handle.
 */
typedef sa_handle sa_key;

/**
 * SVP buffer opaque data structure.
 */
typedef sa_handle sa_svp_buffer;

/**
 * Cipher context handle.
 */
typedef sa_handle sa_crypto_cipher_context;

/**
 * MAC context handle.
 */
typedef sa_handle sa_crypto_mac_context;

/**
 * SecAPI version.
 */
typedef struct {
    /** major version of the SecAPI specification */
    size_t specification_major;
    /** minor version of the SecAPI specification */
    size_t specification_minor;
    /** revision version of the SecAPI specification */
    size_t specification_revision;
    /** revision version of the SecAPI implementation */
    size_t implementation_revision;
} sa_version;

/**
 * List of currently supported cipher algorithms.
 */
typedef enum {
    SA_CIPHER_ALGORITHM_AES_ECB = 0,
    SA_CIPHER_ALGORITHM_AES_ECB_PKCS7,
    SA_CIPHER_ALGORITHM_AES_CBC,
    SA_CIPHER_ALGORITHM_AES_CBC_PKCS7,
    SA_CIPHER_ALGORITHM_AES_CTR,
    SA_CIPHER_ALGORITHM_AES_GCM,
    SA_CIPHER_ALGORITHM_RSA_PKCS1V15,
    SA_CIPHER_ALGORITHM_RSA_OAEP,
    SA_CIPHER_ALGORITHM_EC_ELGAMAL,
    SA_CIPHER_ALGORITHM_CHACHA20,
    SA_CIPHER_ALGORITHM_CHACHA20_POLY1305
} sa_cipher_algorithm;

/**
 * List of cipher modes.
 */
typedef enum {
    SA_CIPHER_MODE_DECRYPT = 0,
    SA_CIPHER_MODE_ENCRYPT
} sa_cipher_mode;

/**
 * List of currently supported signature algorithms.
 */
typedef enum {
    SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15 = 0,
    SA_SIGNATURE_ALGORITHM_RSA_PSS,
    SA_SIGNATURE_ALGORITHM_ECDSA,
    SA_SIGNATURE_ALGORITHM_EDDSA
} sa_signature_algorithm;

/**
 * List of currently supported message authentication code algorithms.
 */
typedef enum {
    SA_MAC_ALGORITHM_CMAC = 0,
    SA_MAC_ALGORITHM_HMAC
} sa_mac_algorithm;

/**
 * List of currently supported digest algorithms.
 */
typedef enum {
    SA_DIGEST_ALGORITHM_SHA1 = 0,
    SA_DIGEST_ALGORITHM_SHA256,
    SA_DIGEST_ALGORITHM_SHA384,
    SA_DIGEST_ALGORITHM_SHA512
} sa_digest_algorithm;

/**
 * List of currently supported key derivation function algorithms.
 */
typedef enum {
    SA_KDF_ALGORITHM_ROOT_KEY_LADDER = 0,
    SA_KDF_ALGORITHM_HKDF,
    SA_KDF_ALGORITHM_CONCAT,
    SA_KDF_ALGORITHM_ANSI_X963,
    SA_KDF_ALGORITHM_CMAC,
    SA_KDF_ALGORITHM_NETFLIX
} sa_kdf_algorithm;

/**
 * List of currently supported key exchange algorithms.
 */
typedef enum {
    SA_KEY_EXCHANGE_ALGORITHM_DH = 0,
    SA_KEY_EXCHANGE_ALGORITHM_ECDH,
    SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH
} sa_key_exchange_algorithm;

/**
 * List of supported key formats for sa_key_import.
 */
typedef enum {
    SA_KEY_FORMAT_SYMMETRIC_BYTES = 0,
    SA_KEY_FORMAT_EC_PRIVATE_BYTES,
    SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO,
    SA_KEY_FORMAT_EXPORTED,
    SA_KEY_FORMAT_SOC,
    SA_KEY_FORMAT_TYPEJ
} sa_key_format;

/**
 * List of supported key types.
 */
typedef enum {
    SA_KEY_TYPE_SYMMETRIC = 0,
    SA_KEY_TYPE_EC = 1,
    SA_KEY_TYPE_RSA = 2,
    SA_KEY_TYPE_DH = 3
} sa_key_type;

/**
 * List of supported elliptic curves.
 */
typedef enum {
    SA_ELLIPTIC_CURVE_NIST_P256 = 0,
    /** This curve is for future support and is not currently required. **/
    SA_ELLIPTIC_CURVE_NIST_P384 = 1,
    /** This curve is for future support and is not currently required. **/
    SA_ELLIPTIC_CURVE_NIST_P521 = 2,
    /** Supported only with SA_SIGNATURE_ALGORITHM_ECDSA */
    SA_ELLIPTIC_CURVE_ED25519 = 3,
    /** Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH */
    SA_ELLIPTIC_CURVE_X25519 = 4,
    /** Supported only with SA_SIGNATURE_ALGORITHM_ECDSA */
    /** This curve is for future support and is not currently required. **/
    SA_ELLIPTIC_CURVE_ED448 = 5,
    /** Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH */
    /** This curve is for future support and is not currently required. **/
    SA_ELLIPTIC_CURVE_X448 = 6,
    SA_ELLIPTIC_CURVE_NIST_P192 = 7,
    SA_ELLIPTIC_CURVE_NIST_P224 = 8
} sa_elliptic_curve;

/**
 * List of buffer types.
 */
typedef enum {
    SA_BUFFER_TYPE_CLEAR = 0,
    SA_BUFFER_TYPE_SVP
} sa_buffer_type;

/**
 * List of operation status codes.
 */
typedef enum {
    /** Operation completed successfully. */
    SA_STATUS_OK = 0,
    /** Operation failed due to no resource slots being available. */
    SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT,
    /** Operation failed during key format validation. */
    SA_STATUS_INVALID_KEY_FORMAT,
    /** Operation failed due to invalid key type used for specified algorithm. */
    SA_STATUS_INVALID_KEY_TYPE,
    /** Operation failed due to NULL value for a required parameter. */
    SA_STATUS_NULL_PARAMETER,
    /** Operation failed due to invalid parameter value for specified algorithm. */
    SA_STATUS_INVALID_PARAMETER,
    /** Operation failed due to key rights enforcement. One or more preconditions required by the
     * key rights were not met. */
    SA_STATUS_OPERATION_NOT_ALLOWED,
    /** Operation failed due to SVP buffer not being fully contained within secure SVP region. */
    SA_STATUS_INVALID_SVP_BUFFER,
    /** Operation failed due to the combination of parameters not being supported in the
     * implementation. */
    SA_STATUS_OPERATION_NOT_SUPPORTED,
    /** Operation failed due to self-test failure. */
    SA_STATUS_SELF_TEST,
    /** Signature or padding verification failed. */
    SA_STATUS_VERIFICATION_FAILED,
    /** Operation failed due to an internal implementation error. */
    SA_STATUS_INTERNAL_ERROR,
    /** Operation failed due to a hardware error. */
    SA_STATUS_HW_ERROR
} sa_status;

/**
 * List of allowed operations for the key.
 */
typedef enum {
    /** Key can be used as a private key in key exchange operations. */
    SA_USAGE_FLAG_KEY_EXCHANGE = 0,
    /** Key can be used as a base key in key derivation operations. */
    SA_USAGE_FLAG_DERIVE = 1,
    /** Key can be used as an unwrapping key in unwrap operations. */
    SA_USAGE_FLAG_UNWRAP = 2,
    /** Key can be used as an encryption key in cipher operations. */
    SA_USAGE_FLAG_ENCRYPT = 3,
    /** Key can be used as a decryption key in cipher operations. */
    SA_USAGE_FLAG_DECRYPT = 4,
    /** Key can be used as a signing key in signing or mac operations. */
    SA_USAGE_FLAG_SIGN = 5,
    /**
     * Key can be used for AES cipher operations when an analog video output is in an unprotected
     * state.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED = 6,
    /**
     * Key can be used for AES cipher operations when an analog video output is protected using
     * CGMSA.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA = 7,
    /**
     * Key can be used for AES cipher operations when a digital video output is in an unprotected
     * state.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED = 8,
    /**
     * Key can be used for AES cipher operations when a digital video output is protected using
     * HDCP 1.4.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14 = 9,
    /**
     * Key can be used for AES cipher operations when a digital video output is protected using
     * HDCP 2.2.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22 = 10,
    /**
     * Key can be used for AES cipher operations when a digital video output is protected using
     * DTCP.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP = 11,
    /**
     * Key can be used for AES cipher operations to unprotected memory. If not set, only cipher
     * operations in sa_svp.h are allowed.
     *
     * Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
     * have this flag set if the parent key did not have it set.
     */
    SA_USAGE_FLAG_SVP_OPTIONAL = 12,
    /** Key can be exported using sa_key_export call. */
    SA_USAGE_FLAG_CACHEABLE = 13
} sa_usage_flags;

/**
 * 128-bit UUID
 */
typedef struct {
    /** ID in network order */
    uint8_t id[16];
} sa_uuid;

#define MAX_NUM_ALLOWED_TA_IDS 32

/**
 * Key rights describing the conditions under which the key can be used.
 */
typedef struct {
    /**
     * Key identifier. Not used internally by SecAPI.
     */
    char id[64];

    /**
     * Usage flags bitfield. Flags are set and tested using the SA_USAGE_BIT* macros.
     */
    uint64_t usage_flags;

    /**
     * Usage flags bitfield for unwrapped child keys. When usage_flags only has SA_USAGE_FLAG_UNWRAP (bit 2) set of
     * bits 0-5, then these child_usage_flags apply to any key unwrapped by this key. Flags are set and tested using the
     * SA_USAGE_BIT* macros.
     */
    uint64_t child_usage_flags;

    /**
     * Start of the key validity period in seconds since Unix epoch.
     */
    uint64_t not_before;

    /**
     * End of the key validity period in seconds since Unix epoch.
     */
    uint64_t not_on_or_after;

    /**
     * List of TAs that are allowed to wield this key. All entries in the array are compared to the
     * calling TA's UUID. If any of them match key is allowed to be used by the TA.
     *
     * There are two special case values:
     * +  0x00000000000000000000000000000000 matches no TAs.
     * +  0xffffffffffffffffffffffffffffffff matches all TAs.
     */
    sa_uuid allowed_tas[MAX_NUM_ALLOWED_TA_IDS];
} sa_rights;

#define DH_MAX_MOD_SIZE 512

/**
 * Type parameters for the sa_header.
 */
typedef union {
    sa_elliptic_curve curve;

    struct {
        /** Prime. */
        uint8_t p[DH_MAX_MOD_SIZE];
        /** Prime length in bytes. */
        size_t p_length;
        /** Generator. */
        uint8_t g[DH_MAX_MOD_SIZE];
        /** Generator length in bytes. */
        size_t g_length;
    } dh_parameters;
} sa_type_parameters;

/**
 * Exported key container header.
 */
typedef struct {
    /** Fixed "sak0" value used for identifying the exported key container. */
    char magic[NUM_MAGIC];
    /** Key rights. */
    sa_rights rights;
    /** Key type. One of sa_key_type type values. */
    uint8_t type;
    /** Additional key type parameter. */
    sa_type_parameters type_parameters;
    /**
     * Key length in bytes. Modulus length for SA_KEY_TYPE_RSA and SA_KEY_TYPE_DH, private key
     * length for SA_KEY_TYPE_EC, symmetric key length for SA_KEY_TYPE_SYMMETRIC.
     */
    uint16_t size;
} sa_header;

/**
 * Buffer description containing either a clear or SVP buffer indicated by sa_buffer_type.
 */
typedef struct {
    /**
     * The type of the buffer.
     */
    sa_buffer_type buffer_type;

    /**
     * The buffer information.
     */
    union {
        struct {
            void* buffer;
            size_t length;
            size_t offset;
        } clear;

        struct {
            sa_svp_buffer buffer;
            size_t offset;
        } svp;
    } context;
} sa_buffer;

/**
 * Import parameters for SA_KEY_FORMAT_SYMMETRIC_BYTES.
 */
typedef struct {
    /** Key rights to associate with imported key. */
    const sa_rights* rights;
} sa_import_parameters_symmetric;

/**
 * Import parameters for SA_KEY_FORMAT_EC_PRIVATE_BYTES.
 */
typedef struct {
    /** Key rights to associate with imported key. */
    const sa_rights* rights;
    /** Elliptic curve */
    sa_elliptic_curve curve;
} sa_import_parameters_ec_private_bytes;

/**
 * Import parameters for SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO
 */
typedef struct {
    /** Key rights to associate with imported key. */
    const sa_rights* rights;
} sa_import_parameters_rsa_private_key_info;

/**
 * Import parameters for SA_KEY_FORMAT_TYPEJ.
 */
typedef struct {
    /** Cipher key handle. */
    sa_key kcipher;
    /** HMAC key handle. */
    sa_key khmac;
} sa_import_parameters_typej;

/**
 * Key generation parameter for SA_KEY_TYPE_SYMMETRIC.
 */
typedef struct {
    /** Key length in bytes. Has to be greater than 16 and less than or equal to 512. */
    size_t key_length;
} sa_generate_parameters_symmetric;

/**
 * Key generation parameters for SA_KEY_TYPE_RSA.
 */
typedef struct {
    /** Modulus size in bytes. Valid values are 128, 256, 384, and 512. */
    size_t modulus_length;
} sa_generate_parameters_rsa;

/**
 * Key generation parameters for SA_KEY_TYPE_EC.
 */
typedef struct {
    /** Elliptic curve. */
    sa_elliptic_curve curve;
} sa_generate_parameters_ec;

/**
 * Key generation parameters for SA_KEY_TYPE_DH.
 */
typedef struct {
    /** Prime. */
    const void* p;
    /** Prime length in bytes. */
    size_t p_length;
    /** Generator. */
    const void* g;
    /** Generator length in bytes. */
    size_t g_length;
} sa_generate_parameters_dh;

/**
 * Cipher parameters for SA_CIPHER_ALGORITHM_AES_CBC and SA_CIPHER_ALGORITHM_AES_CBC_PKCS7.
 */
typedef struct {
    /** Initialization vector */
    const void* iv;
    /** Initialization vector length in bytes. Has to equal 16. */
    size_t iv_length;
} sa_cipher_parameters_aes_cbc;

/**
 * Cipher parameters for SA_CIPHER_ALGORITHM_AES_CTR.
 */
typedef struct {
    /** Concatenated nonce and counter value. */
    const void* ctr;
    /** Length of concatenated nonce and counter values in bytes. Has to be equal to 16. */
    size_t ctr_length;
} sa_cipher_parameters_aes_ctr;

/**
 * Cipher parameters for SA_CIPHER_ALGORITHM_AES_GCM.
 */
typedef struct {
    /** Initialization vector. */
    const void* iv;
    /** Length of initialization vector in bytes. Has to be equal to 16. */
    size_t iv_length;
    /** Additional authenticated data. */
    const void* aad;
    /** Length of additional authenticated data. */
    size_t aad_length;
} sa_cipher_parameters_aes_gcm;

/**
 * Cipher parameters for SA_CIPHER_ALGORITHM_CHACHA20.
 */
typedef struct {
    /** Counter value in little-endian format. */
    const void* counter;
    /** Length of the counter in bytes. Must be equal to 4. */
    size_t counter_length;
    /** Nonce value. */
    const void* nonce;
    /** Length of the nonce in bytes. Must be equal to 12. */
    size_t nonce_length;
} sa_cipher_parameters_chacha20;

/**
 * Cipher parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305.
 */
typedef struct {
    /** Nonce value. */
    const void* nonce;
    /** Length of the nonce in bytes. Must be equal to 12. */
    size_t nonce_length;
    /** Additional authenticated data. */
    const void* aad;
    /** Length of additional authenticated data. */
    size_t aad_length;
} sa_cipher_parameters_chacha20_poly1305;

/**
 * Cipher parameters for SA_CIPHER_ALGORITHM_RSA_OAEP.
 */
typedef struct {
    /** Digest algorithm. */
    sa_digest_algorithm digest_algorithm;
    /** MGF1 digest algorithm. */
    sa_digest_algorithm mgf1_digest_algorithm;
    /** Label. May be NULL */
    void* label;
    /** Label length. 0 if label is NULL. */
    size_t label_length;
} sa_cipher_parameters_rsa_oaep;

/**
 * MAC parameters for SA_MAC_ALGORITHM_HMAC.
 */
typedef struct {
    /** Digest algorithm. */
    sa_digest_algorithm digest_algorithm;
} sa_mac_parameters_hmac;

/**
 * Cipher end parameters for SA_CIPHER_ALGORITHM_AES_GCM.
 */
typedef struct {
    /** Authentication tag. */
    void* tag;
    /** Authentication tag length in bytes. */
    size_t tag_length;
} sa_cipher_end_parameters_aes_gcm;

/**
 * Cipher end parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305.
 */
typedef sa_cipher_end_parameters_aes_gcm sa_cipher_end_parameters_chacha20_poly1305;

/**
 * Unwrap type parameters for SA_KEY_TYPE_EC.
 */
typedef struct {
    /** Elliptic curve. */
    sa_elliptic_curve curve;
} sa_unwrap_type_parameters_ec;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_AES_CBC and SA_CIPHER_ALGORITHM_AES_CBC_PKCS7.
 */
typedef struct {
    /** Initialization vector. */
    const void* iv;
    /** Length of initialization vector in bytes. Has to be equal to 16. */
    size_t iv_length;
} sa_unwrap_parameters_aes_cbc;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_AES_CTR.
 */
typedef struct {
    /** Concatenated nonce and counter value. */
    const void* ctr;
    /** Length of concatenated nonce and counter values in bytes. Has to be equal to 16. */
    size_t ctr_length;
} sa_unwrap_parameters_aes_ctr;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_AES_GCM.
 */
typedef struct {
    /** Initialization vector. */
    const void* iv;
    /** Length of initialization vector in bytes. Has to be equal to 16. */
    size_t iv_length;
    /** Additional authenticated data. */
    const void* aad;
    /** Length of additional authenticated data. */
    size_t aad_length;
    /** Authentication tag. */
    const void* tag;
    /** Authentication tag length in bytes. */
    size_t tag_length;
} sa_unwrap_parameters_aes_gcm;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_CHACHA20.
 */
typedef struct {
    /** Counter value in little-endian format. */
    const void* counter;
    /** Length of the counter in bytes. Must be equal to 4. */
    size_t counter_length;
    /** Nonce value. */
    const void* nonce;
    /** Length of the nonce in bytes. Must be equal to 12. */
    size_t nonce_length;
} sa_unwrap_parameters_chacha20;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305.
 */
typedef struct {
    /** Nonce value. */
    const void* nonce;
    /** Length of the nonce in bytes. Must be equal to 12. */
    size_t nonce_length;
    /** Additional authenticated data. */
    const void* aad;
    /** Length of additional authenticated data. */
    size_t aad_length;
    /** Authentication tag. */
    const void* tag;
    /** Authentication tag length in bytes. */
    size_t tag_length;
} sa_unwrap_parameters_chacha20_poly1305;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_RSA_OAEP.
 */
typedef struct {
    /** Digest algorithm. */
    sa_digest_algorithm digest_algorithm;
    /** MGF1 digest algorithm. */
    sa_digest_algorithm mgf1_digest_algorithm;
    /** Label. May be NULL */
    void* label;
    /** Label length. 0 if label is NULL. */
    size_t label_length;
} sa_unwrap_parameters_rsa_oaep;

/**
 * Unwrap parameters for SA_CIPHER_ALGORITHM_EC_ELGAMAL.
 */
typedef struct {
    /** offset of the wrapped key. */
    size_t offset;
    /** length of the wrapped key. */
    size_t key_length;
} sa_unwrap_parameters_ec_elgamal;

/**
 * Signature parameters for SA_SIGNATURE_ALGORITHM_RSA_PSS.
 */
typedef struct {
    /** The digest algorithm to use in the signature. */
    sa_digest_algorithm digest_algorithm;
    /** MGF1 digest algorithm. */
    sa_digest_algorithm mgf1_digest_algorithm;
    /** Indicates the in parameter has the result of the digest operation. */
    bool precomputed_digest;
    /** Salt length. */
    size_t salt_length;
} sa_sign_parameters_rsa_pss;

/**
 * Signature parameters for SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15.
 */
typedef struct {
    /** The digest algorithm to use in the signature. */
    sa_digest_algorithm digest_algorithm;
    /** Indicates the in parameter has the result of the digest operation. */
    bool precomputed_digest;
} sa_sign_parameters_rsa_pkcs1v15;

/**
 * Signature parameters for SA_SIGNATURE_ALGORITHM_ECDSA.
 */
typedef struct {
    /** The digest algorithm to use in the signature. */
    sa_digest_algorithm digest_algorithm;
    /** Indicates the in parameter has the result of the digest operation. */
    bool precomputed_digest;
} sa_sign_parameters_ecdsa;

/**
 * KDF parameters for SA_KDF_ALGORITHM_ROOT_KEY_LADDER.
 */
typedef struct {
    /** Input for first stage of the key ladder. */
    const void* c1;
    /** Length in bytes of the input for the first stage of the key ladder. Has to be equal to 16. */
    size_t c1_length;
    /** Input for second stage of the key ladder. */
    const void* c2;
    /** Length in bytes of the input for the second stage of the key ladder. Has to be equal to 16. */
    size_t c2_length;
    /** Input for third stage of the key ladder. */
    const void* c3;
    /** Length in bytes of the input for the third stage of the key ladder. Has to be equal to 16. */
    size_t c3_length;
    /** Input for fourth stage of the key ladder. */
    const void* c4;
    /** Length in bytes of the input for the fourth stage of the key ladder. Has to be equal to 16. */
    size_t c4_length;
} sa_kdf_parameters_root_key_ladder;

/**
 * KDF parameters for SA_KDF_ALGORITHM_HKDF.
 */
typedef struct {
    /** Derived key length in bytes. */
    size_t key_length;
    /** Digest algorithm. */
    sa_digest_algorithm digest_algorithm;
    /** Parent key handle. */
    sa_key parent;
    /** Salt value. */
    const void* salt;
    /** Salt length in bytes. */
    size_t salt_length;
    /** Info value. */
    const void* info;
    /** Info length in bytes. */
    size_t info_length;
} sa_kdf_parameters_hkdf;

/**
 * KDF parameters for SA_KDF_ALGORITHM_CONCAT.
 */
typedef struct {
    /** Derived key length in bytes. */
    size_t key_length;
    /** Digest algorithm. */
    sa_digest_algorithm digest_algorithm;
    /** Parent key handle. */
    sa_key parent;
    /** Info value. */
    const void* info;
    /** Info length in bytes. */
    size_t info_length;
} sa_kdf_parameters_concat;

/**
 * KDF parameters for SA_KDF_ALGORITHM_ANSI_X963.
 */
typedef struct {
    /** Derived key length in bytes. */
    size_t key_length;
    /** Digest algorithm. */
    sa_digest_algorithm digest_algorithm;
    /** Parent key handle. */
    sa_key parent;
    /** Info value. */
    const void* info;
    /** Info length in bytes. */
    size_t info_length;
} sa_kdf_parameters_ansi_x963;

/**
 * KDF parameters for SA_KDF_ALGORITHM_CMAC.
 */
typedef struct {
    /** Derived key length in bytes. */
    size_t key_length;
    /** Parent key handle. */
    sa_key parent;
    /** Other data value. */
    const void* other_data;
    /** Length of other data in bytes. */
    size_t other_data_length;
    /** Counter value. Has to be between 1 and 4 inclusive. */
    uint8_t counter;
} sa_kdf_parameters_cmac;

/**
 * KDF parameters for SA_KDF_ALGORITHM_NETFLIX
 * (https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication).
 */
typedef struct {
    /** Encryption key handle. */
    sa_key kenc;
    /** HMAC key handle. */
    sa_key khmac;
} sa_kdf_parameters_netflix;

/**
 * Key exchange parameters for SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH
 * (https://github.com/Netflix/msl/wiki/Authenticated-Diffie-Hellman-Key-Exchange).
 *
 * Kw is specified as 'key' parameter in sa_key_exchange.
 * Kw rights are specified as 'rights' parameter in sa_key_exchange.
 */
typedef struct {
    /** Input wrapping key. */
    sa_key in_kw;
    /** Derived encryption key. */
    sa_key* out_ke;
    /** Derived encryption key rights. */
    sa_rights* rights_ke;
    /** Derived HMAC key. */
    sa_key* out_kh;
    /** Derived HMAC key rights. */
    sa_rights* rights_kh;
} sa_key_exchange_parameters_netflix_authenticated_dh;

/**
 * Structure to use in sa_svp_buffer_copy_blocks
 */
typedef struct {
    // offset into the output buffer.
    size_t out_offset;
    // offset into the input buffer.
    size_t in_offset;
    // numbers of bytes to copy or write.
    size_t length;
} sa_svp_offset;

#ifdef __cplusplus
}
#endif

#endif /* SA_TYPES_H */
