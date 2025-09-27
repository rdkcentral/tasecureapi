/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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

#include <climits>
#include <cstdbool>
#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <limits.h>
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
 * A bit mask of all video output protection bits.
 */
#define SA_USAGE_OUTPUT_PROTECTIONS_MASK \
    (SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP) | \
     SA_USAGE_BIT_MASK(SA_USAGE_FLAG_SVP_OPTIONAL))
/**
 * A bit mask of all key usage bits
 */
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
typedef uint64_t sa_handle; // NOLINT

/**
 * Value for an uninitialized handle.
 */
#define INVALID_HANDLE ((sa_handle) ULONG_MAX)

/**
 * The number of MAGIC bytes in a key header.
 */
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
    uint64_t specification_major;
    /** minor version of the SecAPI specification */
    uint64_t specification_minor;
    /** revision version of the SecAPI specification */
    uint64_t specification_revision;
    /** revision version of the SecAPI implementation */
    uint64_t implementation_revision;
} sa_version;

/**
 * List of currently supported cipher algorithms.
 */
typedef enum {
    /** AES ECB Cipher Algorithm */
    SA_CIPHER_ALGORITHM_AES_ECB = 0,
    /** AES ECB Cipher Algorithm with PKCS7 Padding */
    SA_CIPHER_ALGORITHM_AES_ECB_PKCS7,
    /** AES CBC Cipher Algorithm */
    SA_CIPHER_ALGORITHM_AES_CBC,
    /** AES CBC Cipher Algorithm with PKCS7 Padding */
    SA_CIPHER_ALGORITHM_AES_CBC_PKCS7,
    /** AES CTR Cipher Algorithm */
    SA_CIPHER_ALGORITHM_AES_CTR,
    /** AES GCM Cipher Algorithm */
    SA_CIPHER_ALGORITHM_AES_GCM,
    /** AES RSA PKCS1 v1.5 Cipher Algorithm */
    SA_CIPHER_ALGORITHM_RSA_PKCS1V15,
    /** AES RSA OAEP Cipher Algorithm */
    SA_CIPHER_ALGORITHM_RSA_OAEP,
    /** AES EC El Gamal Cipher Algorithm */
    SA_CIPHER_ALGORITHM_EC_ELGAMAL,
    /** AES ChaCha20 Cipher Algorithm */
    SA_CIPHER_ALGORITHM_CHACHA20,
    /** AES ChaCha20 with Poly 1305 Cipher Algorithm */
    SA_CIPHER_ALGORITHM_CHACHA20_POLY1305
} sa_cipher_algorithm;

/**
 * List of cipher modes.
 */
typedef enum {
    /** Decrypt Cipher Mode */
    SA_CIPHER_MODE_DECRYPT = 0,
    /** Encrypt Cipher Mode */
    SA_CIPHER_MODE_ENCRYPT
} sa_cipher_mode;

/**
 * List of currently supported signature algorithms.
 */
typedef enum {
    /** RSA PKCS1 v1.5 Signature Algorithm */
    SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15 = 0,
    /** RSA PSS Signature Algorithm */
    SA_SIGNATURE_ALGORITHM_RSA_PSS,
    /** ECDSA Signature Algorithm */
    SA_SIGNATURE_ALGORITHM_ECDSA,
    /** EDDSA Signature Algorithm */
    SA_SIGNATURE_ALGORITHM_EDDSA
} sa_signature_algorithm;

/**
 * List of currently supported message authentication code algorithms.
 */
typedef enum {
    /** CMAC MAC Algorithm */
    SA_MAC_ALGORITHM_CMAC = 0,
    /** HMAC MAC Algorithm */
    SA_MAC_ALGORITHM_HMAC
} sa_mac_algorithm;

/**
 * List of currently supported digest algorithms.
 */
typedef enum {
    /** SHA1 Digest Algorithm */
    SA_DIGEST_ALGORITHM_SHA1 = 0,
    /** SHA256 Digest Algorithm */
    SA_DIGEST_ALGORITHM_SHA256,
    /** SHA384 Digest Algorithm */
    SA_DIGEST_ALGORITHM_SHA384,
    /** SHA512 Digest Algorithm */
    SA_DIGEST_ALGORITHM_SHA512
} sa_digest_algorithm;

/**
 * List of currently supported key derivation function algorithms.
 */
typedef enum {
    /** Root Key Ladder Key Derivation Function Algorithm--derives a key from the OTP root key */
    SA_KDF_ALGORITHM_ROOT_KEY_LADDER = 0,
    /** HKDF Key Derivation Function Algorithm.
     * See RFC 5869 for definition. */
    SA_KDF_ALGORITHM_HKDF,
    /** Concat Key Derivation Function Algorithm--a.k.a. the single step key derivation function (SSKDF).
     *  See NIST SP 56A for definition. */
    SA_KDF_ALGORITHM_CONCAT,
    /** ANSI X9.63 Key Derivation Function Algorithm.
     * See ANSI X9.63 for definition. */
    SA_KDF_ALGORITHM_ANSI_X963,
    /** CMAC Key Derivation Function Algorithm--a.k.a. the key based key derivation function (KBKDF).
     * See NIST SP 800-108 for definition. */
    SA_KDF_ALGORITHM_CMAC,
    /** Netflix Key Derivation Function Algorithm.
     * See https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication for
     * definition. */
    SA_KDF_ALGORITHM_NETFLIX,
    /** Common Root Key Ladder Key Derivation Function Algorithm--derives a key from the common SoC root key */
    SA_KDF_ALGORITHM_COMMON_ROOT_KEY_LADDER
} sa_kdf_algorithm;

/**
 * List of currently supported key exchange algorithms.
 */
typedef enum {
    /** DH Key Exchange Algorithm. */
    SA_KEY_EXCHANGE_ALGORITHM_DH = 0,
    /** ECDH Key Exchange Algorithm. */
    SA_KEY_EXCHANGE_ALGORITHM_ECDH,
    /** Netflix Key Exchange Algorithm.
     * See https://github.com/Netflix/msl/wiki/Authenticated-Diffie-Hellman-Key-Exchange for definition. */
    SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH
} sa_key_exchange_algorithm;

/**
 * List of supported key formats for sa_key_import.
 */
typedef enum {
    /** Symmetric Key Bytes Format - Raw Bytes */
    SA_KEY_FORMAT_SYMMETRIC_BYTES = 0,
    /** EC Private Bytes Key Format - PKCS #8 encoded */
    SA_KEY_FORMAT_EC_PRIVATE_BYTES,
    /** RSA Private Key Info Format - PKCS #8 encoded */
    SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO,
    /** Exported Key Format - encoded in a SoC specific way */
    SA_KEY_FORMAT_EXPORTED,
    /** SoC Key Format - encoded according to the SoC Specific Key Specification */
    SA_KEY_FORMAT_SOC,
    /** TypeJ Key Format - encoded according to the SecApi Key Container Specification */
    SA_KEY_FORMAT_TYPEJ,
    /** Provision key into SoC Key Format */
    SA_KEY_FORMAT_PROVISION_TA,
} sa_key_format;

/**
 * List of supported key types.
 */
typedef enum {
    /** Symmetric Key Type - AES & HMAC */
    SA_KEY_TYPE_SYMMETRIC = 0,
    /** Elliptic Curve Key Type */
    SA_KEY_TYPE_EC = 1,
    /** RSA Key Type */
    SA_KEY_TYPE_RSA = 2,
    /** Diffie-Hellman Key Type */
    SA_KEY_TYPE_DH = 3
} sa_key_type;

/**
 * List of supported elliptic curves.
 */
typedef enum {
    /** NIST P-256 Elliptic Curve */
    SA_ELLIPTIC_CURVE_NIST_P256 = 0,
    /** NIST P-384 Elliptic Curve
     * This curve is for future support and is not currently required. */
    SA_ELLIPTIC_CURVE_NIST_P384 = 1,
    /** NIST P-521 Elliptic Curve
     * This curve is for future support and is not currently required. */
    SA_ELLIPTIC_CURVE_NIST_P521 = 2,
    /** ED25519 Elliptic Curve
     * Supported only with SA_SIGNATURE_ALGORITHM_EDDSA */
    SA_ELLIPTIC_CURVE_ED25519 = 3,
    /** X25519 Elliptic Curve
     * Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH. */
    SA_ELLIPTIC_CURVE_X25519 = 4,
    /** ED448 Elliptic Curve
     * Supported only with SA_SIGNATURE_ALGORITHM_EDDSA.
     * This curve is for future support and is not currently required. */
    SA_ELLIPTIC_CURVE_ED448 = 5,
    /** ED448 Elliptic Curve
     * Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH.
     * This curve is for future support and is not currently required. */
    SA_ELLIPTIC_CURVE_X448 = 6,
    /** NIST P-192 Elliptic Curve */
    SA_ELLIPTIC_CURVE_NIST_P192 = 7,
    /** NIST P-224 Elliptic Curve */
    SA_ELLIPTIC_CURVE_NIST_P224 = 8
} sa_elliptic_curve;

/**
 * List of buffer types.
 */
typedef enum {
    /** Clear Buffer Type */
    SA_BUFFER_TYPE_CLEAR = 0,
    /** SVP Buffer Type */
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

/**
 * The number of allowed TA IDs in a key header.
 */
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

/**
 * The maxium length of the p and g values in DH parameters.
 */
#define DH_MAX_MOD_SIZE 512

/**
 * Type parameters for the sa_header.
 */
typedef union {
    /** EC curve type. */
    sa_elliptic_curve curve;

    /** DH parameters. */
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
        /** Clear buffer information */
        struct {
            /** Buffer data */
            void* buffer;
            /** Length of the buffer */
            size_t length;
            /** Current offset into the buffer */
            size_t offset;
        } clear;
#ifndef DISABLE_SVP
        /** SVP buffer information */
        struct {
            /** SVP buffer handle */
            sa_svp_buffer buffer;
            /** Current offset into the buffer */
            size_t offset;
        } svp;
#endif // DISABLE_SVP
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
 * Import parameters for a SoC key container. This structure is used to signal the SecApi compatability version of the
 * key container and to identify the object_id in the key rights. This structure can be extended in a SoC specific way
 * with additional fields at the end, however the length field must include the sizeof the extended structure.
 */
typedef struct {
    /** The size of this structure. The most significant size byte is in length[0] and the least
        significant size byte is in length[1]. */
    uint8_t length[2];

    /** The SecApi version that the key container is compatible with. Must be either version 2 or version 3. */
    uint8_t version;

    /** The default key rights to use only if the key container does not contain included key rights. */
    sa_rights default_rights;

    /** The object ID of the key. The first 8 bytes of the sa_rights.id field will be set to this value in big endian
     * form. */
    uint64_t object_id;
} sa_import_parameters_soc;

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
 * KDF parameters for SA_KDF_ALGORITHM_HKDF. See RFC 5869 for definition.
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
 * KDF parameters for SA_KDF_ALGORITHM_CONCAT. See NIST SP 56A for definition.
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
 * KDF parameters for SA_KDF_ALGORITHM_ANSI_X963. See ANSI X9.63 for definition.
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
 * KDF parameters for SA_KDF_ALGORITHM_CMAC. See NIST SP 800-108 for definition.
 */
typedef struct {
    /** Derived key length in bytes. */
    size_t key_length;
    /** Parent key handle. */
    sa_key parent;
    /** Other data value. Should be Label || 0x00 || Context || L according to NIST SP 800-108 */
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
#ifndef DISABLE_SVP
typedef struct {
    /** offset into the output buffer. */
    size_t out_offset;
    /** offset into the input buffer. */
    size_t in_offset;
    /** numbers of bytes to copy or write. */
    size_t length;
} sa_svp_offset;
#endif

/** TA Key Type Definition */

/*The operator provisioning key type will be communicated through the following enumeration:
 */
typedef enum  {
  WIDEVINE_OEM_PROVISIONING,
  PLAYREADY_MODEL_PROVISIONING,
  APPLE_MFI_PROVISIONING,
  APPLE_FAIRPLAY_PROVISIONING,
  NETFLIX_PROVISIONING
} sa_key_type_ta;

/** PlayReady model types */

typedef enum {
  PLAYREADY_MODEL_2K,
  PLAYREADY_MODEL_3K
} PLAYREADY_MODEL_TYPE;

/** Widevine OEM Provisioning Structure */

/*The object provided as input to the sa_key_provision_ta API via the in parameter for the
  WIDEVINE_OEM_PROVISIONING key type contains the following Widevine OEM Provisioning 3.0 model
  properties.
 */

typedef struct {
  unsigned int oemDevicePrivateKeyLength;
  void * oemDevicePrivateKey;
  unsigned int oemDeviceCertificateLength;
  void * oemDeviceCertificate;
} WidevineOemProvisioning;


/** PlayReady Model Provisioning Structure */

/*The object provided as input to the sa_ta_key_provision API via the in parameter for the
  PLAYREADY_MODEL_PROVISIONING key type contains the following properties.
 */

typedef struct {
  unsigned int modelType; // 2K or 3K
  unsigned int privateKeyLength;
  void * privateKey;
  unsigned int modelCertificateLength;
  void * modelCertificate;
} PlayReadyProvisioning;

/** Netflix Provisioning Structure */

/*The object provided as input to the sa_ta_key_provision API via the in parameter for the
  NETFLIX_PROVISIONING key type contains the following properties.
 */

typedef struct {
  unsigned int encryptionKeyLength;
  void * encryptionKey; // kde
  unsigned int hmacKeyLength;
  void * hmacKey; //kdh
  unsigned int wrappingKeyLength;
  void * wrappingKey; //kdw
  unsigned int esnContainerLength;
  void * esnContainer; //ESN
} NetflixProvisioning;

/** Apple MFi Provisioning Structure */

/*The object provided as input to the sa_key_provision_ta API via the in parameter for the
  APPLE_MFI_PROVISIONING key type contains the following properties.
 */

typedef struct {
  unsigned int mfiBaseKeyLength;
  void * mfiBaseKey;
  unsigned int mfiProvisioningObjectLength;
  void * mfiProvisioningObject;
} AppleMfiProvisioning;

/** Apple FairPlay Provisioning Structure */

/*The object provided as input to the sa_key_provision_ta API via the in parameter for the
  APPLE_FAIRPLAY_PROVISIONING key type contains the following properties.
 */

typedef struct {
  unsigned int fairPlaySecretLength;
  void * fairPlaySecret;
} AppleFairPlayProvisioning;

#ifdef __cplusplus
}
#endif

#endif /* SA_TYPES_H */
