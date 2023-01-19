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

/** @section Description
 * @file sa_ta_types.h
 *
 * This file contains the TA specific structures and constants.
 */

#ifndef SA_TA_TYPES_H
#define SA_TA_TYPES_H

#include "sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16
#define GCM_IV_LENGTH 12
#define CHACHA20_COUNTER_LENGTH 4
#define CHACHA20_NONCE_LENGTH 12
#define API_VERSION 1

/**
 * Command IDs of the SecApi 3 commands, used in the ta_invoke_command function.
 */
typedef enum {
    SA_GET_VERSION = 1,
    SA_GET_NAME,
    SA_GET_DEVICE_ID,
    SA_GET_TA_UUID,
    SA_KEY_GENERATE,
    SA_KEY_EXPORT,
    SA_KEY_IMPORT,
    SA_KEY_UNWRAP,
    SA_KEY_GET_PUBLIC,
    SA_KEY_DERIVE,
    SA_KEY_EXCHANGE,
    SA_KEY_RELEASE,
    SA_KEY_HEADER,
    SA_KEY_DIGEST,
    SA_CRYPTO_RANDOM,
    SA_CRYPTO_CIPHER_INIT,
    SA_CRYPTO_CIPHER_UPDATE_IV,
    SA_CRYPTO_CIPHER_PROCESS,
    SA_CRYPTO_CIPHER_PROCESS_LAST,
    SA_CRYPTO_CIPHER_RELEASE,
    SA_CRYPTO_MAC_INIT,
    SA_CRYPTO_MAC_PROCESS,
    SA_CRYPTO_MAC_PROCESS_KEY,
    SA_CRYPTO_MAC_COMPUTE,
    SA_CRYPTO_MAC_RELEASE,
    SA_CRYPTO_SIGN,
    SA_SVP_SUPPORTED,
    SA_SVP_BUFFER_ALLOC,
    SA_SVP_BUFFER_CREATE,
    SA_SVP_BUFFER_FREE,
    SA_SVP_BUFFER_RELEASE,
    SA_SVP_BUFFER_WRITE,
    SA_SVP_BUFFER_COPY,
    SA_SVP_KEY_CHECK,
    SA_SVP_BUFFER_CHECK,
    SA_PROCESS_COMMON_ENCRYPTION
} SA_COMMAND_ID;

/**
 * The types of the TA parameters.
 */
typedef enum {
    TA_PARAM_NULL,
    TA_PARAM_IN,
    TA_PARAM_OUT,
    TA_PARAM_INOUT
} ta_param_type;

/**
 * TA parameter structure that identifies a memory reference and its size.
 */
typedef struct {
    void* mem_ref;
    size_t mem_ref_size;
} ta_param;

// sa_get_version
// param[0] INOUT - sa_get_version_s
typedef struct {
    uint8_t api_version;
    sa_version version;
} sa_get_version_s;

// sa_get_name
// param[0] INOUT - sa_get_name_s
// param[1] OUT - name
typedef struct {
    uint8_t api_version;
    size_t name_length;
} sa_get_name_s;

// sa_get_device_id
// param[0] INOUT - sa_get_device_id_s
typedef struct {
    uint8_t api_version;
    uint64_t id;
} sa_get_device_id_s;

// sa_get_ta_uuid
// param[0] INOUT - sa_get_ta_uuid_s
typedef struct {
    uint8_t api_version;
    sa_uuid uuid;
} sa_get_ta_uuid_s;

// sa_key_generate
// param[0] INOUT - sa_key_generate_s
// param[1] IN - DH p + length
// param[2] IN - DH g + length
typedef struct {
    uint8_t api_version;
    sa_key key;
    sa_rights rights;
    uint32_t key_type;
    size_t key_length; // key_length or curve
} sa_key_generate_s;

// sa_key_export
// param[0] INOUT - sa_key_export_s
// param[1] OUT - out+out_length
// param[2] IN - mixin+mixin_length
typedef struct {
    uint8_t api_version;
    size_t out_length;
    sa_key key;
} sa_key_export_s;

// sa_key_import
// param[0] INOUT - sa_key_import_s
// param[1] IN - in + in_length
// param[2] IN - rights or sa_import_parameters_typej or sa_import_parameters_soc
typedef struct {
    uint8_t api_version;
    sa_key key;
    uint32_t key_format;
    uint32_t curve;
} sa_key_import_s;

// sa_key_unwrap
// param[0] INOUT - sa_key_unwrap_s
// param[1] IN - in + in_length
// param[2] IN - sa_unwrap_parameters_aes_iv_s or sa_unwrap_parameters_aes_gcm_s or sa_unwrap_parameters_ec_elgamal_s or
// sa_unwrap_parameters_chacha20_s or sa_unwrap_parameters_chacha20_poly1305_s or sa_unwrap_parameters_rsa_oaep_s
// param[3] IN - aad + aad_length or label + label_length
typedef struct {
    uint8_t api_version;
    sa_key key;
    sa_rights rights;
    uint32_t key_type;
    uint32_t curve;
    uint32_t cipher_algorithm;
    uint32_t wrapping_key;
} sa_key_unwrap_s;

typedef struct {
    uint8_t iv[AES_BLOCK_SIZE];
} sa_unwrap_parameters_aes_iv_s;

typedef struct {
    uint8_t iv[GCM_IV_LENGTH];
    size_t iv_length;
    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t tag_length;
} sa_unwrap_parameters_aes_gcm_s;

typedef struct {
    uint8_t counter[CHACHA20_COUNTER_LENGTH];
    size_t counter_length;
    uint8_t nonce[CHACHA20_NONCE_LENGTH];
    size_t nonce_length;
} sa_unwrap_parameters_chacha20_s;

typedef struct {
    uint8_t nonce[CHACHA20_NONCE_LENGTH];
    size_t nonce_length;
    uint8_t tag[AES_BLOCK_SIZE];
    uint8_t tag_length;
} sa_unwrap_parameters_chacha20_poly1305_s;

typedef struct {
    sa_digest_algorithm digest_algorithm;
    sa_digest_algorithm mgf1_digest_algorithm;
} sa_unwrap_parameters_rsa_oaep_s;

typedef sa_unwrap_parameters_ec_elgamal sa_unwrap_parameters_ec_elgamal_s;

// sa_key_get_public
// param[0] INOUT - sa_key_get_public_s
// param[1] OUT - out + out_length
typedef struct {
    uint8_t api_version;
    size_t out_length;
    sa_key key;
} sa_key_get_public_s;

// sa_key_derive
// param[0] INOUT - sa_key_derive_s
// param[1] IN - sa_kdf_parameters_root_key_ladder_s or sa_kdf_parameters_hkdf_s or sa_kdf_parameters_concat_s or
// sa_kdf_parameters_ansi_x963_s or sa_kdf_parameters_cmac_s or sa_kdf_parameters_netflix_s
// param[2] IN - info or other_data
// param[3] IN - salt
typedef struct {
    uint8_t api_version;
    sa_key key;
    sa_rights rights;
    uint32_t kdf_algorithm;
} sa_key_derive_s;

typedef struct {
    uint8_t c1[AES_BLOCK_SIZE];
    uint8_t c2[AES_BLOCK_SIZE];
    uint8_t c3[AES_BLOCK_SIZE];
    uint8_t c4[AES_BLOCK_SIZE];
} sa_kdf_parameters_root_key_ladder_s;

typedef struct {
    size_t key_length;
    uint32_t digest_algorithm;
    sa_key parent;
} sa_kdf_parameters_hkdf_s;

typedef struct {
    size_t key_length;
    uint32_t digest_algorithm;
    sa_key parent;
} sa_kdf_parameters_concat_s;

typedef struct {
    size_t key_length;
    uint32_t digest_algorithm;
    sa_key parent;
} sa_kdf_parameters_ansi_x963_s;

typedef struct {
    size_t key_length;
    sa_key parent;
    uint32_t counter;
} sa_kdf_parameters_cmac_s;

typedef sa_kdf_parameters_netflix sa_kdf_parameters_netflix_s;

// sa_key_exchange
// param[0] INOUT - sa_key_exchange_s
// param[1] IN - other_public + other_public_length
// param[2] IN - sa_key_exchange_parameters_netflix_authenticated_dh_s
typedef struct {
    uint8_t api_version;
    sa_key key;
    sa_rights rights;
    uint32_t key_exchange_algorithm;
    sa_key private_key;
} sa_key_exchange_s;

typedef struct {
    sa_key in_kw;
    sa_key out_ke;
    sa_rights rights_ke;
    sa_key out_kh;
    sa_rights rights_kh;
} sa_key_exchange_parameters_netflix_authenticated_dh_s;

// sa_key_release
// param[0] INOUT - sa_key_release_s
typedef struct {
    uint8_t api_version;
    sa_key key;
} sa_key_release_s;

// sa_key_header
// param[0] INOUT - sa_key_header_s
typedef struct {
    uint8_t api_version;
    sa_header header;
    sa_key key;
} sa_key_header_s;

// sa_key_digest
// param[0] INOUT - sa_key_digest_s
// param[1] OUT - out + length
typedef struct {
    uint8_t api_version;
    size_t out_length;
    sa_key key;
    sa_digest_algorithm digest_algorithm;
} sa_key_digest_s;

// sa_crypto_random
// param[0] IN - sa_crypto_random_s
// param[1] OUT - out + length
typedef struct {
    uint8_t api_version;
} sa_crypto_random_s;

// sa_crypto_cipher_init
// param[0] INOUT - sa_crypto_cipher_init_s
// param[1] IN - iv + iv_length or nonce + nonce_length or sa_cipher_parameters_rsa_oaep_s
// param[2] IN - aad + aad_length or counter + counter_length or label + label_length
typedef struct {
    uint8_t api_version;
    sa_crypto_cipher_context context;
    uint32_t cipher_algorithm;
    uint32_t cipher_mode;
    sa_key key;
} sa_crypto_cipher_init_s;

typedef struct {
    sa_digest_algorithm digest_algorithm;
    sa_digest_algorithm mgf1_digest_algorithm;
} sa_cipher_parameters_rsa_oaep_s;

// sa_crypto_cipher_update_iv_s
// param[0] IN - sa_crypto_cipher_context
// param[1] IN - iv + iv_length
typedef struct {
    uint8_t api_version;
    sa_crypto_cipher_context context;
} sa_crypto_cipher_update_iv_s;

// sa_crypto_cipher_process
// param[0] INOUT - sa_crypto_cipher_process_s
// param[1] OUT - out.buffer
// param[2] IN - in.buffer
typedef struct {
    uint8_t api_version;
    sa_crypto_cipher_context context;
    size_t bytes_to_process;
    uint32_t out_buffer_type;
    size_t out_offset;
    uint32_t in_buffer_type;
    size_t in_offset;
} sa_crypto_cipher_process_s;

// sa_crypto_cipher_process_last
// param[0] INOUT - sa_crypto_cipher_process_s
// param[1] OUT - out
// param[2] IN - in
// param[3] IN - tag + tag_length
// use sa_crypto_cipher_process_s

// sa_crypto_cipher_release
// param[0] IN - sa_cipher_release_s
typedef struct {
    uint8_t api_version;
    sa_crypto_cipher_context cipher_context;
} sa_crypto_cipher_release_s;

// sa_crypto_mac_init
// param[0] INOUT - sa_crypto_mac_init_s
typedef struct {
    uint8_t api_version;
    sa_crypto_mac_context context;
    uint32_t mac_algorithm;
    sa_key key;
    uint32_t digest_algorithm; // HMAC
} sa_crypto_mac_init_s;

// sa_crypto_mac_process
// param[0] IN - sa_crypto_mac_context
// param[1] IN - in + length
typedef struct {
    uint8_t api_version;
    sa_crypto_mac_context mac_context;
} sa_crypto_mac_process_s;

// sa_crypto_mac_process_key
// param[0] IN - sa_crypto_mac_context
typedef struct {
    uint8_t api_version;
    sa_crypto_mac_context mac_context;
    sa_key key;
} sa_crypto_mac_process_key_s;

// sa_crypto_mac_compute
// param[0] INOUT - sa_crypto_mac_compute_s
// param[1] OUT - out + length
typedef struct {
    uint8_t api_version;
    size_t out_length;
    sa_crypto_mac_context context;
} sa_crypto_mac_compute_s;

// sa_crypto_mac_release
// param[0] IN - sa_crypto_mac_release_s
typedef struct {
    uint8_t api_version;
    sa_crypto_mac_context context;
} sa_crypto_mac_release_s;

// sa_crypto_sign
// param[0] INOUT - sa_crypto_sign_s
// param[1] OUT - out
// param[2] IN - in
typedef struct {
    uint8_t api_version;
    size_t out_length;
    uint32_t signature_algorithm;
    uint32_t digest_algorithm;
    sa_key key;
    size_t salt_length;                        // RSA PSS
    sa_digest_algorithm mgf1_digest_algorithm; // RSA PSS
    bool precomputed_digest;
} sa_crypto_sign_s;

// sa_svp_supported
// param[0] IN - sa_svp_supported_s
typedef struct {
    uint8_t api_version;
} sa_svp_supported_s;

// sa_svp_buffer_create
// param[0] INOUT - sa_svp_buffer
// param[1] IN - buffer+size
typedef struct {
    uint8_t api_version;
    sa_svp_buffer svp_buffer;
    uintptr_t svp_memory;
    size_t size;
} sa_svp_buffer_create_s;

// sa_svp_buffer_release
// param[0] INOUT - sa_svp_buffer_release_s
typedef struct {
    uint8_t api_version;
    uintptr_t svp_memory;
    size_t size;
    sa_svp_buffer svp_buffer;
} sa_svp_buffer_release_s;

// sa_svp_buffer_write
// param[0] INOUT - sa_svp_buffer_write_s
// param[1] IN - in + in_length
// param[2] IN - sa_svp_offset
typedef struct {
    uint8_t api_version;
    sa_svp_buffer out;
} sa_svp_buffer_write_s;

// sa_svp_buffer_copy
// param[0] INOUT - sa_svp_buffer_copy_s
// param[1] IN - sa_svp_block
typedef struct {
    uint8_t api_version;
    sa_svp_buffer out;
    sa_svp_buffer in;
} sa_svp_buffer_copy_s;

// sa_svp_key_check
// param[0] INOUT - sa_svp_key_check_s
// param[1] IN - in
// param[2] IN - expected+length
typedef struct {
    uint8_t api_version;
    sa_key key;
    uint32_t in_buffer_type;
    size_t in_offset;
    size_t bytes_to_process;
} sa_svp_key_check_s;

// sa_svp_buffer_check
// param[0] IN - sa_svp_buffer_check_s
// param[1] IN - hash+length
typedef struct {
    uint8_t api_version;
    sa_svp_buffer svp_buffer;
    size_t offset;
    size_t length;
    uint32_t digest_algorithm;
} sa_svp_buffer_check_s;

// sa_process_common_encryption (1 sample per call)
// param[0] INOUT - sa_process_common_encryption_s
// param[1] IN - subsample_lengths
// param[2] OUT - out.buffer
// param[3] IN - in.buffer
typedef struct {
    uint8_t api_version;
    uint8_t iv[AES_BLOCK_SIZE];
    size_t crypt_byte_block;
    size_t skip_byte_block;
    size_t subsample_count;
    sa_crypto_cipher_context context;
    uint32_t out_buffer_type;
    size_t out_offset;
    uint32_t in_buffer_type;
    size_t in_offset;
} sa_process_common_encryption_s;
#ifdef __cplusplus
}
#endif

#endif // SA_TA_TYPES_H
