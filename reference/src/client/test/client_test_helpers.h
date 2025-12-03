/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

#ifndef CLIENT_TEST_HELPERS_H
#define CLIENT_TEST_HELPERS_H

#include "common.h"
#include "log.h"
#include "sa.h"
#include "sa_public_key.h"
#include "test_helpers.h"
#include <ctime>
#include <memory>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <string>
#include <vector>

typedef enum {
    TYPEJ_DATA_AND_KEY = 0,
    DATA_ONLY = 1,
    KEY_ONLY = 2,
    SOC_DATA_AND_KEY = 3
} key_usage;

#define EC_KEY_SIZE(ec_group) (EC_GROUP_get_degree(ec_group) / 8 + (EC_GROUP_get_degree(ec_group) % 8 == 0 ? 0 : 1))

#define UNSUPPORTED_OPENSSL_KEY static_cast<uintptr_t>(-1)

namespace client_test_helpers {
    using namespace test_helpers_openssl;

    /**
     * Obtain a sample DH Prime - 768.
     *
     * @return DH Prime 96 bytes.
     */
    std::vector<uint8_t> sample_dh_p_768();

    /**
     * Obtain a sample DH Generator - 768
     *
     * @return DH Generator.
     */
    std::vector<uint8_t> sample_dh_g_768();

    /**
     * Obtain a sample DH Prime - 1024.
     *
     * @return DH Prime 128 bytes.
     */
    std::vector<uint8_t> sample_dh_p_1024();

    /**
     * Obtain a sample DH Generator - 1024
     *
     * @return DH Generator.
     */
    std::vector<uint8_t> sample_dh_g_1024();

    /**
     * Obtain a sample DH Prime - 1536.
     *
     * @return DH Prime 192 bytes.
     */
    std::vector<uint8_t> sample_dh_p_1536();

    /**
     * Obtain a sample DH Generator - 1536
     *
     * @return DH Generator.
     */
    std::vector<uint8_t> sample_dh_g_1536();

    /**
     * Obtain a sample DH Prime - 2048.
     *
     * @return DH Prime 256 bytes.
     */
    std::vector<uint8_t> sample_dh_p_2048();

    /**
     * Obtain a sample DH Generator - 2048
     *
     * @return DH Generator.
     */
    std::vector<uint8_t> sample_dh_g_2048();

    /**
     * Obtain a sample DH Prime - 3072.
     *
     * @return DH Prime 384 bytes.
     */
    std::vector<uint8_t> sample_dh_p_3072();

    /**
     * Obtain a sample DH Generator - 3072
     *
     * @return DH Generator.
     */
    std::vector<uint8_t> sample_dh_g_3072();

    /**
     * Obtain a sample DH Prime - 4096.
     *
     * @return DH Prime 512 bytes.
     */
    std::vector<uint8_t> sample_dh_p_4096();

    /**
     * Obtain a sample DH Generator - 4096
     *
     * @return DH Generator.
     */
    std::vector<uint8_t> sample_dh_g_4096();

    /**
     * Obtain a sample invalid DH Prime - 4096.
     *
     * @return invalid DH Prime 512 bytes.
     */
    std::vector<uint8_t> sample_dh_invalid_p_4096();

    /**
     * Obtain a sample RSA 1024 key in PKCS8 format.
     *
     * @return PKCS8 key.
     */
    std::vector<uint8_t> sample_rsa_1024_pkcs8();

    /**
     * Obtain a sample RSA 1024 key with a public exponent of 3 in PKCS8 format.
     *
     * @return PKCS8 key.
     */
    std::vector<uint8_t> sample_rsa_1024_pkcs8_e3();

    /**
     * Obtain a sample RSA 2048 key in PKCS8 format.
     *
     * @return PKCS8 key.
     */
    std::vector<uint8_t> sample_rsa_2048_pkcs8();

    /**
     * Obtain a sample RSA 3072 key in PKCS8 format.
     *
     * @return PKCS8 key.
     */
    std::vector<uint8_t> sample_rsa_3072_pkcs8();

    /**
     * Obtain a sample RSA 4096 key in PKCS8 format.
     *
     * @return PKCS8 key.
     */
    std::vector<uint8_t> sample_rsa_4096_pkcs8();

    /**
     * Obtain a sample RSA 6144 key in PKCS8 format.
     *
     * @return PKCS8 key.
     */
    std::vector<uint8_t> sample_rsa_6144_pkcs8();

    /**
     * Gets DH parameters based on key size.
     * @param[in] key_size the size of the DH parameters to retrieve.
     * @return the requested parameters key.
     */
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> get_dh_parameters(size_t key_size);

    /**
     * Gets an RSA private key based on key size.
     * @param[in] key_size the size of the RSA to retrieve.
     * @return the requested RSA key.
     */
    std::vector<uint8_t> get_rsa_private_key(size_t key_size);

    /**
     * Convert time instant into ISO8601 format.
     *
     * @param[in] instant instant to convert.
     * @return ISO8601 time.
     */
    std::string iso8601(uint64_t instant);

    /**
     * Creates a shared pointer holding the sa_key value. Key will be released using
     * sa_key_release when the shared pointer gets destroyed.
     *
     * @return created shared pointer.
     */
    std::shared_ptr<sa_key> create_uninitialized_sa_key();

    /**
     * Creates a shared pointer holding the sa_crypto_cipher_context value. Context will be
     * released using sa_crypto_cipher_release when the shared pointer gets destroyed.
     *
     * @return created shared pointer.
     */
    std::shared_ptr<sa_crypto_cipher_context> create_uninitialized_sa_crypto_cipher_context();

    /**
     * Creates a shared pointer holding the sa_crypto_mac_context value. Context will be
     * released using sa_crypto_mac_release when the shared pointer gets destroyed.
     *
     * @return created shared pointer.
     */
    std::shared_ptr<sa_crypto_mac_context> create_uninitialized_sa_crypto_mac_context();

    /**
     * Create a symmetric SecApi key.
     *
     * @param[in] rights key rights.
     * @param[in] clear_key key cleartext.
     * @return created key, UNSUPPORTED_KEY (if unsupported), or nullptr (if failure).
     */
    std::shared_ptr<sa_key> create_sa_key_symmetric(
            const sa_rights* rights,
            const std::vector<uint8_t>& clear_key);

    /**
     * Create an RSA SecApi key.
     *
     * @param[in] rights key rights.
     * @param[in] clear_key key cleartext.
     * @return created key, UNSUPPORTED_KEY (if unsupported), or nullptr (if failure).
     */
    std::shared_ptr<sa_key> create_sa_key_rsa(
            const sa_rights* rights,
            const std::vector<uint8_t>& clear_key);

    /**
     * Create an EC SecApi key.
     *
     * @param[in] rights key rights.
     * @param[in] curve ec curve.
     * @param[in] clear_key key cleartext.
     * @return created key, UNSUPPORTED_KEY (if unsupported), or nullptr (if failure).
     */
    std::shared_ptr<sa_key> create_sa_key_ec(
            const sa_rights* rights,
            sa_elliptic_curve curve,
            const std::vector<uint8_t>& clear_key);

    /**
     * Create a DH SecApi key.
     *
     * @param[in] rights key rights.
     * @param[in] dh_parameters the DH p and g values.
     * @return created key, UNSUPPORTED_KEY (if unsupported), or nullptr (if failure).
     */
    std::shared_ptr<sa_key> create_sa_key_dh(
            const sa_rights* rights,
            std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>& dh_parameters);

    /**
     * Creates an sa_key.
     *
     * @param[in] key_type the type of the key to create.
     * @param[in] key_length the curve for EC keys or the key length for all others.
     * @param[out] clear_key the clear_key. (NULL for DH).
     * @param[out] curve the ec curve.
     * @return the created key or nullptr if not created.
     */
    std::shared_ptr<sa_key> create_sa_key(
            sa_key_type key_type,
            size_t& key_length,
            std::vector<uint8_t>& clear_key,
            sa_elliptic_curve& curve);

    /**
     * Obtain a key header.
     *
     * @param[in] key key to extract header from.
     * @return header shared pointer.
     */
    std::shared_ptr<sa_header> key_header(sa_key key);

    /**
     * Perform key check on a symmetric key. Key check method will be picked based on the
     * enabled key rights.
     *
     * @param[in] key key to check.
     * @param[in] clear_key key cleartext.
     * @return status of the operation.
     */
    bool key_check_sym(
            sa_key key,
            std::vector<uint8_t>& clear_key);

    /**
     * Perform key check on an RSA key. Key check method will be picked based on the
     * enabled key rights.
     *
     * @param[in] key key to check.
     * @param[in] clear_key key cleartext.
     * @return status of the operation.
     */
    bool key_check_rsa(
            sa_key key,
            const std::vector<uint8_t>& clear_key);

    /**
     * Perform key check on an EC key. Key check method will be picked based on the
     * enabled key rights.
     *
     * @param[in] key key to check.
     * @param[in] clear_key key cleartext.
     * @return status of the operation.
     */
    bool key_check_ec(
            sa_key key,
            const std::vector<uint8_t>& clear_key);

    /**
     * Exports a public key into a DER SubjectPublicKeyInfo byte vector.
     *
     * @param out the DER encoded public key.
     * @param evp_pkey the private key.
     * @return status of the operation.
     */
    bool export_public_key(
            std::vector<uint8_t>& out,
            std::shared_ptr<EVP_PKEY>& evp_pkey);

    /**
     * Import a PKCS8 RSA key into OpenSSL EVP_PKEY key.
     *
     * @param[in] in pkcs8 data.
     * @return imported key.
     */
    std::shared_ptr<EVP_PKEY> rsa_import_pkcs8(const std::vector<uint8_t>& in);

    /**
     * Verify RSA PSS signature.
     *
     * @param[in] evp_key RSA key.
     * @param[in] digest_algorithm digest algorithm.
     * @param[in] mgf1_digest_algorithm the digest algorithm for the MGF1 function.
     * @param[in] salt_length salt length.
     * @param[in] in input message.
     * @param[in] signature message signature.
     * @return status of the operation.
     */
    bool verify_rsa_pss_openssl(
            const std::shared_ptr<EVP_PKEY>& evp_key,
            sa_digest_algorithm digest_algorithm,
            sa_digest_algorithm mgf1_digest_algorithm,
            size_t salt_length,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& signature);

    /**
     * Verify RSA PKCS1v15 signature.
     *
     * @param[in] evp_key RSA key.
     * @param[in] digest_algorithm digest algorithm.
     * @param[in] in input message.
     * @param[in] signature message signature.
     * @return status of the operation.
     */
    bool verify_rsa_pkcs1v15_openssl(
            const std::shared_ptr<EVP_PKEY>& evp_key,
            sa_digest_algorithm digest_algorithm,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& signature);

    /**
     * Encrypt using RSA OAEP algorithm.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] evp_pkey RSA key.
     * @param[in] digest_algorithm the digest algorithm for OAEP padding.
     * @param[in] mgf1_digest_algorithm the digest algorithm for the MGF1 function.
     * @param[in] label the label for the OAEP padding. May be empty.
     * @return status of the operation.
     */
    bool encrypt_rsa_oaep_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::shared_ptr<EVP_PKEY>& evp_pkey,
            sa_digest_algorithm digest_algorithm,
            sa_digest_algorithm mgf1_digest_algorithm,
            const std::vector<uint8_t>& label);

    /**
     * Encrypt using RSA PKCS1v15 algorithm.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] evp_pkey RSA key.
     * @return status of the operation.
     */
    bool encrypt_rsa_pkcs1v15_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::shared_ptr<EVP_PKEY>& evp_pkey);

    /**
     * Import a EC key into OpenSSL EVP_PKEY key.
     *
     * @param[in] curve Elliptic curve to use.
     * @param[in] in private data.
     * @return imported key.
     */
    std::shared_ptr<EVP_PKEY> ec_import_private(
            sa_elliptic_curve curve,
            const std::vector<uint8_t>& in);

    /**
     * Generate a EC Key in OneAsymmetricKey format.
     *
     * @param[in] size size of the EC key.
     * @return generated EC key.
     */
    std::vector<uint8_t> ec_generate_key_bytes(sa_elliptic_curve curve);

    /**
     * Verify an ECDSA signature.
     *
     * @param[in] evp_pkey EC key.
     * @param[in] curve the elliptic curve algorithm.
     * @param[in] digest_algorithm digest algorithm.
     * @param[in] in input data.
     * @param[in] signature signature.
     * @return status of the operation.
     */
    bool verify_ec_ecdsa_openssl(
            EVP_PKEY* evp_pkey,
            sa_elliptic_curve curve,
            sa_digest_algorithm digest_algorithm,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& signature);

    /**
     * Verify an EDDSA signature.
     *
     * @param[in] evp_pkey EC key.
     * @param[in] curve the elliptic curve algorithm.
     * @param[in] in input data.
     * @param[in] signature signature.
     * @return status of the operation.
     */
    bool verify_ec_eddsa_openssl(
            EVP_PKEY* evp_pkey,
            sa_elliptic_curve curve,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& signature);

    /**
     * Encrypt input buffer with EC ElGamal algorithm. The last 4 bytes of in are used as a counter to use to locate a
     * valid point. These should be set to 0.
     *
     * @param[out] out output buffer.
     * @param[in] in the input data to encrypt.
     * @param[in] curve the ellipic curve algorithm.
     * @param[in] public_key the ec public key.
     * @return status of the operation.
     */
    bool encrypt_ec_elgamal_openssl(
            std::vector<uint8_t>& out,
            std::vector<uint8_t>& in,
            sa_elliptic_curve curve,
            const std::shared_ptr<EVP_PKEY>& public_key);

    /**
     * Encrypt data using AES CBC mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] iv initialization vector.
     * @param[in] key key.
     * @param[in] pad apply pkcs7 padding.
     * @return status of the operation.
     */
    bool encrypt_aes_cbc_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& key,
            bool pad);

    /**
     * Decrypt data using AES CBC mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] iv initialization vector.
     * @param[in] key key.
     * @param[in] pad check pkcs7 padding.
     * @return status of the operation.
     */
    bool decrypt_aes_cbc_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& key,
            bool pad);

    /**
     * Encrypt data using AES ECB mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] key key.
     * @param[in] pad apply pkcs7 padding.
     * @return status of the operation.
     */
    bool encrypt_aes_ecb_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& key,
            bool pad);

    /**
     * Decrypt data using AES ECB mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] key key.
     * @param[in] pad check pkcs7 padding.
     * @return status of the operation.
     */
    bool decrypt_aes_ecb_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& key,
            bool pad);

    /**
     * Encrypt data using AES CTR mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] counter initialization vector.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool encrypt_aes_ctr_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& counter,
            const std::vector<uint8_t>& key);

    /**
     * Decrypt data using AES CTR mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] counter counter.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool decrypt_aes_ctr_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& counter,
            const std::vector<uint8_t>& key);

    /**
     * Encrypt data using AES GCM mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] iv initialization vector.
     * @param[in] aad additional authenticated data.
     * @param[out] tag authentication tag.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool encrypt_aes_gcm_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& aad,
            std::vector<uint8_t>& tag,
            const std::vector<uint8_t>& key);

    /**
     * Decrypt data using AES GCM mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] iv initialization vector.
     * @param[in] aad additional authenticated data.
     * @param[in] tag authentication tag.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool decrypt_aes_gcm_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& aad,
            const std::vector<uint8_t>& tag,
            const std::vector<uint8_t>& key);

    /**
     * Encrypt data using CHACHA20 mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] counter counter.
     * @param[in] nonce nonce.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool encrypt_chacha20_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& counter,
            const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& key);

    /**
     * Decrypt data using CHACHA20 mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] counter counter.
     * @param[in] nonce nonce.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool decrypt_chacha20_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& counter,
            const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& key);

    /**
     * Encrypt data using CHACHA20-POLY1305 mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] nonce nonce.
     * @param[in] aad additional authenticated data.
     * @param[out] tag authentication tag.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool encrypt_chacha20_poly1305_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& aad,
            std::vector<uint8_t>& tag,
            const std::vector<uint8_t>& key);

    /**
     * Decrypt data using AES GCM mode using OpenSSL.
     *
     * @param[out] out output buffer.
     * @param[in] in input buffer.
     * @param[in] nonce nonce.
     * @param[in] aad additional authenticated data.
     * @param[in] tag authentication tag.
     * @param[in] key key.
     * @return status of the operation.
     */
    bool decrypt_chacha20_poly1305_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& aad,
            const std::vector<uint8_t>& tag,
            const std::vector<uint8_t>& key);

    /**
     * Compute HMAC value over inputs.
     *
     * @param[out] out output buffer for computed digest value.
     * @param[in] key the key for the HMAC calculation.
     * @param[in] in the input for the calculation
     * @param[in] digest_algorithm the digest algorithm to use in the HMAC.
     * @return status of the operation
     */
    bool hmac_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& in,
            sa_digest_algorithm digest_algorithm);

    /**
     * Compute CMAC value over inputs.
     *
     * @param[out] out output buffer for computed digest value.
     * @param[in] key the key for the HMAC calculation.
     * @param[in] in the input for the calculation
     * @return status of the operation
     */
    bool cmac_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& in);

    /**
     * Exports an EC_POINT into a byte array.
     * @param out the resulting byte array.
     * @param ec_point the point to export.
     * @param ec_group the EC group of the point.
     * @return
     */
    bool ec_point_export_xy(
            std::vector<uint8_t>& out,
            const EC_POINT* ec_point,
            const EC_GROUP* ec_group);

    /**
     * Allocates an sa_buffer with the given type and size.
     *
     * @param buffer_type the type of the buffer.
     * @param size the size of the buffer.
     * @return the buffer.
     */
    std::shared_ptr<sa_buffer> buffer_alloc(
            sa_buffer_type buffer_type,
            size_t size);

    /**
     * Allocates an sa_buffer with the given type and initializes it with the given value.
     *
     * @param buffer_type the type of the buffer.
     * @param initial_value the value to initialize the buffer.
     * @return the buffer.
     */
    std::shared_ptr<sa_buffer> buffer_alloc(
            sa_buffer_type buffer_type,
            std::vector<uint8_t>& initial_value);

} // namespace client_test_helpers

#endif // CLIENT_TEST_HELPERS_H
