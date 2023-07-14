/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 * @file sa_provider.h
 *
 * sa_provider implements an OpenSSL 3 Provider that delegates its implementation to SecApi 3. Users can use the OpenSSL
 * API, but SecApi 3 will be used to perform the cryptographic processing.
 *
 * To use a provider, users must call sa_get_provider(). This will create an OpenSSL Library Context and initialize it
 * with a base provider and the SecApi 3 provider. The OpenSSL Library Context must not be freed.
 *
 * Private keys that have been imported into SecApi 3 should be loaded into OpenSSL using the EVP_PKEY_fromdata
 * function using the OSSL_PARAM_SA_KEY parameter. Including the OSSL_PARAM_SA_KEY_DELETE parameter causes EVP_PKEY
 * object to take ownership of the key and sa_key_release will be called when the EVP_PKEY object is freed:
 *
 * Example:
 * --------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * OSSL_PARAM params[] = {
 *       OSSL_PARAM_construct_uint64(OSSL_PARAM_SA_KEY, key),
 *       OSSL_PARAM_construct_int(OSSL_PARAM_SA_KEY_DELETE, 1),
 *       OSSL_PARAM_construct_end()};
 * EVP_PKEY_CTX* = EVP_PKEY_CTX_new_from_name(lib_ctx, "RSA", nullptr);
 * EVP_PKEY_fromdata_init(evp_pkey_ctx);
 * EVP_PKEY* evp_pkey = NULL;
 * EVP_PKEY_fromdata(evp_pkey_ctx, &evp_pkey, EVP_PKEY_KEYPAIR, params);
 * ```
 *
 * A Clear PKCS8 formatted private key can also be read into an EVP_PKEY.
 * Example:
 * --------
 * ```
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * uint8_t* clear_pkcs8_key = // Retrieve PKCS8 formatted key bytes.
 * size_t clear_pkcs8_key_length = // Retrieve PKCS8 formatted key size.
 * const uint8_t* p_clear_pkcs8_key = clear_pkcs8_key;
 * EVP_PKEY* evp_pkey = d2i_AutoPrivateKey_ex(NULL, &p_clear_pkcs8_key, clear_pkcs8_key_length, lib_ctx, NULL);
 * ```
 *
 * Examples of SecApi 3 Usage with OpenSSL:
 * ========================================
 * These examples assume the private key has been imported using the above examples.
 *
 * Signing (RSA, EC, ED25519, ED448)
 * ---------------------------------
 * ```
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_MD_CTX* evp_md_ctx = EVP_MD_CTX_new();
 * EVP_PKEY_CTX* evp_pkey_ctx;
 * // Padding parameters can alternatively be passed into params parameter.
 * EVP_DigestSignInit_ex(evp_md_ctx, &evp_pkey_ctx, "SHA256", lib_ctx, NULL, evp_pkey, NULL);
 * EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PSS_PADDING);
 * EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ctx, 16);
 * EVP_DigestSignUpdate(evp_md_ctx, data, data_length);
 * EVP_DigestSignFinal(evp_md_ctx, signature, &signature_length);
 * EVP_MD_CTX_free(evp_md_ctx);
 * EVP_PKEY_free(evp_pkey);
 * ```
 *
 * Signing Predigested Content (RSA, EC)
 * -------------------------------------
 * ```
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_PKEY_CTX* evp_pkey_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey, nullptr);
 * // Padding parameters can alternatively be passed into params parameter.
 * EVP_PKEY_sign_init_ex(evp_pkey_ctx, NULL);
 * EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PSS_PADDING);
 * EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ctx, 16);
 * EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md);
 * EVP_PKEY_sign(evp_pkey_ctx, signature, &signature_length, digest, digest_length);
 * EVP_MD_CTX_free(evp_md_ctx);
 * EVP_PKEY_free(evp_pkey);
 * ```
 *
 * Decryption (RSA)
 * ----------------
 * ```
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_PKEY_CTX* evp_pkey_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey, nullptr);
 * // Padding parameters can alternatively be passed into params parameter.
 * EVP_PKEY_decrypt_init_ex(evp_pkey_ctx, NULL);
 * EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PADDING);
 * EVP_PKEY_decrypt(evp_pkey_ctx, decrypted_data, &decrypted_data_length, encrypted_data, encrypted_data_length);
 * EVP_PKEY_CTX_free(evp_pkey_ctx);
 * EVP_PKEY_free(evp_pkey);
 * ```
 *
 * Derivation (DH, EC, X25519, X448)
 * ---------------------------------
 * ```
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_PKEY_CTX* evp_pkey_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey, nullptr);
 * EVP_PKEY_derive_init(evp_pkey_ctx);
 * EVP_PKEY_derive_set_peer(evp_pkey_ctx, other_public_key);
 * EVP_PKEY_derive(evp_pkey_ctx, shared_secret, &shared_secret_length);
 * sa_key shared_secret_key = *((sa_key*)shared_secret);
 * EVP_PKEY_CTX_free(evp_pkey_ctx);
 * EVP_PKEY_free(evp_pkey);
 * sa_engine_free(engine);
 * ```
 *
 * KDF (HMAC, CONCAT a.k.a. SSKDF, ANSI_X963 a.k.a. X963KDF, CMAC a.k.a. KBKDF)
 * ----------------------------------------------------------------------------
 * ```
 * sa_key shared_secret_key = // shared secret key potentially derived through DH, EC, X25519, or X448
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_KDF* evp_kdf = EVP_KDF_fetch(lib_ctx, "HMAC", NULL);
 * EVP_KDF_CTX* evp_kdf_ctx = EVP_KDF_CTX_new(evp_kdf);
 * OSSL_PARAM params[] = {
 *     OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared_secret_key, sizeof(sa_key)),
 *     OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 6),
 *     OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_length),
 *     OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_length),
 *     OSSL_PARAM_END};
 * EVP_KDF_derive(evp_kdf_ctx, derived, derived_length, params);
 * sa_key derived_key = *((sa_key*)derived);
 * EVP_KDF_CTX_free(evp_kdf_ctx);
 * EVP_KDF_free(evp_kdf);
 * ```
 *
 * MAC (HMAC, CMAC)
 * ----------------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_MAC* evp_mac = EVP_MAC_fetch(lib_ctx, "HMAC", NULL);
 * OSSL_PARAM params[] = {
 *     OSSL_PARAM_construct_uint64(OSSL_PARAM_SA_KEY, key),
 *     OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 6),
 *     OSSL_PARAM_construct_end()};
 * // A clear raw HMAC/CMAC key can alternatively be passed into the key parameter--SA_KEY_DELETE will automatically
 * // be set to true.
 * EVP_MAC* evp_mac = EVP_MAC_init(evp_mac_ctx.get(), NULL, 0, params);
 * EVP_MAC_update(evp_mac_ctx, data, data_length);
 * size_t mac_out_length;
 * EVP_MAC_final(evp_mac_ctx, mac, &mac_out_length, mac_length);
 * EVP_MAC_free(evp_mac_ctx);
 * ```
 *
 * Encryption/Decryption (AES, CHACHA20)
 * -------------------------------------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * OSSL_LIB_CTX* lib_ctx = sa_get_provider();
 * EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(lib_ctx, "aes-128-cbc", nullptr);
 * OSSL_PARAM params[] = {
 *     OSSL_PARAM_construct_uint64(OSSL_PARAM_SA_KEY, key),
 *     OSSL_PARAM_construct_end()};
 * EVP_CIPHER_CTX* evp_cipher_ctx = EVP_CIPHER_CTX_new();
 * // A clear raw symmetric key can alternatively be passed into the key parameter--SA_KEY_DELETE will automatically
 * // be set to true.
 * EVP_CipherInit_ex2(evp_cipher_ctx, evp_cipher, NULL, iv, 1, params); // 1 = enc, 0 = dec
 * EVP_CipherUpdate(evp_cipher_ctx, encrypted_data, &length, data, data_length);
 * EVP_CipherFinal(evp_cipher_ctx, encrypted_data + total_length, &length);
 * EVP_CIPHER_CTX_free(evp_cipher_ctx);
 * EVP_CIPHER_free(cipher);
 * ```
 */

#ifndef SA_PROVIDER_H
#define SA_PROVIDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslconf.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/types.h>

/**
 * The provider ID used to register the SecApi 3 provider.
 */
#define SA_PROVIDER_ID "secapi3"

/**
 * The name of the SecApi 3 provider.
 */
#define SA_PROVIDER_NAME "SecApi3 Provider"

/**
 * The OSSL_PARAM_SA_KEY parameter is used to import the SecApi 3 key handle into an EVP_PKEY object, for private keys,
 * or, for symmetric keys, into the the EVP_CIPHER_CTX object when used with EVP_CipherInit_ex2 or into the EVP_MAC_CTX
 * object when used with EVP_MAC_init.
 */
#define OSSL_PARAM_SA_KEY "sa_key"

/**
 * The OSSL_PARAM_SA_KEY_DELETE parameter, when set to 1, directs the SecApi 3 provider to release the sa_key handle
 * when the EVP_PKEY, EVP_MAC_CTX, or EVP_CIPHER_CTX object is freed (the EVP_PKEY, EVP_MAC_CTX, or EVP_CIPHER_CTX
 * object assumes control of the handle). If the parameter is 0 or not set, the SecApi 3 provider assumes that the
 * caller will release the sa_key handle when they are done using it.
 */
#define OSSL_PARAM_SA_KEY_DELETE "sa_key_delete"

/**
 * Retrieves the OpenSSL library context initialized with the SecApi3 provider.
 *
 * @return NULL if not successful.
 */
OSSL_LIB_CTX* sa_get_provider();

#endif

#ifdef __cplusplus
}
#endif

#endif //SA_PROVIDER_H
