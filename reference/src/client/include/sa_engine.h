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

/**
 * @file sa_engine.h
 *
 * sa_engine implements an OpenSSL Engine that delegates its implementation to SecApi 3. Users can use the OpenSSL
 * API, but SecApi3 will be used to perform the cryptographic processing.
 *
 * To use an engine, users must call sa_get_engine(). This will create a singleton instance of engine and then retrieve
 * it, incrementing its reference count. Users will submit the Engine as the impl parameter in calls like
 * EVP_EncryptInit_ex and EVP_SignInit_ex. Once finished with the Engine, users must call sa_engine_free. This does not
 * free the engine, but decrements its reference count.  For APIs that take an unsigned char* key parameter, a pointer
 * to the sa_key value should passed in with sizeof(sa_key) as its length. For asymmetric keys,
 * ENGINE_load_private_key should be called passing in the engine and a pointer to the sa_key value.
 *
 * Examples:
 * =========
 * Signing (RSA, EC, ED25519, ED448)
 * ---------------------------------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * ENGINE* engine = sa_get_engine();
 * EVP_PKEY* evp_pkey = ENGINE_load_private_key(engine, (char*)&key, NULL, NULL);
 * EVP_MD_CTX* evp_md_ctx = EVP_MD_CTX_new();
 * EVP_PKEY_CTX* evp_pkey_ctx;
 * EVP_DigestSignInit(evp_md_ctx, &evp_pkey_ctx, EVP_sha256(), engine, evp_pkey);
 * EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PSS_PADDING);
 * EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ctx, 16);
 * EVP_DigestSignUpdate(evp_md_ctx, data, data_length);
 * EVP_DigestSignFinal(evp_md_ctx, signature, &signature_length);
 * EVP_MD_CTX_free(evp_md_ctx);
 * EVP_PKEY_free(evp_pkey);
 * sa_engine_free(engine);
 * ```
 *
 * Signing Predigested Content (RSA, EC)
 * -------------------------------------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * ENGINE* engine = sa_get_engine();
 * EVP_PKEY* evp_pkey = ENGINE_load_private_key(engine, (char*)&key, NULL, NULL);
 * EVP_MD_CTX* evp_md_ctx = EVP_MD_CTX_new();
 * EVP_PKEY_CTX* evp_pkey_ctx;
 * EVP_PKEY_sign_init(evp_pkey_ctx);
 * EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PSS_PADDING);
 * EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ctx, 16);
 * EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md);
 * EVP_PKEY_sign(evp_pkey_ctx, signature, &signature_length, digest, digest_length);
 * EVP_MD_CTX_free(evp_md_ctx);
 * EVP_PKEY_free(evp_pkey);
 * sa_engine_free(engine);
 * ```
 *
 * Decryption (RSA)
 * ----------------
 * ```
 * ENGINE* engine = sa_get_engine();
 * EVP_PKEY* evp_pkey = ENGINE_load_private_key(engine, (char*)&key, NULL, NULL);
 * EVP_PKEY_CTX* evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, engine);
 * EVP_PKEY_decrypt_init(evp_pkey_ctx);
 * EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PADDING);
 * EVP_PKEY_decrypt(evp_pkey_ctx, decrypted_data, &decrypted_data_length, encrypted_data, encrypted_data_length);
 * EVP_PKEY_CTX_free(evp_pkey_ctx);
 * EVP_PKEY_free(evp_pkey);
 * sa_engine_free(engine);
 * ```
 *
 * Derivation (DH, EC, X25519, X448)
 * ---------------------------------
 * ```
 * ENGINE* engine = sa_get_engine();
 * EVP_PKEY* evp_pkey = ENGINE_load_private_key(engine, (char*)&key, NULL, NULL);
 * EVP_PKEY_CTX* evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, engine);
 * EVP_PKEY_derive_init(evp_pkey_ctx);
 * EVP_PKEY_derive_set_peer(evp_pkey_ctx, other_public_key);
 * EVP_PKEY_derive(evp_pkey_ctx, shared_secret, &shared_secret_length);
 * sa_key shared_secret_key = *((sa_key*)shared_secret);
 * EVP_PKEY_CTX_free(evp_pkey_ctx);
 * EVP_PKEY_free(evp_pkey);
 * sa_engine_free(engine);
 * ```
 *
 * MAC (HMAC, CMAC with a symmetric key) - Only OpenSSL 1.1.1
 * ----------------------------------------------------------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * ENGINE* engine = sa_get_engine();
 * EVP_PKEY* evp_pkey = ENGINE_load_private_key(engine, (char*)&key, NULL, NULL);
 * EVP_MD_CTX* evp_md_ctx = EVP_MD_CTX_new();
 * EVP_PKEY_CTX* evp_pkey_ctx;
 * EVP_DigestSignInit(evp_md_ctx, &evp_pkey_ctx, EVP_sha256(), engine, evp_pkey); // HMAC
 * EVP_DigestSignInit(evp_md_ctx, &evp_pkey_ctx, NULL, engine, evp_pkey); // CMAC
 * EVP_DigestSignUpdate(evp_md_ctx, data, data_length);
 * EVP_DigestSignFinal(evp_md_ctx, mac, &mac_length);
 * EVP_MD_CTX_free(evp_md_ctx);
 * EVP_PKEY_free(evp_pkey);
 * sa_engine_free(engine);
 * ```
 *
 * Encryption/Decryption (AES, CHACHA20)
 * -------------------------------------
 * ```
 * sa_key key = // Load key into SecApi 3;
 * ENGINE* engine = sa_get_engine();
 * EVP_CIPHER_CTX* evp_cipher_ctx = EVP_CIPHER_CTX_new();
 * EVP_CipherInit_ex(evp_cipher_ctx, EVP_aes_128_cbc(), engine, (const unsigned char*)&key, iv, 1); // 1=enc, 0=dec
 * EVP_CipherUpdate(evp_cipher_ctx, encrypted_data, &length, data, data_length);
 * EVP_CipherFinal(evp_cipher_ctx, encrypted_data + total_length, &length);
 * EVP_CIPHER_CTX_free(evp_cipher_ctx);
 * sa_engine_free(engine);
 * ```
 */

#ifndef SA_ENGINE_H
#define SA_ENGINE_H

#include <openssl/engine.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include "sa.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The return value indiciating a function is NOT SUPPORTED.
 */
#define OPENSSL_NOT_SUPPORTED (-2)

/**
 * Returns the SecApi3 engine and initializes it if it hasn't been created.
 *
 * @return a new ENGINE if successful or NULL if not.
 */
ENGINE* sa_get_engine();

/**
 * Releases the engine.
 *
 * @param[in] engine the engine to release.
 */
void sa_engine_free(ENGINE* engine);

#ifdef __cplusplus
}
#endif

#endif
#endif //SA_ENGINE_H
