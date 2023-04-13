/**
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

#ifndef SA_ENGINE_INTERNAL_H
#define SA_ENGINE_INTERNAL_H

#include "sa_engine.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000

#include "sa.h"
#include "sa_public_key.h"
#include <openssl/engine.h>
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000
#if defined(__GNUC__)
#define ossl_unused __attribute__((unused))
#else
#define ossl_unused
#endif
#endif

#define EVP_PKEY_SYM ((int) 0x83655100)
#define EVP_PKEY_SYM_NAME "SecApi 3 Symmetric"

extern mtx_t engine_mutex;

#define MAX_KEY_DATA_LEN 512

typedef struct {
    uint8_t data[MAX_KEY_DATA_LEN];
    int type;
    sa_key private_key;
    sa_header header;
} pkey_data;

/**
 * Returns a cipher for the SecApi3 Engine as requested by nid. If the ciphers parameter is NULL, returns the list of
 * nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] cipher the cipher referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if cipher is NULL.
 * @param[in] nid the nid for which to return the cipher.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_ciphers(
        ENGINE* engine,
        const EVP_CIPHER** cipher,
        const int** nids,
        int nid);

/**
 * Frees all of the created ciphers.
 */
void sa_free_engine_ciphers();

/**
 * Returns a digest for the SecApi3 Engine as requested by nid. If the digests parameter is NULL, returns the list of
 * nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] evp_md the digest referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if evp_md is NULL.
 * @param[in] nid the nid for which to return the digest.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_digests(
        ENGINE* engine,
        const EVP_MD** evp_md,
        const int** nids,
        int nid);

/**
 * Frees all of the created digests.
 */
void sa_free_engine_digests();

/**
 * Returns a pkey method for the SecApi3 Engine as requested by nid. If the method parameter is NULL, returns the list
 * of nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] method the pkey method referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if method is NULL.
 * @param[in] nid the nid for which to return the pkey method.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_pkey_methods(
        ENGINE* engine,
        EVP_PKEY_METHOD** method,
        const int** nids,
        int nid);

/**
 * Loads a private key from the SecApi 3 engine.
 *
 * @param[in] engine the engine instance.
 * @param[in] key_id the key ID. The value passed in should be a pointer to a sa_key.
 * @param[in] ui_method unused.
 * @param[in] callback_data unused.
 * @return the SecApi 3 engine private key.
 */
EVP_PKEY* sa_load_engine_private_pkey(
        ENGINE* engine,
        const char* key_id,
        UI_METHOD* ui_method,
        void* callback_data);

/**
 * Returns a ASN.1 method for the SecApi3 Engine as requested by nid. If the method parameter is NULL, returns the list
 * of nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] method the ASN.1 method referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if method is NULL.
 * @param[in] nid the nid for which to return the pkey method.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_pkey_asn1_meths(
        ENGINE* engine,
        EVP_PKEY_ASN1_METHOD** method,
        const int** nids,
        int nid);

/**
 * Initializes the ex_data index for EVP_PKEY.
 *
 * @return the ex_data index for EVP_PKEY
 */
int sa_get_ex_data_index();

/**
 * Retrieves the pkey_data.
 *
 * @param[in] evp_pkey the key to retrieve the pkey_data from.
 * @return the pkey_data retrieved from the key.
 */
const pkey_data* sa_get_pkey_data(EVP_PKEY* evp_pkey);

/**
 * Set the pkey_data.
 *
 * @param[in/out] evp_pkey the key to set the pkey_data on.
 * @param[in] data the pkey_data to set on the key.
 * @return 1 if successful and 0 if not.
 */
int sa_set_pkey_data(
        EVP_PKEY** evp_pkey,
        const pkey_data* data);

#ifdef __cplusplus
}
#endif

#endif
#endif //SA_ENGINE_INTERNAL_H
