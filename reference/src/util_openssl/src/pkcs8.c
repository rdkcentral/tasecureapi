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

#include "pkcs8.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>

bool evp_pkey_to_pkcs8(
        void* out,
        size_t* out_length,
        EVP_PKEY* evp_pkey) {
    
    if (out_length == NULL || evp_pkey == NULL) {
        return false;
    }

    PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(evp_pkey);
    if (p8inf == NULL) {
        return false;
    }

    unsigned char* der = NULL;
    int der_length = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &der);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    
    if (der_length <= 0 || der == NULL) {
        return false;
    }

    // If out is NULL, just return the required length
    if (out == NULL) {
        *out_length = (size_t)der_length;
        OPENSSL_free(der);
        return true;
    }

    // Check if the output buffer is large enough
    if (*out_length < (size_t)der_length) {
        OPENSSL_free(der);
        return false;
    }

    // Copy the DER-encoded data to the output buffer
    memcpy(out, der, (size_t)der_length);
    *out_length = (size_t)der_length;
    OPENSSL_free(der);
    
    return true;
}

EVP_PKEY* evp_pkey_from_pkcs8(
        int type,
        const void* in,
        size_t in_length) {
    
    if (in == NULL || in_length == 0) {
        return NULL;
    }

    const unsigned char* p = (const unsigned char*)in;
    PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)in_length);
    if (p8inf == NULL) {
        return NULL;
    }

    EVP_PKEY* evp_pkey = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    
    if (evp_pkey == NULL) {
        return NULL;
    }

    // Optionally verify the key type matches the expected type
    // type parameter can be EVP_PKEY_NONE to skip verification
    if (type != EVP_PKEY_NONE && EVP_PKEY_id(evp_pkey) != type) {
        EVP_PKEY_free(evp_pkey);
        return NULL;
    }

    return evp_pkey;
}
