/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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
#include "log.h"
#include <openssl/x509.h>
#include <stdint.h>

bool evp_pkey_to_pkcs8(
        void* out,
        size_t* out_length,
        EVP_PKEY* evp_pkey) {

    bool status = false;
    PKCS8_PRIV_KEY_INFO* pkcs8 = NULL;
    do {
        pkcs8 = EVP_PKEY2PKCS8(evp_pkey);
        if (pkcs8 == NULL)
            // Don't log.
            break;

        int length = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, NULL);
        if (length <= 0) {
            ERROR("i2d_PKCS8_PRIV_KEY_INFO failed");
            break;
        }

        if (out == NULL) {
            *out_length = length;
            status = true;
            break;
        }

        if (*out_length < (size_t) length) {
            ERROR("out_length too short");
            break;
        }

        uint8_t* p_out = out;
        length = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &p_out);
        if (length <= 0) {
            ERROR("i2d_PKCS8_PRIV_KEY_INFO failed");
            break;
        }

        *out_length = length;
        status = true;
    } while (false);

    PKCS8_PRIV_KEY_INFO_free(pkcs8);
    return status;
}

EVP_PKEY* evp_pkey_from_pkcs8(
        int type,
        const void* in,
        size_t in_length) {

    EVP_PKEY* evp_pkey = NULL;
    PKCS8_PRIV_KEY_INFO* pkcs8 = NULL;
    do {
        const uint8_t* p_in = in;
        pkcs8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p_in, (long) in_length);
        if (pkcs8 == NULL) {
            ERROR("d2i_PKCS8_PRIV_KEY_INFO failed");
            break;
        }

        evp_pkey = EVP_PKCS82PKEY(pkcs8);
        if (evp_pkey == NULL) {
            ERROR("EVP_PKCS82PKEY failed");
            break;
        }

        if (EVP_PKEY_id(evp_pkey) != type) {
            ERROR("wrong key type");
            EVP_PKEY_free(evp_pkey);
            evp_pkey = NULL;
            break;
        }
    } while (false);

    PKCS8_PRIV_KEY_INFO_free(pkcs8);
    return evp_pkey;
}
