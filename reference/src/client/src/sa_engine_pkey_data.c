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

#include "sa_engine_internal.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include "log.h"
#include <memory.h>

#define EVP_PKEY_SECAPI3 0x53415F33

#if defined(__linux__)
#include <malloc.h>
static size_t memory_size(const void* ptr, ossl_unused size_t default_size) {
    return malloc_usable_size((void*) ptr);
}
#elif defined(__APPLE__)
// https://www.unix.com/man-page/osx/3/malloc_size/
#include <malloc/malloc.h>
static int memory_size(void* ptr, size_t default_size) {
    return malloc_size(ptr);
}
#elif defined(_WIN32)
// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/msize
#include <malloc.h>
static int memory_size(void* ptr, size_t default_size) {
    return _msize((void*) ptr);
}
#else
static int memory_size(void* ptr, size_t default_size) {
    return default_size;
}
#endif

// Do nothing.
int sa_get_ex_data_index() {
    return 1;
}

const pkey_data* sa_get_pkey_data(EVP_PKEY* evp_pkey) {
    pkey_data* data = EVP_PKEY_get0(evp_pkey);
    if (data == NULL || data->type != EVP_PKEY_SECAPI3) {
        ERROR("EVP_PKEY_get0 failed");
        data = NULL;
    }

    return data;
}

// OpenSSL 1.0.2 and 1.1.1 don't have ex_data for an EVP_PKEY. So we have to make our own by getting the original
// allocated key, reallocating a larger space with our extended data, and putting back the new reallocated key.
int sa_set_pkey_data(
        EVP_PKEY** evp_pkey,
        const pkey_data* data) {

    int result = 0;
    int type = EVP_PKEY_id(*evp_pkey);
    void* temp_key = NULL;
    switch (type) {
        case EVP_PKEY_RSA:
            temp_key = EVP_PKEY_get1_RSA(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get1_RSA failed");
                break;
            }

            // Free the RSA evp_pkey to decrement the RSA reference count and create a new one to use.
            EVP_PKEY_free(*evp_pkey);
            *evp_pkey = EVP_PKEY_new();
            break;

        case EVP_PKEY_EC:
            temp_key = EVP_PKEY_get1_EC_KEY(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get1_EC_KEY failed");
                break;
            }

            // Free the EC evp_pkey to decrement the EC reference count and create a new one to use.
            EVP_PKEY_free(*evp_pkey);
            *evp_pkey = EVP_PKEY_new();
            break;

        case EVP_PKEY_DH:
            temp_key = EVP_PKEY_get1_DH(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get1_DH failed");
                break;
            }

            // Free the DH evp_pkey to decrement the DH reference count and create a new one to use.
            EVP_PKEY_free(*evp_pkey);
            *evp_pkey = EVP_PKEY_new();
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
        case EVP_PKEY_X25519:
        case EVP_PKEY_X448:
#endif
        case EVP_PKEY_SYM:
            temp_key = EVP_PKEY_get0(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get0 failed");
                break;
            }

            // Don't free a ED or X curve or SYM evp_pkey, it can be reused.
            break;

        default:
            break;
    }

    if (temp_key != NULL) {
        if (type != EVP_PKEY_SYM) {
            pkey_data* new_data = NULL;
            do {
                new_data = OPENSSL_malloc(sizeof(pkey_data));
                if (new_data == NULL) {
                    ERROR("OPENSSL_malloc failed");
                    break;
                }

                memset(new_data, 0, sizeof(pkey_data));

                // Copy the original key data structure into another larger data structure.
                if (temp_key != NULL) {
                    size_t temp_key_length = memory_size(temp_key, MAX_KEY_DATA_LEN);
                    memcpy(new_data->data, temp_key, temp_key_length);
                }

                // Free the original data structure (unless it's an ED or X key), but don't free any of it's contents
                // which are now pointed to by the key_data.
                if (type == EVP_PKEY_RSA || type == EVP_PKEY_EC || type == EVP_PKEY_DH)
                    OPENSSL_free(temp_key);

                new_data->type = EVP_PKEY_SECAPI3;
                new_data->private_key = data->private_key;
                memcpy(&new_data->header, &data->header, sizeof(sa_header));
                if (EVP_PKEY_assign(*evp_pkey, type, new_data) != 1) {
                    ERROR("EVP_PKEY_assign failed");
                    break;
                }

                // Assigned to evp_pkey;
                new_data = NULL;
                result = 1;
            } while (false);

            if (new_data != NULL)
                OPENSSL_free(new_data);
        } else {
            pkey_data* new_data = temp_key;
            new_data->type = EVP_PKEY_SECAPI3;
            result = 1;
        }
    }

    return result;
}

#endif
