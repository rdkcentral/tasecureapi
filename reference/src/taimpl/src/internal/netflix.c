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

#include "netflix.h" // NOLINT
#include "common.h"
#include "digest.h"
#include "hmac_internal.h"
#include "log.h"
#include "porting/memory.h"
#include "stored_key_internal.h"

sa_status kdf_netflix_wrapping(
        stored_key_t** stored_key_wrap,
        const sa_rights* rights_wrap,
        const sa_rights* rights_parent,
        const stored_key_t* stored_key_enc,
        const stored_key_t* stored_key_hmac) {

    if (stored_key_wrap == NULL) {
        ERROR("NULL stored_key_wrap");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights_wrap == NULL) {
        ERROR("NULL rights_wrap");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights_parent == NULL) {
        ERROR("NULL rights_parent");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_enc == NULL) {
        ERROR("NULL stored_key_enc");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_hmac == NULL) {
        ERROR("NULL stored_key_hmac");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* enc_key = stored_key_get_key(stored_key_enc);
    if (enc_key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t enc_length = stored_key_get_length(stored_key_enc);
    if (enc_length != SYM_128_KEY_SIZE) {
        ERROR("Invalid enc_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    const void* hmac_key = stored_key_get_key(stored_key_hmac);
    if (hmac_key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t hmac_length = stored_key_get_length(stored_key_hmac);
    if (hmac_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid hmac_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    bool status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* temp_key = NULL;
    size_t temp_key_length = SYM_256_KEY_SIZE;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SHA256_DIGEST_LENGTH;
    do {
        // Salt values are from https://github.com/Netflix/msl/
        // Copyright 2014 Netflix, Inc.
        // Licensed under the Apache License, Version 2.0
        static const uint8_t salt[] = {
                0x02, 0x76, 0x17, 0x98, 0x4f, 0x62, 0x27, 0x53,
                0x9a, 0x63, 0x0b, 0x89, 0x7c, 0x01, 0x7d, 0x69};

        temp_key = memory_secure_alloc(temp_key_length);
        if (temp_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!hmac_internal(temp_key, &temp_key_length, SA_DIGEST_ALGORITHM_SHA256, enc_key, enc_length, hmac_key,
                    hmac_length, NULL, 0, salt, sizeof(salt))) {
            ERROR("hmac_internal failed");
            break;
        }

        // Info values are from https://github.com/Netflix/msl/
        // Copyright 2014 Netflix, Inc.
        // Licensed under the Apache License, Version 2.0
        static const uint8_t info[] = {
                0x80, 0x9f, 0x82, 0xa7, 0xad, 0xdf, 0x54, 0x8d,
                0x3e, 0xa9, 0xdd, 0x06, 0x7f, 0xf9, 0xbb, 0x91};

        if (!hmac_internal(wrapping_key, &wrapping_key_length, SA_DIGEST_ALGORITHM_SHA256, info, sizeof(info),
                    NULL, 0, NULL, 0, temp_key, temp_key_length)) {
            ERROR("hmac_internal failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_wrap, rights_wrap, rights_parent, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                    AES_BLOCK_SIZE, wrapping_key, AES_BLOCK_SIZE);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (temp_key != NULL) {
        memory_memset_unoptimizable(temp_key, 0, temp_key_length);
        memory_secure_free(temp_key);
    }

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

sa_status kdf_netflix_shared_secret(
        stored_key_t** stored_key_enc,
        const sa_rights* rights_enc,
        stored_key_t** stored_key_hmac,
        const sa_rights* rights_hmac,
        const stored_key_t* stored_key_in,
        const stored_key_t* stored_key_shared_secret) {

    if (stored_key_enc == NULL) {
        ERROR("NULL stored_key_enc");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights_enc == NULL) {
        ERROR("NULL rights_enc");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_hmac == NULL) {
        ERROR("NULL stored_key_hmac");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights_hmac == NULL) {
        ERROR("NULL rights_hmac");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_in == NULL) {
        ERROR("NULL stored_key_in");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* in_key = stored_key_get_key(stored_key_in);
    if (in_key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* in_key_header = stored_key_get_header(stored_key_in);
    if (in_key_header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t in_key_length = stored_key_get_length(stored_key_in);
    if (in_key_length != SYM_128_KEY_SIZE) {
        ERROR("Invalid in_key_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (stored_key_shared_secret == NULL) {
        ERROR("NULL stored_key_shared_secret");
        return SA_STATUS_NULL_PARAMETER;
    }

    bool status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* digest_bytes = NULL;
    size_t digest_bytes_length = SHA384_DIGEST_LENGTH;
    uint8_t* key_bytes = NULL;
    size_t key_bytes_length = SHA384_DIGEST_LENGTH;
    do {
        digest_bytes = memory_secure_alloc(digest_bytes_length);
        if (digest_bytes == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        key_bytes = memory_secure_alloc(key_bytes_length);
        if (key_bytes == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!digest_sha(digest_bytes, &digest_bytes_length, SA_DIGEST_ALGORITHM_SHA384, in_key, in_key_length, NULL, 0,
                    NULL, 0)) {
            ERROR("digest_sha failed");
            break;
        }

        /*
            Per MSL spec:

            Since the computed shared secret is a numeric value (typically a BigInteger) it
            must be converted into a byte array when computing the HMAC-SHA384. The byte array
            will be the minimum number of bytes required for the two's complement representation
            in big-endian byte-order (the most significant byte is first) including at least one
            sign bit, with exactly one zero byte in the zeroth element. As a result, a shared
            secret value of zero will be represented by an array of length one containing a single
            byte with a value of zero. This representation is not outright compatible with the Java
            BigInteger.toByteArray() function and BigInteger(byte[]) constructor, but close.

            So, essentially, if the first byte of the shared secret is not zero, we prepend
            a zero byte.
        */

        const void* shared_secret = stored_key_get_key(stored_key_shared_secret);
        if (shared_secret == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t shared_secret_length = stored_key_get_length(stored_key_shared_secret);
        if (shared_secret_length == 0) {
            ERROR("stored_key_get_length failed");
            break;
        }

        const uint8_t zero = 0;
        bool pre_zero = (((const uint8_t*) shared_secret)[0] != 0);
        if (!hmac_internal(key_bytes, &key_bytes_length, SA_DIGEST_ALGORITHM_SHA384, &zero, pre_zero ? 1 : 0,
                    shared_secret, shared_secret_length, NULL, 0, digest_bytes, digest_bytes_length)) {
            ERROR("hmac_internal failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_enc, rights_enc, &in_key_header->rights, SA_KEY_TYPE_SYMMETRIC,
                    &type_parameters, SYM_128_KEY_SIZE, key_bytes, SYM_128_KEY_SIZE);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }

        status = stored_key_create(stored_key_hmac, rights_hmac, &in_key_header->rights, SA_KEY_TYPE_SYMMETRIC,
                    &type_parameters, SYM_256_KEY_SIZE, key_bytes + SYM_128_KEY_SIZE, SHA256_DIGEST_LENGTH);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (digest_bytes != NULL) {
        memory_memset_unoptimizable(digest_bytes, 0, digest_bytes_length);
        memory_secure_free(digest_bytes);
    }

    if (key_bytes != NULL) {
        memory_memset_unoptimizable(key_bytes, 0, key_bytes_length);
        memory_secure_free(key_bytes);
    }

    return status;
}
