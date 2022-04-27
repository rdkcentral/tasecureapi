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

#include "digest.h" // NOLINT
#include "common.h"
#include "digest_internal.h"
#include "log.h"
#include "stored_key_internal.h"
#include <openssl/evp.h>

const EVP_MD* digest_mechanism(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return EVP_sha1();

        case SA_DIGEST_ALGORITHM_SHA256:
            return EVP_sha256();

        case SA_DIGEST_ALGORITHM_SHA384:
            return EVP_sha384();

        case SA_DIGEST_ALGORITHM_SHA512:
            return EVP_sha512();

        default:
            ERROR("Unknown digest encountered");
            return NULL;
    }
}

const char* digest_string(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return "sha1";

        case SA_DIGEST_ALGORITHM_SHA256:
            return "sha256";

        case SA_DIGEST_ALGORITHM_SHA384:
            return "sha384";

        case SA_DIGEST_ALGORITHM_SHA512:
            return "sha512";

        default:
            ERROR("Unknown digest encountered");
            return NULL;
    }
}

size_t digest_length(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return SHA1_DIGEST_LENGTH;

        case SA_DIGEST_ALGORITHM_SHA256:
            return SHA256_DIGEST_LENGTH;

        case SA_DIGEST_ALGORITHM_SHA384:
            return SHA384_DIGEST_LENGTH;

        case SA_DIGEST_ALGORITHM_SHA512:
            return SHA512_DIGEST_LENGTH;

        default:
            ERROR("Unknown digest encountered");
            break;
    }

    return (size_t) -1;
}

bool digest_sha(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    size_t required_length = digest_length(digest_algorithm);
    if (out == NULL) {
        *out_length = required_length;
        return required_length != (size_t) -1;
    }

    if (*out_length < required_length) {
        ERROR("Bad out_length");
        return false;
    }
    *out_length = required_length;

    if (in1 == NULL && in1_length > 0) {
        ERROR("NULL in1");
        return false;
    }

    if (in2 == NULL && in2_length > 0) {
        ERROR("NULL in2");
        return false;
    }

    if (in3 == NULL && in3_length > 0) {
        ERROR("NULL in3");
        return false;
    }

    bool status = false;
    EVP_MD_CTX* context = NULL;
    do {
        context = EVP_MD_CTX_create();
        if (context == NULL) {
            ERROR("EVP_MD_CTX_create failed");
            break;
        }

        const EVP_MD* md = digest_mechanism(digest_algorithm);
        if (md == NULL) {
            ERROR("digest_mechanism failed");
            break;
        }

        if (EVP_DigestInit_ex(context, md, NULL) != 1) {
            ERROR("EVP_DigestInit_ex failed");
            break;
        }

        if (in1_length > 0) {
            if (EVP_DigestUpdate(context, in1, in1_length) != 1) {
                ERROR("EVP_DigestUpdate failed");
                break;
            }
        }

        if (in2_length > 0) {
            if (EVP_DigestUpdate(context, in2, in2_length) != 1) {
                ERROR("EVP_DigestUpdate failed");
                break;
            }
        }

        if (in3_length > 0) {
            if (EVP_DigestUpdate(context, in3, in3_length) != 1) {
                ERROR("EVP_DigestUpdate failed");
                break;
            }
        }

        unsigned int length = required_length;
        if (EVP_DigestFinal_ex(context, (unsigned char*) out, &length) != 1) {
            ERROR("EVP_DigestFinal_ex failed");
            break;
        }

        status = true;
    } while (false);

    EVP_MD_CTX_destroy(context);
    return status;
}

bool digest_key(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    size_t required_length = digest_length(digest_algorithm);
    if (out == NULL) {
        *out_length = required_length;
        return required_length != (size_t) -1;
    }

    if (*out_length < required_length) {
        ERROR("Bad out_length");
        return false;
    }
    *out_length = required_length;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    bool status = false;
    EVP_MD_CTX* context = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);

        context = EVP_MD_CTX_create();
        if (context == NULL) {
            ERROR("EVP_MD_CTX_create failed");
            break;
        }

        const EVP_MD* md = digest_mechanism(digest_algorithm);
        if (md == NULL) {
            ERROR("digest_mechanism failed");
            break;
        }

        if (EVP_DigestInit_ex(context, md, NULL) != 1) {
            ERROR("EVP_DigestInit_ex failed");
            break;
        }

        if (EVP_DigestUpdate(context, key, key_length) != 1) {
            ERROR("EVP_DigestUpdate failed");
            break;
        }

        unsigned int length = required_length;
        if (EVP_DigestFinal_ex(context, (unsigned char*) out, &length) != 1) {
            ERROR("EVP_DigestFinal_ex failed");
            break;
        }

        status = true;
    } while (false);

    EVP_MD_CTX_destroy(context);
    return status;
}
