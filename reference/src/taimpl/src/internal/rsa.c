/**
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

#include "rsa.h" // NOLINT
#include "digest_internal.h"
#include "log.h"
#include "pkcs8.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include <memory.h>
#include <openssl/pem.h>

size_t rsa_validate_private(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    EVP_PKEY* evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_RSA, in, in_length);
    if (evp_pkey == NULL) {
        ERROR("evp_pkey_from_pkcs8 failed");
        return 0;
    }

    size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
    EVP_PKEY_free(evp_pkey);
    return key_size;
}

sa_status rsa_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_PKEY* evp_pkey = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_RSA, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        int length = i2d_PUBKEY(evp_pkey, NULL);
        if (length <= 0) {
            ERROR("i2d_PUBKEY failed");
            break;
        }

        if (out == NULL) {
            *out_length = length;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < (size_t) length) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        uint8_t* p_out = out;
        length = i2d_PUBKEY(evp_pkey, &p_out);
        if (length <= 0) {
            ERROR("i2d_PUBKEY failed");
            break;
        }

        *out_length = length;
        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    return status;
}

sa_status rsa_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        void* parameters,
        const stored_key_t* stored_key) {

    if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
        if (parameters == NULL) {
            ERROR("NULL parameters");
            return SA_STATUS_NULL_PARAMETER;
        }
    }

    return SA_STATUS_OK;
}

sa_status rsa_decrypt_pkcs1v15(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_RSA, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        if (in_length != key_size) {
            ERROR("Invalid in_length");
            break;
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
        if (evp_pkey_ctx == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        if (EVP_PKEY_decrypt_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_decrypt_init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PADDING) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
            break;
        }

        if (EVP_PKEY_decrypt(evp_pkey_ctx, out, out_length, in, in_length) != 1) {
            status = SA_STATUS_VERIFICATION_FAILED;
            ERROR("EVP_PKEY_decrypt failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    return status;
}

sa_status rsa_decrypt_oaep(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        sa_digest_algorithm digest_algorithm,
        sa_digest_algorithm mgf1_digest_algorithm,
        const void* label,
        size_t label_length,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_RSA, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        if (in_length != key_size) {
            ERROR("Invalid in_length");
            break;
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
        if (evp_pkey_ctx == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        if (EVP_PKEY_decrypt_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_decrypt_init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(evp_pkey_ctx, digest_mechanism(digest_algorithm)) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_oaep_md failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ctx, digest_mechanism(mgf1_digest_algorithm)) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
            break;
        }

        if (label != NULL && label_length > 0) {
            uint8_t* new_label = memory_secure_alloc(label_length);
            if (new_label == NULL) {
                ERROR("memory_secure_alloc failed");
                break;
            }

            memcpy(new_label, label, label_length);
            if (EVP_PKEY_CTX_set0_rsa_oaep_label(evp_pkey_ctx, new_label, (int) label_length) != 1) {
                memory_secure_free(new_label);
                ERROR("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
                break;
            }
        }

        if (EVP_PKEY_decrypt(evp_pkey_ctx, out, out_length, in, in_length) != 1) {
            ERROR("EVP_PKEY_decrypt failed");
            status = SA_STATUS_VERIFICATION_FAILED;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    return status;
}

sa_status rsa_sign_pkcs1v15(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_MD_CTX* evp_md_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_RSA, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        const EVP_MD* evp_md = digest_mechanism(digest_algorithm);
        if (precomputed_digest) {
            evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
            if (evp_pkey_ctx == NULL) {
                ERROR("EVP_PKEY_CTX_new failed");
                break;
            }

            if (EVP_PKEY_sign_init(evp_pkey_ctx) != 1) {
                ERROR("EVP_PKEY_sign_init failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PADDING) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_signature_md failed");
                break;
            }

            if (EVP_PKEY_sign(evp_pkey_ctx, out, out_length, in, in_length) != 1) {
                ERROR("EVP_PKEY_sign failed");
                break;
            }
        } else {
            evp_md_ctx = EVP_MD_CTX_create();
            if (evp_md_ctx == NULL) {
                ERROR("EVP_MD_CTX_create failed");
                break;
            }

            // evp_md_pkey_ctx freed by EVP_MD_CTX_destroy.
            EVP_PKEY_CTX* evp_md_pkey_ctx = NULL;
            if (EVP_DigestSignInit(evp_md_ctx, &evp_md_pkey_ctx, evp_md, NULL, evp_pkey) != 1) {
                ERROR("EVP_DigestSignInit failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_padding(evp_md_pkey_ctx, RSA_PKCS1_PADDING) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (EVP_DigestSignUpdate(evp_md_ctx, in, in_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }

            if (EVP_DigestSignFinal(evp_md_ctx, out, out_length) != 1) {
                ERROR("EVP_DigestSignFinal failed");
                break;
            }
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_MD_CTX_destroy(evp_md_ctx);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return status;
}

sa_status rsa_sign_pss(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        sa_digest_algorithm mgf1_digest_algorithm,
        size_t salt_length,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_OK;
    EVP_MD_CTX* evp_md_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(EVP_PKEY_RSA, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            break;
        }

        const EVP_MD* evp_md = digest_mechanism(digest_algorithm);
        if (precomputed_digest) {
            evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
            if (evp_pkey_ctx == NULL) {
                ERROR("EVP_PKEY_CTX_new failed");
                break;
            }

            if (EVP_PKEY_sign_init(evp_pkey_ctx) != 1) {
                ERROR("EVP_PKEY_sign_init failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ctx, digest_mechanism(mgf1_digest_algorithm)) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ctx, (int) salt_length) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_pss_saltlen failed");
                break;
            }

            if (EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_signature_md failed");
                break;
            }

            if (EVP_PKEY_sign(evp_pkey_ctx, out, out_length, in, in_length) != 1) {
                ERROR("EVP_PKEY_sign failed");
                break;
            }
        } else {
            evp_md_ctx = EVP_MD_CTX_create();
            if (evp_md_ctx == NULL) {
                ERROR("EVP_MD_CTX_create failed");
                break;
            }

            // evp_md_pkey_ctx freed by EVP_MD_CTX_destroy.
            EVP_PKEY_CTX* evp_md_pkey_ctx = NULL;
            if (EVP_DigestSignInit(evp_md_ctx, &evp_md_pkey_ctx, evp_md, NULL, evp_pkey) != 1) {
                ERROR("EVP_DigestSignInit failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_padding(evp_md_pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp_md_pkey_ctx, digest_mechanism(mgf1_digest_algorithm)) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_md_pkey_ctx, (int) salt_length) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_pss_saltlen failed");
                break;
            }

            if (EVP_DigestSignUpdate(evp_md_ctx, in, in_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }

            if (EVP_DigestSignFinal(evp_md_ctx, out, out_length) != 1) {
                ERROR("EVP_DigestSignFinal failed");
                break;
            }
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_MD_CTX_destroy(evp_md_ctx);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return status;
}

sa_status rsa_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_generate_parameters_rsa* parameters) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* key = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    size_t key_length = 0;
    do {

        evp_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (evp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new_id failed");
            break;
        }

        if (EVP_PKEY_keygen_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_keygen_init failed");
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(evp_pkey_ctx, (int) parameters->modulus_length * 8) != 1) {
            ERROR("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
            break;
        }

        if (EVP_PKEY_keygen(evp_pkey_ctx, &evp_pkey) != 1) {
            ERROR("EVP_PKEY_keygen failed");
            break;
        }

        if (!evp_pkey_to_pkcs8(NULL, &key_length, evp_pkey)) {
            ERROR("evp_pkey_to_pkcs8 failed");
            break;
        }

        key = memory_secure_alloc(key_length);
        if (key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!evp_pkey_to_pkcs8(key, &key_length, evp_pkey)) {
            ERROR("evp_pkey_to_pkcs8 failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(type_parameters));
        status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_RSA, &type_parameters,
                parameters->modulus_length, key, key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (key != NULL) {
        memory_memset_unoptimizable(key, 0, key_length);
        memory_secure_free(key);
    }

    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(evp_pkey);
    return status;
}
