/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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
#include "stored_key_internal.h"
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER >= 0X10100000
static EVP_PKEY* rsa_import_pkcs8(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL pkcs8");
        return NULL;
    }

    const unsigned char* in_bytes = (const unsigned char*) in;
    EVP_PKEY* evp_pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &in_bytes, (long) in_length);
    if (evp_pkey == NULL) {
        ERROR("d2i_PrivateKey failed");
    }

    return evp_pkey;
}

size_t rsa_validate_pkcs8(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    EVP_PKEY* evp_pkey = rsa_import_pkcs8(in, in_length);
    if (evp_pkey == NULL) {
        ERROR("rsa_import_pkcs8 failed");
        return 0;
    }

    size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
    EVP_PKEY_free(evp_pkey);
    return key_size;
}

#else
static RSA* rsa_import_pkcs8(
        const void* in,
        size_t in_length) {

    const unsigned char* in_bytes = (const unsigned char*) in;
    EVP_PKEY* evp_pkey = NULL;
    RSA* rsa_key = NULL;
    do {
        if (in == NULL) {
            ERROR("NULL pkcs8");
            break;
        }

        evp_pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &in_bytes, (long) in_length);
        if (evp_pkey == NULL) {
            ERROR("d2i_PrivateKey failed");
            break;
        }

        rsa_key = EVP_PKEY_get1_RSA(evp_pkey);
        if (rsa_key == NULL) {
            ERROR("EVP_PKEY_get1_RSA failed");
            break;
        }
    } while (false);

    EVP_PKEY_free(evp_pkey);

    return rsa_key;
}

size_t rsa_validate_pkcs8(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    RSA* rsa_key = rsa_import_pkcs8(in, in_length);
    if (rsa_key == NULL) {
        ERROR("rsa_import_pkcs8 failed");
        return 0;
    }

    size_t key_size = RSA_size(rsa_key);
    RSA_free(rsa_key);
    return key_size;
}
#endif

bool rsa_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    bool status = false;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY* evp_pkey = NULL;
#else
    RSA* rsa = NULL;
#endif
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        evp_pkey = rsa_import_pkcs8(key, key_length);
        int required_length = i2d_PublicKey(evp_pkey, NULL);
        if (required_length <= 0) {
            ERROR("i2d_PublicKey failed");
            break;
        }

        if (out == NULL) {
            *out_length = required_length;
            status = true;
            break;
        }

        if (*out_length < (size_t) required_length) {
            ERROR("Bad out_length");
            break;
        }

        unsigned char* buf = (uint8_t*) out;
        int written = i2d_PublicKey(evp_pkey, &buf);
        if (written <= 0) {
            ERROR("i2d_PublicKey failed");
            break;
        }

        *out_length = written;
#else
        rsa = rsa_import_pkcs8(key, key_length);
        int required_length = i2d_RSAPublicKey(rsa, NULL);
        if (required_length <= 0) {
            ERROR("i2d_RSAPublicKey failed");
            break;
        }

        if (out == NULL) {
            *out_length = required_length;
            status = true;
            break;
        }

        if (*out_length < (size_t) required_length) {
            ERROR("Bad out_length");
            break;
        }

        unsigned char* buf = (uint8_t*) out;
        int written = i2d_RSAPublicKey(rsa, &buf);
        if (written <= 0) {
            ERROR("i2d_RSAPublicKey failed");
            break;
        }

        *out_length = written;
#endif
        status = true;
    } while (false);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY_free(evp_pkey);
#else
    RSA_free(rsa);
#endif
    return status;
}

sa_status rsa_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key) {

    return SA_STATUS_OK;
}

bool rsa_decrypt_pkcs1v15(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    bool status = false;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
#else
    RSA* rsa_key = NULL;
#endif
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        evp_pkey = rsa_import_pkcs8(key, key_length);
        if (evp_pkey == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Bad out_length");
            break;
        }

        if (in_length != key_size) {
            ERROR("Bad in_length");
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
            ERROR("EVP_PKEY_decrypt failed");
            break;
        }

#else
        rsa_key = rsa_import_pkcs8(key, key_length);
        if (rsa_key == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        if (*out_length < (size_t) RSA_size(rsa_key)) {
            ERROR("Bad out_length");
            break;
        }

        if (in_length != (size_t) RSA_size(rsa_key)) {
            ERROR("Bad in_length");
            break;
        }

        int rsa_length = RSA_private_decrypt((int) in_length, in, out, rsa_key, RSA_PKCS1_PADDING);
        if (rsa_length < 0) {
            ERROR("RSA_private_decrypt failed");
            break;
        }

        *out_length = rsa_length;
#endif
        status = true;
    } while (false);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
#else
    RSA_free(rsa_key);
#endif
    return status;
}

bool rsa_decrypt_oaep(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    bool status = false;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
#else
    RSA* rsa_key = NULL;
#endif
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        evp_pkey = rsa_import_pkcs8(key, key_length);
        if (evp_pkey == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Bad out_length");
            break;
        }

        if (in_length != key_size) {
            ERROR("Bad in_length");
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

        if (EVP_PKEY_decrypt(evp_pkey_ctx, out, out_length, in, in_length) != 1) {
            ERROR("EVP_PKEY_decrypt failed");
            break;
        }

#else
        rsa_key = rsa_import_pkcs8(key, key_length);
        if (rsa_key == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        if (*out_length < (size_t) RSA_size(rsa_key)) {
            ERROR("Bad out_length");
            break;
        }

        if (in_length != (size_t) RSA_size(rsa_key)) {
            ERROR("Bad in_length");
            break;
        }

        int rsa_length = RSA_private_decrypt((int) in_length, in, out, rsa_key, RSA_PKCS1_OAEP_PADDING);
        if (rsa_length < 0) {
            ERROR("RSA_private_decrypt failed");
            break;
        }

        *out_length = rsa_length;
#endif
        status = true;
    } while (false);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
#else
    RSA_free(rsa_key);
#endif
    return status;
}

bool rsa_sign_pkcs1v15(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return false;
    }

    bool status = false;
    EVP_MD_CTX* evp_md_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    RSA* rsa_key = NULL;
#endif
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        evp_pkey = rsa_import_pkcs8(key, key_length);
        if (evp_pkey == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Bad out_length");
            break;
        }

#else
        rsa_key = rsa_import_pkcs8(key, key_length);
        if (rsa_key == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        if (*out_length < (size_t) RSA_size(rsa_key)) {
            ERROR("Bad out_length");
            break;
        }

        evp_pkey = EVP_PKEY_new();
        if (evp_pkey == NULL) {
            ERROR("EVP_PKEY_new failed");
            break;
        }

        if (EVP_PKEY_set1_RSA(evp_pkey, rsa_key) != 1) {
            ERROR("EVP_PKEY_set1_RSA failed");
            break;
        }
#endif
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

        status = true;
    } while (false);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    RSA_free(rsa_key);
#endif
    EVP_MD_CTX_destroy(evp_md_ctx);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return status;
}

bool rsa_sign_pss(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        size_t salt_length,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return false;
    }

    bool status = false;
    EVP_MD_CTX* evp_md_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    RSA* rsa_key = NULL;
#endif
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        evp_pkey = rsa_import_pkcs8(key, key_length);
        if (evp_pkey == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        size_t key_size = EVP_PKEY_bits(evp_pkey) / 8;
        if (*out_length < key_size) {
            ERROR("Bad out_length");
            break;
        }

#else
        rsa_key = rsa_import_pkcs8(key, key_length);
        if (rsa_key == NULL) {
            ERROR("rsa_import_pkcs8 failed");
            break;
        }

        if (*out_length < (size_t) RSA_size(rsa_key)) {
            ERROR("Bad out_length");
            break;
        }

        evp_pkey = EVP_PKEY_new();
        if (evp_pkey == NULL) {
            ERROR("EVP_PKEY_new failed");
            break;
        }

        if (EVP_PKEY_set1_RSA(evp_pkey, rsa_key) != 1) {
            ERROR("EVP_PKEY_set1_RSA failed");
            break;
        }
#endif
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

        status = true;
    } while (false);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    RSA_free(rsa_key);
#endif
    EVP_MD_CTX_destroy(evp_md_ctx);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return status;
}
