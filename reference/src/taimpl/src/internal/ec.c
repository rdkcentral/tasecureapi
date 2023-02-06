/*
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

#include "ec.h" // NOLINT
#include "common.h"
#include "digest_util.h"
#include "log.h"
#include "pkcs8.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include <memory.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#define EC_KEY_SIZE(ec_group) (EC_GROUP_get_degree(ec_group) / 8 + (EC_GROUP_get_degree(ec_group) % 8 == 0 ? 0 : 1))
#define MAX_EC_SIGNATURE 256 // NOLINT

static inline bool is_pcurve(sa_elliptic_curve curve) {
    return curve == SA_ELLIPTIC_CURVE_NIST_P192 || curve == SA_ELLIPTIC_CURVE_NIST_P224 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P256 || curve == SA_ELLIPTIC_CURVE_NIST_P384 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P521;
}

static int ec_get_type(sa_elliptic_curve curve) {
    int type;
    if (is_pcurve(curve))
        type = EVP_PKEY_EC;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    else if (curve == SA_ELLIPTIC_CURVE_ED25519)
        type = EVP_PKEY_ED25519;
    else if (curve == SA_ELLIPTIC_CURVE_X25519)
        type = EVP_PKEY_X25519;
    else if (curve == SA_ELLIPTIC_CURVE_ED448)
        type = EVP_PKEY_ED448;
    else if (curve == SA_ELLIPTIC_CURVE_X448)
        type = EVP_PKEY_X448;
#endif
    else
        type = 0;

    return type;
}

static int ec_get_nid(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P192:
            return NID_X9_62_prime192v1;

        case SA_ELLIPTIC_CURVE_NIST_P224:
            return NID_secp224r1;

        case SA_ELLIPTIC_CURVE_NIST_P256:
            return NID_X9_62_prime256v1;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return NID_secp384r1;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return NID_secp521r1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        case SA_ELLIPTIC_CURVE_ED25519:
            return NID_ED25519;

        case SA_ELLIPTIC_CURVE_X25519:
            return NID_X25519;

        case SA_ELLIPTIC_CURVE_ED448:
            return NID_ED448;

        case SA_ELLIPTIC_CURVE_X448:
            return NID_X448;
#endif

        default:
            ERROR("Unknown EC curve encountered");
            return 0;
    }
}

size_t ec_key_size_from_curve(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P192:
            return EC_P192_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P224:
            return EC_P224_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P256:
            return EC_P256_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return EC_P384_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return EC_P521_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_ED25519:
        case SA_ELLIPTIC_CURVE_X25519:
            return EC_25519_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_ED448:
            return EC_ED448_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_X448:
            return EC_X448_KEY_SIZE;

        default:
            return 0;
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static const char* ec_get_name(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P192:
            return "prime192v1";

        case SA_ELLIPTIC_CURVE_NIST_P224:
            return "secp224r1";

        case SA_ELLIPTIC_CURVE_NIST_P256:
            return "prime256v1";

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return "secp384r1";

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return "secp521r1";

        case SA_ELLIPTIC_CURVE_ED25519:
            return "ED25519";

        case SA_ELLIPTIC_CURVE_X25519:
            return "X25519";

        case SA_ELLIPTIC_CURVE_ED448:
            return "ED448";

        case SA_ELLIPTIC_CURVE_X448:
            return "X448";

        default:
            ERROR("Unknown EC curve encountered");
            return 0;
    }
}
#endif

static EC_GROUP* ec_group_from_curve(sa_elliptic_curve curve) {
    EC_GROUP* ec_group = NULL;
    int type = ec_get_nid(curve);
    if (type == 0) {
        ERROR("ec_get_nid failed");
    } else {
        ec_group = EC_GROUP_new_by_curve_name(type);
        if (ec_group == NULL) {
            ERROR("EC_GROUP_new_by_curve_name failed");
        }
    }

    return ec_group;
}

static size_t export_point(
        uint8_t** out,
        const EC_GROUP* ec_group,
        EC_POINT* ec_point) {

    if (out == NULL) {
        ERROR("out is NULL");
        return 0;
    }

    if (ec_group == NULL) {
        ERROR("ec_group is NULL");
        return 0;
    }

    if (ec_point == NULL) {
        ERROR("ec_point is NULL");
        return 0;
    }

    size_t point_length = (size_t) EC_KEY_SIZE(ec_group) * 2;
    if (point_length == 0) {
        ERROR("ec_key_size_from_curve failed");
        return 0;
    }

    uint8_t buffer[point_length + 1];
    if (EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, buffer, point_length + 1,
                NULL) != point_length + 1) {
        ERROR("EC_POINT_point2oct failed");
        return 0;
    }

    if (buffer[0] != POINT_CONVERSION_UNCOMPRESSED) {
        ERROR("EC_POINT_point2oct failed");
        return 0;
    }

    size_t out_length = point_length;
    *out = memory_secure_alloc(out_length);
    if (*out == NULL) {
        ERROR("memory_secure_alloc failed");
        return 0;
    }

    memcpy(*out, &buffer[1], out_length);
    return out_length;
}

static bool bn_export(
        void* out,
        size_t out_length,
        const BIGNUM* bn) {
    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (bn == NULL) {
        ERROR("NULL bn");
        return false;
    }

    memory_memset_unoptimizable(out, 0, out_length);

    size_t written = BN_num_bytes(bn);

    if (written > out_length) {
        ERROR("Invalid out_length");
        return false;
    }

    uint8_t* out_bytes = (uint8_t*) out;
    BN_bn2bin(bn, out_bytes + out_length - written);

    return true;
}

size_t ec_validate_private(
        sa_elliptic_curve curve,
        const void* private,
        size_t private_length) {

    if (private == NULL) {
        ERROR("NULL private");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t result = 0;
    EVP_PKEY* evp_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY* ec_key = NULL;
    EC_GROUP* ec_group2 = NULL;
#endif
    do {
        evp_pkey = evp_pkey_from_pkcs8(ec_get_type(curve), private, private_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        // ED and X curves are checked in evp_pkey_from_pkcs8.
        if (is_pcurve(curve)) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
            char group_name[MAX_NAME_SIZE];
            size_t length = 0;
            if (EVP_PKEY_get_utf8_string_param(evp_pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name, MAX_NAME_SIZE,
                        &length) != 1) {
                ERROR("EVP_PKEY_get_utf8_string_param failed");
                break;
            }

            if (strcmp(group_name, ec_get_name(curve)) != 0) {
                ERROR("EC_GROUP_cmp failed");
                break;
            }

#else
            ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
            if (ec_key == NULL) {
                ERROR("EVP_PKEY_get1_EC_KEY failed");
                break;
            }

            const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
            if (ec_group == NULL) {
                ERROR("EC_KEY_get0_group failed");
                break;
            }

            ec_group2 = ec_group_from_curve(curve);
            if (EC_GROUP_cmp(ec_group, ec_group2, NULL) != 0) {
                ERROR("EC_GROUP_cmp failed");
                break;
            }
#endif
        }

        result = ec_key_size_from_curve(curve);
    } while (false);

    EVP_PKEY_free(evp_pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY_free(ec_key);
    EC_GROUP_free(ec_group2);
#endif

    return result;
}

sa_status ec_get_public(
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
        const uint8_t* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        evp_pkey = evp_pkey_from_pkcs8(ec_get_type(header->type_parameters.curve), key, key_length);
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

sa_status ec_verify_cipher(
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key) {

    DEBUG("ec_verify_cipher: mode %d, stored_key %p", cipher_mode, stored_key);

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (!is_pcurve(header->type_parameters.curve)) {
        ERROR("ED & X curves cannot be used for ECDSA");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    return SA_STATUS_OK;
}

sa_status ec_decrypt_elgamal(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_PKEY* evp_pkey = NULL;
    EC_GROUP* ec_group = NULL;
    uint8_t* buffer = NULL;
    EC_POINT* c1 = NULL;
    EC_POINT* c2 = NULL;
    EC_POINT* shared_secret = NULL;
    EC_POINT* message_point = NULL;
    BIGNUM* message_point_x = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        if (!is_pcurve(header->type_parameters.curve)) {
            ERROR("ED & X curves cannot be used for El Gamal");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        evp_pkey = evp_pkey_from_pkcs8(ec_get_type(header->type_parameters.curve), key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        size_t point_length = (size_t) header->size * 2;
        if (out == NULL) {
            *out_length = point_length * 2;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < header->size) {
            ERROR("Invalid out_length");
            break;
        }

        if (in_length != point_length * 2) {
            ERROR("Invalid in_length");
            break;
        }

        ec_group = ec_group_from_curve(header->type_parameters.curve);
        c1 = EC_POINT_new(ec_group);
        if (c1 == NULL) {
            ERROR("EC_POINT_new failed");
            break;
        }

        uint8_t in_buffer[point_length + 1];
        in_buffer[0] = POINT_CONVERSION_UNCOMPRESSED;
        memcpy(in_buffer + 1, in, point_length);
        if (EC_POINT_oct2point(ec_group, c1, in_buffer, point_length + 1, NULL) != 1) {
            ERROR("EC_POINT_oct2point failed");
            break;
        }

        c2 = EC_POINT_new(ec_group);
        if (c2 == NULL) {
            ERROR("EC_POINT_new failed");
            break;
        }

        memcpy(in_buffer + 1, (uint8_t*) in + point_length, point_length);
        if (EC_POINT_oct2point(ec_group, c2, in_buffer, point_length + 1, NULL) != 1) {
            ERROR("EC_POINT_oct2point failed");
            break;
        }

        // shared secret = C1*private
        shared_secret = EC_POINT_new(ec_group);
        if (shared_secret == NULL) {
            ERROR("EC_POINT_new failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER < 0x30000000
        const BIGNUM* private_key = NULL;
        EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
        if (ec_key == NULL) {
            ERROR("EVP_PKEY_get1_EC_KEY failed");
            break;
        }

        private_key = EC_KEY_get0_private_key(ec_key);
        EC_KEY_free(ec_key);
#else
        BIGNUM* private_key = NULL;
        if (EVP_PKEY_get_bn_param(evp_pkey, "priv", &private_key) != 1) {
            ERROR("EVP_PKEY_get_bn_param failed");
            break;
        }
#endif

        int result = EC_POINT_mul(ec_group, shared_secret, NULL, c1, private_key, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        BN_free(private_key);
#endif
        if (result == 0) {
            ERROR("EC_POINT_mul failed");
            break;
        }

        // message_point = C2 - shared secret
        if (EC_POINT_invert(ec_group, shared_secret, NULL) == 0) {
            ERROR("EC_POINT_invert failed");
            break;
        }

        message_point = EC_POINT_new(ec_group);
        if (message_point == NULL) {
            ERROR("EC_POINT_new failed");
            break;
        }

        if (EC_POINT_add(ec_group, message_point, c2, shared_secret, NULL) == 0) {
            ERROR("EC_POINT_add failed");
            break;
        }

        if (export_point(&buffer, ec_group, message_point) != point_length) {
            ERROR("export_point failed");
            break;
        }

        // The message is just the X coordinate.
        memcpy(out, buffer, header->size);
        *out_length = header->size;
        status = SA_STATUS_OK;
    } while (false);

    if (buffer != NULL)
        memory_secure_free(buffer);

    EVP_PKEY_free(evp_pkey);
    EC_GROUP_free(ec_group);
    EC_POINT_free(c1);
    EC_POINT_free(c2);
    EC_POINT_free(shared_secret);
    EC_POINT_free(message_point);
    BN_free(message_point_x);

    return status;
}

sa_status ec_compute_ecdh_shared_secret(
        stored_key_t** stored_key_shared_secret,
        const sa_rights* rights,
        const void* other_public,
        size_t other_public_length,
        const stored_key_t* stored_key) {

    if (stored_key_shared_secret == NULL) {
        ERROR("NULL stored_key_shared_secret");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* shared_secret = NULL;
    size_t shared_secret_length = 0;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY* other_evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        if (header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED25519 ||
                header->type_parameters.curve == SA_ELLIPTIC_CURVE_ED448) {
            ERROR("ED curves cannot be used for ECDH");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        evp_pkey = evp_pkey_from_pkcs8(ec_get_type(header->type_parameters.curve), key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        const uint8_t* p_other_public = other_public;
        other_evp_pkey = d2i_PUBKEY(NULL, &p_other_public, (long) other_public_length);
        if (other_evp_pkey == NULL) {
            ERROR("d2i_PUBKEY failed");
            break;
        }

        if (EVP_PKEY_id(evp_pkey) != EVP_PKEY_id(other_evp_pkey)) {
            ERROR("Key type mismatch");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
        if (evp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_new failed");
            break;
        }

        if (EVP_PKEY_derive_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_derive_init failed");
            break;
        }

        if (EVP_PKEY_derive_set_peer(evp_pkey_ctx, other_evp_pkey) != 1) {
            ERROR("EVP_PKEY_derive_set_peer failed");
            break;
        }

        if (EVP_PKEY_derive(evp_pkey_ctx, NULL, &shared_secret_length) != 1) {
            ERROR("EVP_PKEY_derive failed");
            break;
        }

        shared_secret = memory_secure_alloc(shared_secret_length);
        if (shared_secret == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (EVP_PKEY_derive(evp_pkey_ctx, shared_secret, &shared_secret_length) != 1) {
            ERROR("EVP_PKEY_derive failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_shared_secret, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC,
                &type_parameters, shared_secret_length, shared_secret, shared_secret_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (shared_secret != NULL) {
        memory_memset_unoptimizable(shared_secret, 0, shared_secret_length);
        memory_secure_free(shared_secret);
    }

    EVP_PKEY_free(other_evp_pkey);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(evp_pkey);
    return status;
}

sa_status ec_sign_ecdsa(
        void* signature,
        size_t* signature_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_PKEY* evp_pkey = NULL;
    EVP_MD_CTX* evp_md_ctx = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    uint8_t local_signature[MAX_EC_SIGNATURE];
    size_t local_signature_length = sizeof(local_signature);
    ECDSA_SIG* ecdsa_signature = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        if (!is_pcurve(header->type_parameters.curve)) {
            ERROR("ED & X curves cannot be used for ECDSA");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        evp_pkey = evp_pkey_from_pkcs8(ec_get_type(header->type_parameters.curve), key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        if (in == NULL && in_length > 0) {
            ERROR("NULL in");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        size_t ec_signature_length = (size_t) header->size * 2;
        if (signature == NULL) {
            *signature_length = ec_signature_length;
            status = SA_STATUS_OK;
            break;
        }

        if (*signature_length < ec_signature_length) {
            ERROR("Invalid signature_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }
        *signature_length = ec_signature_length;

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

            if (EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_signature_md failed");
                break;
            }

            if (EVP_PKEY_sign(evp_pkey_ctx, local_signature, &local_signature_length, in, in_length) != 1) {
                ERROR("EVP_PKEY_sign failed");
                break;
            }
        } else {
            evp_md_ctx = EVP_MD_CTX_create();
            if (evp_md_ctx == NULL) {
                ERROR("EVP_MD_CTX_create failed");
                break;
            }

            if (EVP_DigestSignInit(evp_md_ctx, NULL, evp_md, NULL, evp_pkey) != 1) {
                ERROR("EVP_DigestSignInit failed");
                break;
            }

            if (EVP_DigestSignUpdate(evp_md_ctx, in, in_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }

            if (EVP_DigestSignFinal(evp_md_ctx, local_signature, &local_signature_length) != 1) {
                ERROR("EVP_DigestSignFinal failed");
                break;
            }
        }

        const uint8_t* local_pointer = local_signature;
        ecdsa_signature = d2i_ECDSA_SIG(NULL, &local_pointer, (int) local_signature_length);
        if (ecdsa_signature == NULL) {
            ERROR("d2i_ECDSA_SIG failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        const BIGNUM* esigr = ecdsa_signature->r;
        const BIGNUM* esigs = ecdsa_signature->s;
#else
        const BIGNUM* esigr = NULL;
        const BIGNUM* esigs = NULL;
        ECDSA_SIG_get0(ecdsa_signature, &esigr, &esigs);
#endif

        uint8_t* signature_bytes = (uint8_t*) signature;
        if (!bn_export(signature_bytes, header->size, esigr)) {
            ERROR("bn_export failed");
            break;
        }

        if (!bn_export(signature_bytes + header->size, header->size, esigs)) {
            ERROR("bn_export failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    ECDSA_SIG_free(ecdsa_signature);
    EVP_MD_CTX_destroy(evp_md_ctx);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return status;
}

sa_status ec_sign_eddsa(
        void* signature,
        size_t* signature_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return SA_STATUS_OPERATION_NOT_SUPPORTED;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    EVP_PKEY* evp_pkey = NULL;
    EVP_MD_CTX* evp_md_ctx = NULL;
    ECDSA_SIG* ecdsa_signature = NULL;
    do {
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        if (header->type_parameters.curve != SA_ELLIPTIC_CURVE_ED25519 &&
                header->type_parameters.curve != SA_ELLIPTIC_CURVE_ED448) {
            ERROR("P & X curves cannot be used for EDDSA");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        evp_pkey = evp_pkey_from_pkcs8(ec_get_type(header->type_parameters.curve), key, key_length);
        if (evp_pkey == NULL) {
            ERROR("evp_pkey_from_pkcs8 failed");
            break;
        }

        if (in == NULL && in_length > 0) {
            ERROR("NULL in");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        size_t ec_signature_length = (size_t) header->size * 2;
        if (signature == NULL) {
            *signature_length = ec_signature_length;
            status = SA_STATUS_OK;
            break;
        }

        if (*signature_length < ec_signature_length) {
            ERROR("Invalid signature_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        evp_md_ctx = EVP_MD_CTX_create();
        if (evp_md_ctx == NULL) {
            ERROR("EVP_MD_CTX_create failed");
            break;
        }

        if (EVP_DigestSignInit(evp_md_ctx, NULL, NULL, NULL, evp_pkey) != 1) {
            ERROR("EVP_DigestSignInit failed");
            break;
        }

        if (EVP_DigestSign(evp_md_ctx, signature, signature_length, in, in_length) != 1) {
            ERROR("EVP_DigestSign failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    ECDSA_SIG_free(ecdsa_signature);
    EVP_MD_CTX_destroy(evp_md_ctx);

    return status;
#endif
}

sa_status ec_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_generate_parameters_ec* parameters) {

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

    size_t key_size = ec_key_size_from_curve(parameters->curve);
    if (key_size == 0) {
        ERROR("Unknown curve");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* key = NULL;
    size_t key_length = 0;
    EVP_PKEY_CTX* evp_pkey_param_ctx = NULL;
    EVP_PKEY* evp_pkey_params = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    EVP_PKEY* evp_pkey = NULL;
    do {
        int type = ec_get_nid(parameters->curve);
        if (type == 0) {
            ERROR("ec_get_nid failed");
            break;
        }

        if (is_pcurve(parameters->curve)) {
            evp_pkey_param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (evp_pkey_param_ctx == NULL) {
                ERROR("EVP_PKEY_CTX_new_id failed");
                break;
            }

            if (EVP_PKEY_paramgen_init(evp_pkey_param_ctx) != 1) {
                ERROR("EVP_PKEY_paramgen_init failed");
                break;
            }

            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_pkey_param_ctx, type) != 1) {
                ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
                break;
            }

            if (EVP_PKEY_CTX_set_ec_param_enc(evp_pkey_param_ctx, OPENSSL_EC_NAMED_CURVE) != 1) {
                ERROR("EVP_PKEY_CTX_set_ec_param_enc failed");
                break;
            }

            if (EVP_PKEY_paramgen(evp_pkey_param_ctx, &evp_pkey_params) <= 0) {
                ERROR("EVP_PKEY_paramgen failed");
                break;
            }

            evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey_params, NULL);
            if (evp_pkey_ctx == NULL) {
                ERROR("EVP_PKEY_CTX_new failed");
                break;
            }
        } else {
            evp_pkey_ctx = EVP_PKEY_CTX_new_id(type, NULL);
        }

        if (EVP_PKEY_keygen_init(evp_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_keygen_init failed");
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
        type_parameters.curve = parameters->curve;
        status = stored_key_create(stored_key, rights, NULL, SA_KEY_TYPE_EC, &type_parameters, key_size, key,
                key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (key != NULL) {
        memory_memset_unoptimizable(key, 0, key_length);
        memory_secure_free(key);
    }

    EVP_PKEY_CTX_free(evp_pkey_param_ctx);
    EVP_PKEY_free(evp_pkey_params);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(evp_pkey);
    return status;
}
