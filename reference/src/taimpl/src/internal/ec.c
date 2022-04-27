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

#include "ec.h" // NOLINT
#include "common.h"
#include "digest_internal.h"
#include "log.h"
#include "porting/memory.h"
#include "porting/rand.h"
#include "stored_key_internal.h"
#include <memory.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#define EC_KEY_SIZE(ec_group) (EC_GROUP_get_degree(ec_group) / 8 + (EC_GROUP_get_degree(ec_group) % 8 == 0 ? 0 : 1))
#define MAX_EC_SIGNATURE 256
#define UNCOMPRESSED_POINT 4

static inline bool is_pcurve(sa_elliptic_curve curve) {
    return curve == SA_ELLIPTIC_CURVE_NIST_P256 || curve == SA_ELLIPTIC_CURVE_NIST_P384 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P521;
}

static int ec_get_type(sa_elliptic_curve curve) {
    switch (curve) {
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

static EC_GROUP* ec_group_from_curve(sa_elliptic_curve curve) {
    EC_GROUP* ec_group = NULL;
    int type = ec_get_type(curve);
    if (type == 0) {
        ERROR("ec_get_type failed");
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
        EC_POINT* ec_point,
        bool raw) {

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

    size_t point_length = EC_KEY_SIZE(ec_group) * 2;
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

    if (buffer[0] != UNCOMPRESSED_POINT) {
        ERROR("EC_POINT_point2oct failed");
        return 0;
    }

    size_t out_length = point_length + (raw ? 0 : 1);
    *out = memory_secure_alloc(out_length);
    if (*out == NULL) {
        ERROR("memory_secure_alloc failed");
        return false;
    }

    memcpy(*out, &buffer[raw ? 1 : 0], out_length);
    return out_length;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static const char* ec_get_name(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P256:
            return "P-256";

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return "P-384";

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return "P-521";

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

static EC_POINT* calculate_point(
        EC_GROUP* ec_group,
        BIGNUM* private_key) {

    EC_POINT* ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
        ERROR("EC_POINT_new failed");
        return NULL;
    }

    if (EC_POINT_mul(ec_group, ec_point, private_key, NULL, NULL, NULL) == 0) {
        ERROR("EC_POINT_mul failed");
        EC_POINT_free(ec_point);
        return NULL;
    }

    return ec_point;
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
        ERROR("Bad out_length");
        return false;
    }

    uint8_t* out_bytes = (uint8_t*) out;
    BN_bn2bin(bn, out_bytes + out_length - written);

    return true;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
static EVP_PKEY* ec_import_private(
        sa_elliptic_curve curve,
        const void* private_key,
        size_t private_key_length) {

    if (private_key == NULL) {
        ERROR("NULL private");
        return NULL;
    }

    size_t key_size = ec_key_size_from_curve(curve);
    if (key_size == 0) {
        ERROR("Bad curve");
        return NULL;
    }

    if (private_key_length != key_size) {
        ERROR("Bad private_length");
        return NULL;
    }

    bool status = false;
    EVP_PKEY* evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    uint8_t* private_bytes = NULL;
    uint8_t* public_bytes = NULL;
    BIGNUM* private_bn = NULL;
    EC_GROUP* ec_group = NULL;
    EC_POINT* public_point = NULL;
    do {
        if (is_pcurve(curve)) {
            private_bn = BN_bin2bn((const unsigned char*) private_key, (int) private_key_length, NULL);
            if (private_bn == NULL) {
                ERROR("BN_bin2bn failed");
                break;
            }

            ec_group = ec_group_from_curve(curve);
            if (ec_group == NULL) {
                ERROR("ec_group_from_curve failed");
                break;
            }

            public_point = calculate_point(ec_group, private_bn);
            if (public_point == NULL) {
                ERROR("calculate_point failed");
                break;
            }

            size_t public_key_length = export_point(&public_bytes, ec_group, public_point, false);
            if (public_key_length == 0) {
                ERROR("export_point failed");
                break;
            }

            evp_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (evp_pkey_ctx == NULL) {
                ERROR("EVP_PKEY_CTX_new_id failed");
                break;
            }

            if (EVP_PKEY_fromdata_init(evp_pkey_ctx) != 1) {
                ERROR("EVP_PKEY_fromdata_init failed");
                break;
            }

            private_bytes = memory_secure_alloc(private_key_length);
            if (private_bytes == NULL) {
                ERROR("memory_secure_alloc failed");
                break;
            }

            if (BN_bn2nativepad(private_bn, private_bytes, (int) private_key_length) != (int) private_key_length) {
                ERROR("BN_bn2nativepad failed");
                break;
            }

            const char* group_name = ec_get_name(curve);
            OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*) group_name,
                            strlen(group_name)),
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, (void*) private_bytes, private_key_length),
                    OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public_bytes, public_key_length),
                    OSSL_PARAM_construct_end()};

            if (EVP_PKEY_fromdata(evp_pkey_ctx, &evp_pkey, EVP_PKEY_KEYPAIR, params) != 1) {
                ERROR("EVP_PKEY_fromdata failed");
                break;
            }
        } else {
            int type = ec_get_type(curve);
            if (type == 0) {
                ERROR("ec_get_type failed");
                break;
            }

            evp_pkey = EVP_PKEY_new_raw_private_key(type, NULL, private_key, private_key_length);
            if (evp_pkey == NULL) {
                ERROR("EVP_PKEY_new_raw_private_key failed");
                break;
            }
        }

        status = true;
    } while (false);

    if (private_bytes != NULL) {
        memory_memset_unoptimizable(private_bytes, 0, private_key_length);
        memory_secure_free(private_bytes);
    }

    if (public_bytes != NULL)
        memory_secure_free(public_bytes);

    EC_POINT_free(public_point);
    EC_GROUP_free(ec_group);
    BN_free(private_bn);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    if (!status) {
        EVP_PKEY_free(evp_pkey);
        evp_pkey = NULL;
    }

    return evp_pkey;
}

#else
static EVP_PKEY* ec_import_private(
        sa_elliptic_curve curve,
        const void* private_key,
        size_t private_key_length) {

    if (private_key == NULL) {
        ERROR("NULL private");
        return NULL;
    }

    size_t key_size = ec_key_size_from_curve(curve);
    if (key_size == 0) {
        ERROR("Bad curve");
        return NULL;
    }

    if (private_key_length != key_size) {
        ERROR("Bad private_length");
        return NULL;
    }

    bool status = false;
    EVP_PKEY* evp_pkey = NULL;
    if (is_pcurve(curve)) {
        // P256, P384, or P521 curve.
        EC_GROUP* ec_group = NULL;
        BIGNUM* private_bn = NULL;
        EC_KEY* ec_key = NULL;
        EC_POINT* ec_point = NULL;
        do {
            ec_group = ec_group_from_curve(curve);
            if (ec_group == NULL) {
                ERROR("ec_group_from_curve failed");
                break;
            }

            ec_key = EC_KEY_new();
            if (ec_key == NULL) {
                ERROR("EC_KEY_new failed");
                break;
            }

            if (EC_KEY_set_group(ec_key, ec_group) == 0) {
                ERROR("EC_KEY_set_group failed");
                break;
            }

            private_bn = BN_bin2bn((const unsigned char*) private_key, (int) private_key_length, NULL);
            if (private_bn == NULL) {
                ERROR("BN_bin2bn failed");
                break;
            }

            if (EC_KEY_set_private_key(ec_key, private_bn) == 0) {
                ERROR("EC_KEY_set_private_key failed");
                break;
            }

            ec_point = calculate_point(ec_group, private_bn);
            if (ec_point == NULL) {
                ERROR("calculate_point failed");
                break;
            }

            if (EC_KEY_set_public_key(ec_key, ec_point) == 0) {
                ERROR("EC_KEY_set_public_key failed");
                break;
            }

            if (EC_KEY_check_key(ec_key) == 0) {
                ERROR("EC_KEY_check_key failed");
                break;
            }

            evp_pkey = EVP_PKEY_new();
            if (EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key) == 0) {
                ERROR("EVP_PKEY_set1_EC_KEY failed");
                break;
            }

            status = true;
        } while (false);

        EC_POINT_free(ec_point);
        BN_free(private_bn);
        EC_KEY_free(ec_key);
        EC_GROUP_free(ec_group);
    } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERROR("Curve not supported");
#else
        int type = ec_get_type(curve);
        if (type == 0) {
            ERROR("ec_get_type failed");
            return NULL;
        }

        evp_pkey = EVP_PKEY_new_raw_private_key(type, NULL, private_key, private_key_length);
        if (evp_pkey == NULL) {
            ERROR("EVP_PKEY_new_raw_private_key failed");
            return NULL;
        }

        status = true;
#endif
    }

    if (!status) {
        EVP_PKEY_free(evp_pkey);
        evp_pkey = NULL;
    }

    return evp_pkey;
}
#endif

sa_status ec_validate_private(
        sa_elliptic_curve curve,
        const void* private,
        size_t private_length) {

    if (private == NULL) {
        ERROR("NULL private");
        return SA_STATUS_NULL_PARAMETER;
    }

    EVP_PKEY* evp_pkey = ec_import_private(curve, private, private_length);
    sa_status status = (evp_pkey != NULL) ? SA_STATUS_OK : SA_STATUS_OPERATION_NOT_SUPPORTED;
    EVP_PKEY_free(evp_pkey);
    return status;
}

size_t ec_key_size_from_curve(sa_elliptic_curve curve) {
    switch (curve) {
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
    uint8_t* public_bytes = NULL;
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

        evp_pkey = ec_import_private(header->param, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("ec_import_private failed");
            break;
        }

        if (is_pcurve(header->param)) {
            int required_length = i2d_PublicKey(evp_pkey, NULL);
            if (required_length <= 0) {
                ERROR("i2d_PublicKey failed");
                break;
            }

            if (out == NULL) {
                *out_length = required_length - 1;
                status = SA_STATUS_OK;
                break;
            }

            if (*out_length < (size_t) required_length - 1) {
                ERROR("Bad out_length");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }

            public_bytes = memory_secure_alloc(required_length);
            if (public_bytes == NULL) {
                ERROR("memory_secure_alloc failed");
                break;
            }

            unsigned char* buffer = public_bytes;
            int written = i2d_PublicKey(evp_pkey, &buffer);

            // The result will always start with a 4 to signify the following bytes are encoded as an uncompressed
            // point.
            if (written != required_length || public_bytes[0] != UNCOMPRESSED_POINT) {
                ERROR("i2d_PublicKey failed");
                break;
            }

            // Strip off the 4.
            memcpy(out, public_bytes + 1, written - 1);
            *out_length = written - 1;
        } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            ERROR("Curve not supported");
            break;
#else
            size_t public_key_size;
            if (EVP_PKEY_get_raw_public_key(evp_pkey, NULL, &public_key_size) != 1) {
                ERROR("EVP_PKEY_get_raw_public_key failed");
                break;
            }

            if (out == NULL) {
                *out_length = public_key_size;
                status = SA_STATUS_OK;
                break;
            }

            if (*out_length < public_key_size) {
                ERROR("Bad out_length");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }

            if (EVP_PKEY_get_raw_public_key(evp_pkey, out, out_length) != 1) {
                ERROR("EVP_PKEY_get_raw_public_key failed");
                break;
            }
#endif
        }

        status = SA_STATUS_OK;
    } while (false);

    if (public_bytes != NULL)
        memory_secure_free(public_bytes);

    EVP_PKEY_free(evp_pkey);
    return status;
}

sa_status ec_verify_cipher(
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key) {

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (header->param != SA_ELLIPTIC_CURVE_NIST_P256 && header->param != SA_ELLIPTIC_CURVE_NIST_P384 &&
            header->param != SA_ELLIPTIC_CURVE_NIST_P521) {
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
        size_t point_length = key_length * 2;
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        if (header->param != SA_ELLIPTIC_CURVE_NIST_P256 && header->param != SA_ELLIPTIC_CURVE_NIST_P384 &&
                header->param != SA_ELLIPTIC_CURVE_NIST_P521) {
            ERROR("ED & X curves cannot be used for El Gamal");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        evp_pkey = ec_import_private(header->param, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("ec_import_private failed");
            break;
        }

        ec_group = ec_group_from_curve(header->param);
        if (out == NULL) {
            *out_length = point_length * 2;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < key_length) {
            ERROR("Bad out_length");
            break;
        }

        if (in_length != point_length * 2) {
            ERROR("Bad in_length");
            break;
        }

        c1 = EC_POINT_new(ec_group);
        if (c1 == NULL) {
            ERROR("EC_POINT_new failed");
            break;
        }

        // 4 indicates the buffer is encoded as an uncompressed point.
        uint8_t in_buffer[point_length + 1];
        in_buffer[0] = UNCOMPRESSED_POINT;
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

        if (export_point(&buffer, ec_group, message_point, true) != point_length) {
            ERROR("export_point failed");
            break;
        }

        // The message is just the X coordinate.
        memcpy(out, buffer, key_length);
        *out_length = key_length;
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
        const stored_key_t* stored_key,
        const void* other_public,
        size_t other_public_length) {

    if (stored_key_shared_secret == NULL) {
        ERROR("NULL stored_key_shared_secret");
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
    EC_GROUP* ec_group = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EC_POINT* other_public_point = NULL;
    EVP_PKEY* other_evp_pkey = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;
    uint8_t* shared_secret = NULL;
    size_t shared_secret_length = 0;
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

        if (header->param == SA_ELLIPTIC_CURVE_ED25519 || header->param == SA_ELLIPTIC_CURVE_ED448) {
            ERROR("ED curves cannot be used for ECDH");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        evp_pkey = ec_import_private(header->param, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("ec_import_private failed");
            break;
        }

        ec_group = ec_group_from_curve(header->param);
        if (is_pcurve(header->param)) {
            uint8_t other_public_bytes[other_public_length + 1];
            memcpy(other_public_bytes + 1, other_public, other_public_length);
            other_public_bytes[0] = UNCOMPRESSED_POINT;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            evp_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (evp_pkey_ctx == NULL) {
                ERROR("EVP_PKEY_CTX_new_id failed");
                break;
            }

            if (EVP_PKEY_fromdata_init(evp_pkey_ctx) != 1) {
                ERROR("EVP_PKEY_fromdata_init failed");
                break;
            }

            const char* group_name = ec_get_name(header->param);
            OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*) group_name,
                            strlen(group_name)),
                    OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, other_public_bytes,
                            other_public_length + 1),
                    OSSL_PARAM_construct_end()};

            if (EVP_PKEY_fromdata(evp_pkey_ctx, &other_evp_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
                status = SA_STATUS_BAD_PARAMETER;
                ERROR("EVP_PKEY_fromdata failed");
                break;
            }

            EVP_PKEY_CTX_free(evp_pkey_ctx);
#else
            other_public_point = EC_POINT_new(ec_group);
            if (other_public_point == NULL) {
                ERROR("EC_POINT_new failed");
                break;
            }

            if (EC_POINT_oct2point(ec_group, other_public_point, other_public_bytes, other_public_length + 1,
                        NULL) != 1) {
                status = SA_STATUS_BAD_PARAMETER;
                ERROR("EC_POINT_oct2point failed");
                break;
            }

            EC_KEY* other_ec_key = EC_KEY_new();
            if (other_ec_key == NULL) {
                ERROR("EC_KEY_new failed");
                break;
            }

            if (EC_KEY_set_group(other_ec_key, ec_group) != 1) {
                ERROR("EC_KEY_set_group failed");
                EC_KEY_free(other_ec_key);
                break;
            }

            if (EC_KEY_set_public_key(other_ec_key, other_public_point) != 1) {
                ERROR("EC_KEY_set_public_key failed");
                EC_KEY_free(other_ec_key);
                break;
            }

            other_evp_pkey = EVP_PKEY_new();
            if (other_evp_pkey == NULL) {
                ERROR("EC_KEY_new failed");
                EC_KEY_free(other_ec_key);
                break;
            }

            if (EVP_PKEY_set1_EC_KEY(other_evp_pkey, other_ec_key) != 1) {
                ERROR("EVP_PKEY_set1_EC_KEY failed");
                EC_KEY_free(other_ec_key);
                break;
            }

            EC_KEY_free(other_ec_key);
#endif
        } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            ERROR("Curve not supported");
            break;
#else
            if (other_public_length != key_length) {
                ERROR("Invalid other_public_length");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }

            int type = ec_get_type(header->param);
            if (type == 0) {
                ERROR("ec_get_type failed");
                break;
            }

            other_evp_pkey = EVP_PKEY_new_raw_public_key(type, NULL, other_public, other_public_length);
            if (other_evp_pkey == NULL) {
                ERROR("EVP_PKEY_new_raw_public_key failed");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }
#endif
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
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        /* Derive the shared secret */
        if (EVP_PKEY_derive(evp_pkey_ctx, shared_secret, &shared_secret_length) != 1) {
            ERROR("EVP_PKEY_derive failed");
            break;
        }

        if (!stored_key_create(stored_key_shared_secret, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, 0,
                    shared_secret_length, shared_secret, shared_secret_length)) {
            ERROR("stored_key_create failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(other_evp_pkey);
    EC_POINT_free(other_public_point);
    EVP_PKEY_CTX_free(evp_pkey_ctx);
    EVP_PKEY_free(evp_pkey);
    EC_GROUP_free(ec_group);

    if (shared_secret != NULL) {
        memory_memset_unoptimizable(shared_secret, 0, shared_secret_length);
        memory_secure_free(shared_secret);
    }

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

        if (header->param != SA_ELLIPTIC_CURVE_NIST_P256 && header->param != SA_ELLIPTIC_CURVE_NIST_P384 &&
                header->param != SA_ELLIPTIC_CURVE_NIST_P521) {
            ERROR("ED & X curves cannot be used for ECDSA");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        evp_pkey = ec_import_private(header->param, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("ec_import_private failed");
            break;
        }

        if (in == NULL && in_length > 0) {
            ERROR("NULL in");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        size_t ec_signature_length = 2 * key_length;
        if (signature == NULL) {
            *signature_length = ec_signature_length;
            status = SA_STATUS_OK;
            break;
        }

        if (*signature_length < ec_signature_length) {
            ERROR("Bad signature_length");
            status = SA_STATUS_BAD_PARAMETER;
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
            if (EVP_DigestSignUpdate(evp_md_ctx, in, in_length) != 1) {
                ERROR("EVP_DigestSignUpdate failed");
                break;
            }

            if (EVP_DigestSignFinal(evp_md_ctx, local_signature, &local_signature_length) != 1) {
                ERROR("EVP_DigestSignFinal failed");
                break;
            }
#else
            if (EVP_DigestSign(evp_md_ctx, local_signature, &local_signature_length, in, in_length) != 1) {
                ERROR("EVP_DigestSign failed");
                break;
            }
#endif
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
        if (!bn_export(signature_bytes, key_length, esigr)) {
            ERROR("bn_export failed");
            break;
        }

        if (!bn_export(signature_bytes + key_length, key_length, esigs)) {
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

        if (header->param != SA_ELLIPTIC_CURVE_ED25519 && header->param != SA_ELLIPTIC_CURVE_ED448) {
            ERROR("P & X curves cannot be used for EDDSA");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        evp_pkey = ec_import_private(header->param, key, key_length);
        if (evp_pkey == NULL) {
            ERROR("ec_import_private failed");
            break;
        }

        if (in == NULL && in_length > 0) {
            ERROR("NULL in");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        size_t ec_signature_length = 2 * key_length;
        if (signature == NULL) {
            *signature_length = ec_signature_length;
            status = SA_STATUS_OK;
            break;
        }

        if (*signature_length < ec_signature_length) {
            ERROR("Bad signature_length");
            status = SA_STATUS_BAD_PARAMETER;
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (EVP_DigestSignUpdate(evp_md_ctx, in, in_length) != 1) {
            ERROR("EVP_DigestSignUpdate failed");
            break;
        }

        if (EVP_DigestSignFinal(evp_md_ctx, local_signature, &local_signature_length) != 1) {
            ERROR("EVP_DigestSignFinal failed");
            break;
        }
#else
        if (EVP_DigestSign(evp_md_ctx, local_signature, &local_signature_length, in, in_length) != 1) {
            ERROR("EVP_DigestSign failed");
            break;
        }
#endif

        memcpy(signature, local_signature, local_signature_length);
        *signature_length = local_signature_length;
        status = SA_STATUS_OK;
    } while (false);

    EVP_PKEY_free(evp_pkey);
    ECDSA_SIG_free(ecdsa_signature);
    EVP_MD_CTX_destroy(evp_md_ctx);

    return status;
}

sa_status ec_generate_key(
        stored_key_t** stored_key_generated,
        const sa_rights* rights,
        sa_generate_parameters_ec* parameters) {

    if (stored_key_generated == NULL) {
        ERROR("NULL stored_key_generated");
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
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* generated = NULL;
    do {
        generated = memory_secure_alloc(key_size);
        if (generated == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!rand_bytes(generated, key_size)) {
            ERROR("rand_bytes failed");
            break;
        }

        if (key_size == EC_P521_KEY_SIZE) {
            // Only the ls bit is used of the MS Byte of the EC P521 private key.
            generated[0] &= 1;
        }

        EVP_PKEY* evp_pkey = ec_import_private(parameters->curve, generated, key_size);
        if (evp_pkey == NULL) {
            EVP_PKEY_free(evp_pkey);
            ERROR("ec_import_private failed");
            status = SA_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        EVP_PKEY_free(evp_pkey);
        if (!stored_key_create(stored_key_generated, rights, NULL, SA_KEY_TYPE_EC, parameters->curve, key_size,
                    generated, key_size)) {
            ERROR("stored_key_create failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (generated != NULL) {
        memory_memset_unoptimizable(generated, 0, key_size);
        memory_secure_free(generated);
    }

    return status;
}
