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

#include <cstring>
#include <openssl/cmac.h>
#include <openssl/ec.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/hmac.h>
#else
#include <openssl/kdf.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "client_test_helpers.h"
#include "sa_key_common.h"

using namespace client_test_helpers;

// This is a randomly generated value.
const std::vector<uint8_t> SaKeyBase::TEST_KEY = {
        0xe7, 0x9b, 0x03, 0x18, 0x85, 0x1b, 0x9d, 0xbd,
        0xd7, 0x17, 0x18, 0xf9, 0xec, 0x72, 0xf0, 0x3d};

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static int ec_get_type(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P256:
            return NID_X9_62_prime256v1;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return NID_secp384r1;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return NID_secp521r1;

        case SA_ELLIPTIC_CURVE_ED25519:
            return NID_ED25519;

        case SA_ELLIPTIC_CURVE_X25519:
            return NID_X25519;

        case SA_ELLIPTIC_CURVE_ED448:
            return NID_ED448;

        case SA_ELLIPTIC_CURVE_X448:
            return NID_X448;

        default:
            ERROR("Unknown EC curve encountered");
            return 0;
    }
}
#endif

static inline bool is_pcurve(sa_elliptic_curve curve) {
    return curve == SA_ELLIPTIC_CURVE_NIST_P256 || curve == SA_ELLIPTIC_CURVE_NIST_P384 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P521;
}

std::shared_ptr<EC_POINT> SaKeyBase::ec_point_import_xy(
        sa_elliptic_curve curve,
        std::vector<uint8_t> in) {

    auto key_size = ec_get_key_size(curve);
    if (key_size == 0) {
        ERROR("Bad curve");
        return nullptr;
    }

    if (in.size() != key_size * 2) {
        ERROR("Bad in_length");
        return nullptr;
    }

    bool status = false;
    std::shared_ptr<EC_GROUP> group;
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    EC_POINT* ec_point = nullptr;

    do {
        group = ec_group_from_curve(curve);
        if (group == nullptr) {
            ERROR("EC_GROUP_new_by_curve_name failed");
            break;
        }

        x = BN_bin2bn(in.data(), static_cast<int>(key_size), nullptr);
        if (x == nullptr) {
            ERROR("BN_bin2bn failed");
            break;
        }

        y = BN_bin2bn(in.data() + key_size, static_cast<int>(key_size), nullptr);
        if (y == nullptr) {
            ERROR("BN_bin2bn failed");
            break;
        }

        ec_point = EC_POINT_new(group.get());
        if (ec_point == nullptr) {
            ERROR("EC_POINT_new failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        if (EC_POINT_set_affine_coordinates(group.get(), ec_point, x, y, nullptr) == 0) {
            ERROR("EC_POINT_set_affine_coordinates failed");
            break;
        }
#else
        if (EC_POINT_set_affine_coordinates_GFp(group.get(), ec_point, x, y, nullptr) == 0) {
            ERROR("EC_POINT_set_affine_coordinates_GFp failed");
            break;
        }
#endif

        status = true;
    } while (false);

    BN_free(x);
    BN_free(y);

    if (!status) {
        EC_POINT_free(ec_point);
        ec_point = nullptr;
    }

    return {ec_point, EC_POINT_free};
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
bool SaKeyBase::dh_generate(
        std::shared_ptr<EVP_PKEY>& evp_pkey,
        std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& p,
        const std::vector<uint8_t>& g) {

    auto evp_pkey_parameters_ctx = std::shared_ptr<EVP_PKEY_CTX>(
            EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr), EVP_PKEY_CTX_free);
    if (evp_pkey_parameters_ctx == nullptr) {
        ERROR("EVP_PKEY_CTX_new_id failed");
        return false;
    }

    if (EVP_PKEY_fromdata_init(evp_pkey_parameters_ctx.get()) != 1) {
        ERROR("EVP_PKEY_fromdata_init failed");
        return false;
    }

    auto p_bn = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    if (p_bn == nullptr) {
        ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(p.data(), static_cast<int>(p.size()), p_bn.get()) == nullptr) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    std::vector<uint8_t> p_native(p.size());
    if (BN_bn2nativepad(p_bn.get(), p_native.data(), static_cast<int>(p_native.size())) !=
            static_cast<int>(p_native.size())) {
        ERROR("BN_bn2nativepad failed");
        return false;
    }

    auto g_bn = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    if (g_bn == nullptr) {
        ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(g.data(), static_cast<int>(g.size()), g_bn.get()) == nullptr) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    std::vector<uint8_t> g_native(g.size());
    if (BN_bn2nativepad(g_bn.get(), g_native.data(), static_cast<int>(g_native.size())) !=
            static_cast<int>(g_native.size())) {
        ERROR("BN_bn2nativepad failed");
        return false;
    }

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, static_cast<unsigned char*>(p_native.data()),
                    p_native.size()),
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, static_cast<unsigned char*>(g_native.data()),
                    g_native.size()),
            OSSL_PARAM_construct_end()};

    EVP_PKEY* evp_pkey_parameters = nullptr;
    if (EVP_PKEY_fromdata(evp_pkey_parameters_ctx.get(), &evp_pkey_parameters, EVP_PKEY_KEY_PARAMETERS, params) != 1) {
        ERROR("EVP_PKEY_fromdata failed");
        return false;
    }

    auto evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(evp_pkey_parameters, nullptr),
            EVP_PKEY_CTX_free);
    EVP_PKEY_free(evp_pkey_parameters);
    if (evp_pkey_ctx == nullptr) {
        ERROR("EVP_PKEY_CTX_new failed");
        return false;
    }

    if (EVP_PKEY_keygen_init(evp_pkey_ctx.get()) != 1) {
        ERROR("EVP_PKEY_keygen_init failed");
        return false;
    }

    EVP_PKEY* temp = nullptr;
    if (EVP_PKEY_generate(evp_pkey_ctx.get(), &temp) != 1) {
        ERROR("EVP_PKEY_generate failed");
        return false;
    }

    evp_pkey = std::shared_ptr<EVP_PKEY>(temp, EVP_PKEY_free);

    BIGNUM* public_bn = nullptr;
    if (EVP_PKEY_get_bn_param(evp_pkey.get(), "pub", &public_bn) != 1) {
        ERROR("EVP_PKEY_get_bn_param failed");
        return false;
    }

    size_t public_key_size = BN_num_bytes(public_bn);
    public_key.resize(public_key_size);
    size_t written = BN_bn2bin(public_bn, public_key.data());
    BN_free(public_bn);
    if (written <= 0) {
        ERROR("BN_bn2bin failed");
        return false;
    }

    public_key.resize(written);

    return true;
}
#else
bool SaKeyBase::dh_generate(
        std::shared_ptr<DH>& dh,
        std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& p,
        const std::vector<uint8_t>& g) {

    dh = std::shared_ptr<DH>(DH_new(), DH_free);
    if (dh == nullptr) {
        ERROR("DH_new failed");
        return false;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = BN_bin2bn(p.data(), static_cast<int>(p.size()), nullptr);
    dh->g = BN_bin2bn(g.data(), static_cast<int>(g.size()), nullptr);

    if ((dh->p == nullptr) || (dh->g == nullptr)) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    dh->length = static_cast<long>(p.size()) * 8;
#else
    BIGNUM* bnp = BN_bin2bn(p.data(), static_cast<int>(p.size()), nullptr);
    BIGNUM* bng = BN_bin2bn(g.data(), static_cast<int>(g.size()), nullptr);
    DH_set0_pqg(dh.get(), bnp, nullptr, bng);
#endif

    if (DH_generate_key(dh.get()) == 0) {
        ERROR("DH_generate_key failed");
        return false;
    }

    public_key.resize(p.size());
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    size_t written = BN_bn2bin(dh->pub_key, public_key.data());
#else
    const BIGNUM* public_bn = nullptr;
    DH_get0_key(dh.get(), &public_bn, nullptr);
    size_t written = BN_bn2bin(public_bn, public_key.data());
#endif
    if (written <= 0) {
        ERROR("BN_bn2bin failed");
        return false;
    }

    public_key.resize(written);

    return true;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000
bool SaKeyBase::dh_compute_secret(
        std::vector<uint8_t>& shared_secret,
        const std::shared_ptr<EVP_PKEY>& evp_pkey,
        const std::vector<uint8_t>& other_pub_key,
        const std::vector<uint8_t>& p,
        const std::vector<uint8_t>& g) {

    size_t modulus_size = p.size();
    std::vector<uint8_t> other_public_bytes = other_pub_key;
    while (other_public_bytes.size() < modulus_size)
        other_public_bytes.insert(other_public_bytes.begin(), 0);

    auto other_evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr),
            EVP_PKEY_CTX_free);
    if (other_evp_pkey_ctx == nullptr) {
        ERROR("EVP_PKEY_CTX_new_id failed");
        return false;
    }

    if (EVP_PKEY_fromdata_init(other_evp_pkey_ctx.get()) != 1) {
        ERROR("EVP_PKEY_fromdata_init failed");
        return false;
    }

    auto other_public_bn = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    if (other_public_bn == nullptr) {
        ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(other_public_bytes.data(), static_cast<int>(other_public_bytes.size()), other_public_bn.get()) ==
            nullptr) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    std::vector<uint8_t> other_public_native(other_pub_key.size());
    if (BN_bn2nativepad(other_public_bn.get(), other_public_native.data(),
                static_cast<int>(other_public_native.size())) != static_cast<int>(other_public_native.size())) {
        ERROR("BN_bn2nativepad failed");
        return false;
    }

    auto p_bn = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    if (p_bn == nullptr) {
        ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(p.data(), static_cast<int>(p.size()), p_bn.get()) == nullptr) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    std::vector<uint8_t> p_native(p.size());
    if (BN_bn2nativepad(p_bn.get(), p_native.data(), static_cast<int>(p_native.size())) !=
            static_cast<int>(p_native.size())) {
        ERROR("BN_bn2nativepad failed");
        return false;
    }

    auto g_bn = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    if (g_bn == nullptr) {
        ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(g.data(), static_cast<int>(g.size()), g_bn.get()) == nullptr) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    std::vector<uint8_t> g_native(g.size());
    if (BN_bn2nativepad(g_bn.get(), g_native.data(), static_cast<int>(g_native.size())) !=
            static_cast<int>(g_native.size())) {
        ERROR("BN_bn2nativepad failed");
        return false;
    }

    OSSL_PARAM other_params[] = {
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, static_cast<unsigned char*>(other_public_native.data()),
                    other_public_native.size()),
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, static_cast<unsigned char*>(p_native.data()),
                    p_native.size()),
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, static_cast<unsigned char*>(g_native.data()),
                    g_native.size()),
            OSSL_PARAM_construct_end()};

    EVP_PKEY* temp = nullptr;
    if (EVP_PKEY_fromdata(other_evp_pkey_ctx.get(), &temp, EVP_PKEY_PUBLIC_KEY, other_params) != 1) {
        ERROR("EVP_PKEY_fromdata failed");
        return false;
    }

    auto other_evp_pkey = std::shared_ptr<EVP_PKEY>(temp, EVP_PKEY_free);
    auto evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(evp_pkey.get(), nullptr), EVP_PKEY_CTX_free);
    if (evp_pkey == nullptr) {
        ERROR("EVP_PKEY_CTX_new failed");
        return false;
    }

    if (EVP_PKEY_derive_init(evp_pkey_ctx.get()) != 1) {
        ERROR("EVP_PKEY_derive_init failed");
        return false;
    }

    if (EVP_PKEY_derive_set_peer(evp_pkey_ctx.get(), other_evp_pkey.get()) != 1) {
        ERROR("EVP_PKEY_derive_set_peer failed");
        return false;
    }

    size_t shared_secret_size = 0;
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), nullptr, &shared_secret_size) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

    shared_secret.resize(modulus_size);
    std::vector<uint8_t> local_shared_secret(modulus_size);
    size_t written = shared_secret_size;
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), local_shared_secret.data(), &written) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

    shared_secret.assign(modulus_size, 0);
    memcpy(shared_secret.data() + modulus_size - written, local_shared_secret.data(), written);

    return true;
}
#else
bool SaKeyBase::dh_compute_secret(
        std::vector<uint8_t>& shared_secret,
        const std::shared_ptr<DH>& dh,
        const std::vector<uint8_t>& other_pub_key) {

    size_t modulus_size = DH_size(dh.get());
    std::vector<uint8_t> other_public_bytes = other_pub_key;
    while (other_public_bytes.size() < modulus_size)
        other_public_bytes.insert(other_public_bytes.begin(), 0);

    BIGNUM* other_pub_key_bn = BN_bin2bn(other_public_bytes.data(), static_cast<int>(other_public_bytes.size()),
            nullptr);
    if (other_pub_key_bn == nullptr) {
        ERROR("BN_bin2bn failed");
        return false;
    }

    shared_secret.resize(modulus_size);
    std::vector<uint8_t> local_shared_secret(modulus_size);
    int written = DH_compute_key(local_shared_secret.data(), other_pub_key_bn, dh.get());
    BN_free(other_pub_key_bn);
    if (written <= 0) {
        ERROR("DH_compute_key failed");
        return false;
    }

    shared_secret.assign(modulus_size, 0);
    memcpy(shared_secret.data() + modulus_size - written, local_shared_secret.data(), written);
    return true;
}
#endif

sa_status SaKeyBase::ec_generate_key(
        sa_elliptic_curve curve,
        std::shared_ptr<EVP_PKEY>& private_key,
        std::vector<uint8_t>& public_key) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (is_pcurve(curve)) {
        auto ec_key = std::shared_ptr<EC_KEY>(EC_KEY_new(), EC_KEY_free);
        if (ec_key == nullptr) {
            ERROR("EC_KEY_new failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        auto group = ec_group_from_curve(curve);
        if (group == nullptr) {
            ERROR("ec_group_from_curve failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        EC_KEY_set_group(ec_key.get(), group.get());

        if (EC_KEY_generate_key(ec_key.get()) != 1) {
            ERROR("EC_KEY_generate_key failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        private_key = {EVP_PKEY_new(), EVP_PKEY_free};
        if (EVP_PKEY_set1_EC_KEY(private_key.get(), ec_key.get()) == 0) {
            ERROR("EVP_PKEY_set1_EC_KEY failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
    } else {
        ERROR("Invalid curve");
        return SA_STATUS_OPERATION_NOT_SUPPORTED;
    }
#else
    int type = ec_get_type(curve);
    if (type == 0) {
        ERROR("ec_get_type failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_ctx;
    if (is_pcurve(curve)) {
        auto param_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
        if (param_ctx == nullptr) {
            ERROR("EVP_PKEY_CTX_new_id failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        if (EVP_PKEY_paramgen_init(param_ctx.get()) != 1) {
            ERROR("EVP_PKEY_paramgen_init failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx.get(), type) != 1) {
            ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        if (EVP_PKEY_CTX_set_ec_param_enc(param_ctx.get(), OPENSSL_EC_NAMED_CURVE) != 1) {
            ERROR("EVP_PKEY_CTX_set_ec_param_enc failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        EVP_PKEY* params = nullptr;
        if (EVP_PKEY_paramgen(param_ctx.get(), &params) <= 0) {
            ERROR("EVP_PKEY_paramgen failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        auto evp_pkey_params = std::shared_ptr<EVP_PKEY>(params, EVP_PKEY_free);
        evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(evp_pkey_params.get(), nullptr),
                EVP_PKEY_CTX_free);
        if (evp_pkey_ctx == nullptr) {
            ERROR("EVP_PKEY_CTX_new failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
    } else {
        evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_id(type, nullptr), EVP_PKEY_CTX_free);
    }

    if (EVP_PKEY_keygen_init(evp_pkey_ctx.get()) != 1) {
        ERROR("EVP_PKEY_keygen_init failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    EVP_PKEY* evp_pkey = nullptr;
    if (EVP_PKEY_keygen(evp_pkey_ctx.get(), &evp_pkey) != 1) {
        ERROR("EVP_PKEY_keygen failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    private_key = {evp_pkey, EVP_PKEY_free};
#endif

    size_t key_length = ec_get_key_size(curve);

    if (is_pcurve(curve)) {
        size_t public_key_size = key_length * 2 + 1;
        public_key.resize(public_key_size);
        unsigned char* buffer = public_key.data();
        size_t written = i2d_PublicKey(private_key.get(), &buffer);

        // The result will always start with a 4 to signify the following bytes are encoded as an uncompressed
        // point.
        if (written != public_key_size || public_key[0] != 4) {
            ERROR("i2d_PublicKey failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        // Strip off the 4.
        public_key.erase(public_key.begin());
    } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000
        ERROR("curve not supported");
        return SA_STATUS_OPERATION_NOT_SUPPORTED;
#else
        size_t public_key_size;
        if (EVP_PKEY_get_raw_public_key(private_key.get(), nullptr, &public_key_size) != 1) {
            ERROR("EVP_PKEY_get_raw_public_key failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        public_key.resize(public_key_size);
        if (EVP_PKEY_get_raw_public_key(private_key.get(), public_key.data(), &public_key_size) != 1) {
            ERROR("EVP_PKEY_get_raw_public_key failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
#endif
    }

    return SA_STATUS_OK;
}

bool SaKeyBase::ecdh_compute_secret(
        sa_elliptic_curve curve,
        std::vector<uint8_t>& shared_secret,
        const std::shared_ptr<EVP_PKEY>& private_key,
        const std::vector<uint8_t>& other_public_key) {

    shared_secret.resize(ec_get_key_size(curve));

    std::shared_ptr<EVP_PKEY> other_evp_pkey;
    if (is_pcurve(curve)) {
        std::vector<uint8_t> other_public_bytes(other_public_key);
        other_public_bytes.insert(other_public_bytes.begin(), 4);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        auto evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
        if (evp_pkey_ctx == nullptr) {
            ERROR("EVP_PKEY_CTX_new_id failed");
            return false;
        }

        if (EVP_PKEY_fromdata_init(evp_pkey_ctx.get()) != 1) {
            ERROR("EVP_PKEY_fromdata_init failed");
            return false;
        }

        const char* group_name = ec_get_name(curve);
        if (group_name == nullptr) {
            ERROR("ec_get_name failed");
            return false;
        }

        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group_name),
                        strlen(group_name)),
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, other_public_bytes.data(),
                        other_public_bytes.size()),
                OSSL_PARAM_construct_end()};

        EVP_PKEY* temp = nullptr;
        if (EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            ERROR("EVP_PKEY_fromdata failed");
            return false;
        }

        other_evp_pkey = {temp, EVP_PKEY_free};
#else
        auto ec_group = ec_group_from_curve(curve);
        auto other_public_point = std::shared_ptr<EC_POINT>(EC_POINT_new(ec_group.get()), EC_POINT_free);
        if (other_public_point == nullptr) {
            ERROR("EC_POINT_new failed");
            return false;
        }

        if (EC_POINT_oct2point(ec_group.get(), other_public_point.get(), other_public_bytes.data(),
                    other_public_bytes.size(), nullptr) != 1) {
            ERROR("EC_POINT_oct2point failed");
            return false;
        }

        auto other_ec_key = std::shared_ptr<EC_KEY>(EC_KEY_new(), EC_KEY_free);
        if (other_ec_key == nullptr) {
            ERROR("EC_KEY_new failed");
            return false;
        }

        if (EC_KEY_set_group(other_ec_key.get(), ec_group.get()) != 1) {
            ERROR("EC_KEY_set_group failed");
            return false;
        }

        if (EC_KEY_set_public_key(other_ec_key.get(), other_public_point.get()) != 1) {
            ERROR("EC_KEY_set_public_key failed");
            return false;
        }

        other_evp_pkey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
        if (other_evp_pkey == nullptr) {
            ERROR("EVP_PKEY_new failed");
            return false;
        }

        if (EVP_PKEY_set1_EC_KEY(other_evp_pkey.get(), other_ec_key.get()) != 1) {
            ERROR("EVP_PKEY_set1_EC_KEY failed");
            return false;
        }
#endif
    } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERROR("ec_group_from_curve failed");
        return false;
#else
        int type = ec_get_type(curve);
        if (type == 0) {
            ERROR("ec_get_type failed");
            return false;
        }

        EVP_PKEY* p = EVP_PKEY_new_raw_public_key(type, nullptr, other_public_key.data(), other_public_key.size());
        other_evp_pkey = std::shared_ptr<EVP_PKEY>(p, EVP_PKEY_free);
        if (other_evp_pkey == nullptr) {
            ERROR("EVP_PKEY_new_raw_public_key failed");
            return false;
        }
#endif
    }

    auto evp_pkey_cxt = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(private_key.get(), nullptr), EVP_PKEY_CTX_free);
    if (evp_pkey_cxt == nullptr) {
        ERROR("EVP_PKEY_CTX_new failed");
        return false;
    }

    if (EVP_PKEY_derive_init(evp_pkey_cxt.get()) != 1) {
        ERROR("EVP_PKEY_derive_init failed");
        return false;
    }

    if (EVP_PKEY_derive_set_peer(evp_pkey_cxt.get(), other_evp_pkey.get()) != 1) {
        ERROR("EVP_PKEY_derive_set_peer failed");
        return false;
    }

    size_t shared_secret_length = 0;
    if (EVP_PKEY_derive(evp_pkey_cxt.get(), nullptr, &shared_secret_length) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

    shared_secret.resize(shared_secret_length);
    if (EVP_PKEY_derive(evp_pkey_cxt.get(), shared_secret.data(), &shared_secret_length) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

    return true;
}

bool SaKeyBase::execute_dh(
        std::shared_ptr<sa_key>& shared_secret,
        std::vector<uint8_t>& clear_shared_secret,
        const std::vector<uint8_t>& dhp,
        const std::vector<uint8_t>& dhg) {
    auto key = create_uninitialized_sa_key();

    sa_rights rights;
    rights_set_allow_all(&rights);

    sa_generate_parameters_dh parameters = {
            .p = dhp.data(),
            .p_length = dhp.size(),
            .g = dhg.data(),
            .g_length = dhg.size()};
    if (sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters) != SA_STATUS_OK)
        return false;

    size_t dh_public_key_length;
    if (sa_key_get_public(nullptr, &dh_public_key_length, *key) != SA_STATUS_OK)
        return false;

    std::vector<uint8_t> dh_public_key(dh_public_key_length);
    if (sa_key_get_public(dh_public_key.data(), &dh_public_key_length, *key) != SA_STATUS_OK)
        return false;

        //create other side info
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    std::shared_ptr<EVP_PKEY> other_private_key;
    std::vector<uint8_t> other_public_key;
    if (!dh_generate(other_private_key, other_public_key, dhp, dhg)) {
        ERROR("dh_generate failed");
        return false;
    }
#else
    std::shared_ptr<DH> other_dh;
    std::vector<uint8_t> other_public_key;
    if (!dh_generate(other_dh, other_public_key, dhp, dhg)) {
        ERROR("dh_generate failed");
        return false;
    }
#endif

    if (sa_key_exchange(shared_secret.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *key,
                other_public_key.data(), other_public_key.size(), nullptr) != SA_STATUS_OK) {
        ERROR("sa_key_exchange failed");
        return false;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    if (!dh_compute_secret(clear_shared_secret, other_private_key, dh_public_key, dhp, dhg)) {
        ERROR("dh_compute_secret failed");
        return false;
    }
#else
    if (!dh_compute_secret(clear_shared_secret, other_dh, dh_public_key)) {
        ERROR("dh_compute_secret failed");
        return false;
    }
#endif

    return true;
}

sa_status SaKeyBase::execute_ecdh(
        sa_elliptic_curve curve,
        std::shared_ptr<sa_key>& shared_secret,
        std::vector<uint8_t>& clear_shared_secret) {
    auto other_private_key = create_uninitialized_sa_key();

    sa_rights rights;
    rights_set_allow_all(&rights);

    sa_generate_parameters_ec parameters = {curve};
    sa_status status = sa_key_generate(other_private_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
    if (status != SA_STATUS_OK)
        return status;

    size_t ec_public_key_length;
    status = sa_key_get_public(nullptr, &ec_public_key_length, *other_private_key);
    if (status != SA_STATUS_OK)
        return status;

    std::vector<uint8_t> other_public_key(ec_public_key_length);
    status = sa_key_get_public(other_public_key.data(), &ec_public_key_length, *other_private_key);
    if (status != SA_STATUS_OK)
        return status;

    std::shared_ptr<EVP_PKEY> private_key;
    std::vector<uint8_t> public_key;
    status = ec_generate_key(curve, private_key, public_key);
    if (status != SA_STATUS_OK) {
        ERROR("ec_generate_key failed");
        return status;
    }

    status = sa_key_exchange(shared_secret.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *other_private_key,
            public_key.data(), public_key.size(), nullptr);
    if (status != SA_STATUS_OK) {
        ERROR("sa_key_exchange failed");
        return status;
    }

    /* Derive the shared secret */
    if (!ecdh_compute_secret(curve, clear_shared_secret, private_key, other_public_key)) {
        ERROR("ecdh_compute_secret failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return status;
}

std::shared_ptr<std::vector<uint8_t>> SaKeyBase::derive_test_key_ladder(
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3,
        std::vector<uint8_t>& c4) {
    size_t key_length = 16;
    std::vector<uint8_t> stage1(key_length);
    if (!decrypt_aes_ecb_openssl(stage1, c1, TEST_KEY, false) || key_length != 16)
        return nullptr;

    std::vector<uint8_t> stage2(key_length);
    if (!decrypt_aes_ecb_openssl(stage2, c2, stage1, false) || key_length != 16)
        return nullptr;

    std::vector<uint8_t> stage3(key_length);
    if (!decrypt_aes_ecb_openssl(stage3, c3, stage2, false) || key_length != 16)
        return nullptr;

    std::shared_ptr<std::vector<uint8_t>> stage4(new std::vector<uint8_t>(key_length),
            [](std::vector<uint8_t>* p) { delete p; });
    if (c4.empty())
        *stage4 = stage3;
    else if (!decrypt_aes_ecb_openssl(*stage4, c4, stage3, false) || key_length != 16)
        return nullptr;

    return stage4;
}

bool SaKeyBase::hkdf(
        std::vector<uint8_t>& out,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& salt,
        std::vector<uint8_t>& info,
        sa_digest_algorithm digest_algorithm) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L

    const EVP_MD* evp_md = digest_mechanism(digest_algorithm);

    uint8_t prk[SHA512_DIGEST_LENGTH];
    unsigned int prk_len;

    // HMAC openssl 1.0.2 doesn't like 0 length keys.
    std::vector<uint8_t> temp_salt = {0};
    if (!salt.empty())
        temp_salt = salt;

    if (HMAC(evp_md, temp_salt.data(), static_cast<int>(temp_salt.size()), key.data(), key.size(), prk, &prk_len) ==
            nullptr) {
        ERROR("HMAC failed");
        return false;
    }

    /* Expand */
    size_t digest_size = digest_length(digest_algorithm);
    size_t out_len = out.size();
    size_t r = out_len / digest_size + ((out_len % digest_size == 0) ? 0 : 1);
    size_t i;

    uint8_t t[SHA512_DIGEST_LENGTH];
    unsigned int t_len = 0;

    for (i = 1; i <= r; i++) {
        uint8_t loop = i;
        size_t cp_len;

        if (i == r) {
            size_t mod = out_len % digest_size;
            cp_len = (mod == 0) ? digest_size : mod;
        } else {
            cp_len = digest_size;
        }

        std::shared_ptr<HMAC_CTX> ctx(new HMAC_CTX(),
                [](HMAC_CTX* p) {
                    HMAC_CTX_cleanup(p);
                    delete p;
                });
        if (1 != HMAC_Init_ex(ctx.get(), prk, static_cast<int>(prk_len), evp_md, nullptr)) {
            ERROR("HMAC_Init_ex failed");
            return false;
        }

        if (t_len > 0 && 1 != HMAC_Update(ctx.get(), t, t_len)) {
            ERROR("HMAC_Update failed");
            return false;
        }

        if (1 != HMAC_Update(ctx.get(), info.data(), info.size())) {
            ERROR("HMAC_Update failed");
            return false;
        }

        if (1 != HMAC_Update(ctx.get(), &loop, 1)) {
            ERROR("HMAC_Update failed");
            return false;
        }

        if (1 != HMAC_Final(ctx.get(), t, &t_len)) {
            ERROR("HMAC_Final failed");
            return false;
        }

        memcpy(out.data() + (i - 1) * digest_size, t, cp_len);
    }

    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    return true;
#else
    std::shared_ptr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);

    if (EVP_PKEY_derive_init(pctx.get()) <= 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx.get(), digest_mechanism(digest_algorithm)) <= 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), key.data(), static_cast<int>(key.size())) <= 0) {
        return false;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), static_cast<int>(info.size())) <= 0) {
        return false;
    }

    size_t length = out.size();
    return EVP_PKEY_derive(pctx.get(), out.data(), &length) > 0;
#endif
}

bool SaKeyBase::ansi_x963_kdf(
        std::vector<uint8_t>& out,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& info,
        sa_digest_algorithm digest_algorithm) {

    std::vector<uint8_t> counter;
    counter.push_back(0);
    counter.push_back(0);
    counter.push_back(0);
    counter.push_back(1);

    size_t key_length = out.size();
    out.resize(0);
    for (size_t i = 0; i < key_length;) {
        std::vector<uint8_t> temp;
        if (!digest_openssl(temp, digest_algorithm, key, counter, info))
            return false;

        out.insert(out.end(), temp.begin(), temp.end());
        i += digest_length(digest_algorithm);

        counter[3]++;
    }

    out.resize(key_length);
    return true;
}

bool SaKeyBase::concat_kdf(
        std::vector<uint8_t>& out,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& info,
        sa_digest_algorithm digest_algorithm) {

    std::vector<uint8_t> counter;
    counter.push_back(0);
    counter.push_back(0);
    counter.push_back(0);
    counter.push_back(1);

    size_t key_length = out.size();
    out.resize(0);
    for (size_t i = 0; i < key_length;) {
        std::vector<uint8_t> temp;
        if (!digest_openssl(temp, digest_algorithm, counter, key, info))
            return false;

        out.insert(out.end(), temp.begin(), temp.end());
        i += digest_length(digest_algorithm);

        counter[3]++;
    }

    out.resize(key_length);
    return true;
}

bool SaKeyBase::cmac_kdf(
        std::vector<uint8_t>& out,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& other_data,
        uint8_t counter) {
    size_t key_length = out.size();
    if ((key_length / SYM_128_KEY_SIZE) > static_cast<size_t>(5 - counter))
        return false;

    if ((key.size() != SYM_128_KEY_SIZE) && (key.size() != SYM_256_KEY_SIZE))
        return false;

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    auto evp_mac = std::shared_ptr<EVP_MAC>(EVP_MAC_fetch(nullptr, "cmac", nullptr), EVP_MAC_free);
    if (evp_mac == nullptr) {
        ERROR("EVP_MAC_fetch failed");
        return false;
    }

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("cipher",
                    const_cast<char*>((key_length == SYM_128_KEY_SIZE) ? "aes-128-cbc" : "aes-256-cbc"), 0),
            OSSL_PARAM_construct_end()};

    std::vector<uint8_t> temp(AES_BLOCK_SIZE * 4);
    for (uint8_t i = 1; i <= 4; ++i) {
        auto evp_mac_ctx = std::shared_ptr<EVP_MAC_CTX>(EVP_MAC_CTX_new(evp_mac.get()), EVP_MAC_CTX_free);
        if (evp_mac_ctx == nullptr) {
            ERROR("EVP_MAC_CTX_new failed");
            return false;
        }

        if (EVP_MAC_init(evp_mac_ctx.get(), key.data(), key.size(), params) != 1) {
            ERROR("EVP_MAC_init failed");
            return false;
        }

        if (EVP_MAC_update(evp_mac_ctx.get(), &i, sizeof(i)) != 1) {
            ERROR("EVP_MAC_update failed");
            return false;
        }

        if (EVP_MAC_update(evp_mac_ctx.get(), other_data.data(), other_data.size()) != 1) {
            ERROR("EVP_MAC_update failed");
            return false;
        }

        size_t length = AES_BLOCK_SIZE;
        if (EVP_MAC_final(evp_mac_ctx.get(), temp.data() + ((i - 1) * AES_BLOCK_SIZE), &length, length) != 1) {
            ERROR("EVP_MAC_final failed");
            return false;
        }
    }
#else
    std::shared_ptr<CMAC_CTX> ctx(CMAC_CTX_new(), CMAC_CTX_free);
    if (ctx == nullptr)
        return false;

    const EVP_CIPHER* cipher = (key.size() == SYM_128_KEY_SIZE) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    std::vector<uint8_t> temp(AES_BLOCK_SIZE * 4);
    for (uint8_t i = 1; i <= 4; ++i) {
        if (CMAC_Init(ctx.get(), key.data(), key.size(), cipher, nullptr) != 1)
            return false;

        if (CMAC_Update(ctx.get(), &i, sizeof(i)) != 1)
            return false;

        if (CMAC_Update(ctx.get(), other_data.data(), other_data.size()) != 1)
            return false;

        size_t length;
        if (CMAC_Final(ctx.get(), temp.data() + ((i - 1) * AES_BLOCK_SIZE), &length) != 1)
            return false;
    }
#endif

    memcpy(out.data(), temp.data() + ((counter - 1) * AES_BLOCK_SIZE), key_length);
    return true;
}

bool SaKeyBase::netflix_wrapping_key_kdf(
        std::vector<uint8_t>& out,
        const std::vector<uint8_t>& encryption_key,
        const std::vector<uint8_t>& hmac_key) {
    std::vector<uint8_t> salt({0x02, 0x76, 0x17, 0x98, 0x4f, 0x62, 0x27, 0x53,
            0x9a, 0x63, 0x0b, 0x89, 0x7c, 0x01, 0x7d, 0x69});
    std::vector<uint8_t> info({0x80, 0x9f, 0x82, 0xa7, 0xad, 0xdf, 0x54, 0x8d,
            0x3e, 0xa9, 0xdd, 0x06, 0x7f, 0xf9, 0xbb, 0x91});

    std::vector<uint8_t> temp_key;
    std::vector<uint8_t> temp_data;
    temp_data.insert(temp_data.end(), encryption_key.begin(), encryption_key.end());
    temp_data.insert(temp_data.end(), hmac_key.begin(), hmac_key.end());
    if (!hmac_openssl(temp_key, salt, temp_data, SA_DIGEST_ALGORITHM_SHA256))
        return false;

    if (!hmac_openssl(out, temp_key, info, SA_DIGEST_ALGORITHM_SHA256))
        return false;

    out.resize(AES_BLOCK_SIZE);
    return true;
}

std::string SaKeyBase::b64_encode(
        const void* in,
        size_t in_length) {

    if (in == nullptr) {
        ERROR("NULL in");
        throw;
    }

    std::shared_ptr<BIO> b64(BIO_new(BIO_f_base64()), BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* sink = BIO_new(BIO_s_mem());
    if (sink == nullptr) {
        ERROR("BIO_new failed");
        throw;
    }

    BIO_push(b64.get(), sink);

    if (BIO_write(b64.get(), in, static_cast<int>(in_length)) < 0) {
        ERROR("BIO_write failed");
        throw;
    }

    if (BIO_flush(b64.get()) < 0) {
        ERROR("BIO_flush failed");
        throw;
    }

    char* encoded;
    const size_t len = BIO_get_mem_data(sink, &encoded); // NOLINT

    return {encoded, len};
}

bool SaKeyBase::key_check(
        sa_key_type key_type,
        sa_key key,
        std::vector<uint8_t>& clear_key) {
    if (key_type == SA_KEY_TYPE_SYMMETRIC)
        return key_check_sym(key, clear_key);

    if (key_type == SA_KEY_TYPE_RSA)
        return key_check_rsa(key, clear_key);

    if (key_type == SA_KEY_TYPE_EC)
        return key_check_ec(key, clear_key);

    return true;
}

INSTANTIATE_TEST_SUITE_P(
        SaKeyExportTests,
        SaKeyExportTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_160_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_MAX_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED448),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_1024_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_2048_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_3072_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_4096_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_768_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_1024_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_1536_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_2048_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_3072_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_4096_BYTE_LENGTH)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyDigestTests,
        SaKeyDigestTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384, SA_DIGEST_ALGORITHM_SHA512)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyGenerateTests,
        SaKeyGenerateTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_160_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_MAX_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED448),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448),
                std::make_tuple(SA_KEY_TYPE_DH, DH_768_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_1024_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_1536_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_2048_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_3072_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_4096_BYTE_LENGTH)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyGetPublicTests,
        SaKeyGetPublicTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED448),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448),
                std::make_tuple(SA_KEY_TYPE_DH, DH_768_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_1024_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_1536_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_2048_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_3072_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_DH, DH_4096_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_1024_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_2048_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_3072_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_4096_BYTE_LENGTH)));
