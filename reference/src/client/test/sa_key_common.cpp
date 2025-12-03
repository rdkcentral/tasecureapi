/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

#include "common.h"
#include "digest_mechanism.h"
#include "root_keystore.h"
#include <cstring>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/hmac.h>
#else
#include <openssl/kdf.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "client_test_helpers.h"
#include "digest_util.h"
#include "pkcs12.h"

#include "pkcs12_mbedtls.h"

#include "sa_key_common.h"

using namespace client_test_helpers;

std::vector<uint8_t> SaKeyBase::root_key;

std::vector<uint8_t> SaKeyBase::common_root_key;

bool SaKeyBase::get_root_key(std::vector<uint8_t>& key) {
    bool status;
    if (root_key.empty()) {
        char name[MAX_NAME_SIZE];
        size_t name_length = MAX_NAME_SIZE;
        name[0] = '\0';
        root_key.resize(SYM_256_KEY_SIZE);
        size_t key_length = SYM_256_KEY_SIZE;

        if (!load_pkcs12_secret_key_mbedtls(root_key.data(), &key_length, name, &name_length)) {
            ERROR("load_pkcs12_secret_key_mbedtls failed");
            return false;
        }
        root_key.resize(key_length);
        status = true;
    } else {
        status = true;
    }

    key = root_key;
    return status;
}

bool SaKeyBase::get_common_root_key(std::vector<uint8_t>& key) {
    if (common_root_key.empty()) {
        char name[MAX_NAME_SIZE];
        size_t name_length = MAX_NAME_SIZE;
        strcpy(name, COMMON_ROOT_NAME);
        common_root_key.resize(SYM_256_KEY_SIZE);
        size_t key_length = SYM_256_KEY_SIZE;

        if (!load_pkcs12_secret_key_mbedtls(common_root_key.data(), &key_length, name, &name_length)) {
            ERROR("load_pkcs12_secret_key_mbedtls failed");
            return false;
        }

        common_root_key.resize(key_length);
    }

    key = common_root_key;
    return true;
}

bool SaKeyBase::dh_generate_key(
        std::shared_ptr<EVP_PKEY>& evp_pkey,
        std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& p,
        const std::vector<uint8_t>& g) {

#if OPENSSL_VERSION_NUMBER >= 0x30000000
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
#else
    auto dh = std::shared_ptr<DH>(DH_new(), DH_free);
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

    dh->length = static_cast<long>(p.size()) * 8; // NOLINT
#else
    BIGNUM* bnp = BN_bin2bn(p.data(), static_cast<int>(p.size()), nullptr);
    BIGNUM* bng = BN_bin2bn(g.data(), static_cast<int>(g.size()), nullptr);
    DH_set0_pqg(dh.get(), bnp, nullptr, bng);
#endif
    if (DH_generate_key(dh.get()) == 0) {
        ERROR("DH_generate_key failed");
        return false;
    }

    evp_pkey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
    if (EVP_PKEY_set1_DH(evp_pkey.get(), dh.get()) != 1) {
        ERROR("EVP_PKEY_generate failed");
        return false;
    }

#endif
    int length = i2d_PUBKEY(evp_pkey.get(), nullptr);
    if (length <= 0) {
        ERROR("i2d_PUBKEY failed");
        return false;
    }

    public_key.resize(length);
    uint8_t* p_public_key = public_key.data();
    length = i2d_PUBKEY(evp_pkey.get(), &p_public_key);
    if (length <= 0) {
        ERROR("i2d_PUBKEY failed");
        return false;
    }

    return true;
}

bool SaKeyBase::dh_compute_secret(
        std::vector<uint8_t>& shared_secret,
        const std::shared_ptr<EVP_PKEY>& private_key,
        const std::shared_ptr<EVP_PKEY>& other_public_key) {

    auto evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(private_key.get(), nullptr), EVP_PKEY_CTX_free);
    if (evp_pkey_ctx == nullptr) {
        ERROR("EVP_PKEY_CTX_new failed");
        return false;
    }

    if (EVP_PKEY_derive_init(evp_pkey_ctx.get()) != 1) {
        ERROR("EVP_PKEY_derive_init failed");
        return false;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    if (EVP_PKEY_CTX_set_dh_pad(evp_pkey_ctx.get(), 1) != 1) {
        ERROR("EVP_PKEY_CTX_set_dh_pad failed");
        return false;
    }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    // Don't validate the peer because it is an engine key.
    if (EVP_PKEY_derive_set_peer_ex(evp_pkey_ctx.get(), other_public_key.get(), 0) != 1) {
        ERROR("EVP_PKEY_derive_set_peer_ex failed");
        return false;
    }
#else
    if (EVP_PKEY_derive_set_peer(evp_pkey_ctx.get(), other_public_key.get()) != 1) {
        ERROR("EVP_PKEY_derive_set_peer failed");
        return false;
    }
#endif

    size_t shared_secret_size = 0;
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), nullptr, &shared_secret_size) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

    shared_secret.resize(shared_secret_size);
    size_t written = shared_secret_size;
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), shared_secret.data(), &written) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000
    if (written < shared_secret_size) {
        memmove(shared_secret.data() + shared_secret_size - written, shared_secret.data(), written);
        memset(shared_secret.data(), 0, shared_secret_size - written);
    }
#endif

    return true;
}

sa_status SaKeyBase::ec_generate_key(
        sa_elliptic_curve curve,
        std::shared_ptr<EVP_PKEY>& private_key,
        std::vector<uint8_t>& public_key) {

    auto private_key_bytes = ec_generate_key_bytes(curve);
    if (private_key_bytes.empty()) {
        ERROR("ec_generate_key_bytes failed");
        return SA_STATUS_OPERATION_NOT_SUPPORTED;
    }

    private_key = ec_import_private(curve, private_key_bytes);
    if (private_key == nullptr) {
        ERROR("ec_import_private failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    int length = i2d_PUBKEY(private_key.get(), nullptr);
    if (length <= 0) {
        ERROR("i2d_PUBKEY failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    public_key.resize(length);
    uint8_t* p_public_key = public_key.data();
    length = i2d_PUBKEY(private_key.get(), &p_public_key);
    if (length <= 0) {
        ERROR("i2d_PUBKEY failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

bool SaKeyBase::ecdh_compute_secret(
        std::vector<uint8_t>& shared_secret,
        const std::shared_ptr<EVP_PKEY>& private_key,
        const std::shared_ptr<EVP_PKEY>& other_public_key) {

    auto evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(private_key.get(), nullptr), EVP_PKEY_CTX_free);
    if (evp_pkey_ctx == nullptr) {
        ERROR("EVP_PKEY_CTX_new failed");
        return false;
    }

    if (EVP_PKEY_derive_init(evp_pkey_ctx.get()) != 1) {
        ERROR("EVP_PKEY_derive_init failed");
        return false;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    // Don't validate the peer because it is an engine key.
    if (EVP_PKEY_derive_set_peer_ex(evp_pkey_ctx.get(), other_public_key.get(), 0) != 1) {
        ERROR("EVP_PKEY_derive_set_peer_ex failed");
        return false;
    }
#else
    if (EVP_PKEY_derive_set_peer(evp_pkey_ctx.get(), other_public_key.get()) != 1) {
        ERROR("EVP_PKEY_derive_set_peer failed");
        return false;
    }
#endif

    size_t shared_secret_length = 0;
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), nullptr, &shared_secret_length) != 1) {
        ERROR("EVP_PKEY_derive failed");
        return false;
    }

    shared_secret.resize(shared_secret_length);
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), shared_secret.data(), &shared_secret_length) != 1) {
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
    sa_rights_set_allow_all(&rights);

    sa_generate_parameters_dh parameters = {
            .p = dhp.data(),
            .p_length = dhp.size(),
            .g = dhg.data(),
            .g_length = dhg.size()};
    if (sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters) != SA_STATUS_OK)
        return false;

    EVP_PKEY* temp = sa_get_public_key(*key);
    if (temp == nullptr) {
        ERROR("sa_get_public_key failed");
        return false;
    }

    auto public_evp_pkey = std::shared_ptr<EVP_PKEY>(temp, EVP_PKEY_free);

    //create other side info
    std::shared_ptr<EVP_PKEY> other_private_key;
    std::vector<uint8_t> other_public_key;
    if (!dh_generate_key(other_private_key, other_public_key, dhp, dhg)) {
        ERROR("dh_generate_key failed");
        return false;
    }

    if (sa_key_exchange(shared_secret.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *key,
                other_public_key.data(), other_public_key.size(), nullptr) != SA_STATUS_OK) {
        ERROR("sa_key_exchange failed");
        return false;
    }

    if (!dh_compute_secret(clear_shared_secret, other_private_key, public_evp_pkey)) {
        ERROR("dh_compute_secret failed");
        return false;
    }

    return true;
}

sa_status SaKeyBase::execute_ecdh(
        sa_elliptic_curve curve,
        std::shared_ptr<sa_key>& shared_secret,
        std::vector<uint8_t>& clear_shared_secret) {
    auto other_private_key = create_uninitialized_sa_key();

    sa_rights rights;
    sa_rights_set_allow_all(&rights);

    sa_generate_parameters_ec parameters = {curve};
    sa_status status = sa_key_generate(other_private_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
    if (status != SA_STATUS_OK)
        return status;

    std::shared_ptr<EVP_PKEY> const other_public_key(sa_get_public_key(*other_private_key), EVP_PKEY_free);
    if (other_public_key == nullptr) {
        ERROR("other_public_key failed");
        return status;
    }

    std::shared_ptr<EVP_PKEY> private_key;
    std::vector<uint8_t> public_key;
    status = ec_generate_key(curve, private_key, public_key);
    if (status != SA_STATUS_OK) {
        ERROR("ec_generate_key_bytes failed");
        return status;
    }

    status = sa_key_exchange(shared_secret.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *other_private_key,
            public_key.data(), public_key.size(), nullptr);
    if (status != SA_STATUS_OK) {
        ERROR("sa_key_exchange failed");
        return status;
    }

    /* Derive the shared secret */
    if (!ecdh_compute_secret(clear_shared_secret, private_key, other_public_key)) {
        ERROR("ecdh_compute_secret failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return status;
}

std::shared_ptr<std::vector<uint8_t>> SaKeyBase::derive_test_key_ladder(
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3,
        std::vector<uint8_t>& c4) {

    std::vector<uint8_t> stage1(SYM_128_KEY_SIZE);
    if (!decrypt_aes_ecb_openssl(stage1, c1, key, false))
        return nullptr;

    std::vector<uint8_t> stage2(SYM_128_KEY_SIZE);
    if (!decrypt_aes_ecb_openssl(stage2, c2, stage1, false))
        return nullptr;

    std::vector<uint8_t> stage3(SYM_128_KEY_SIZE);
    if (!decrypt_aes_ecb_openssl(stage3, c3, stage2, false))
        return nullptr;

    std::shared_ptr<std::vector<uint8_t>> stage4(new std::vector<uint8_t>(SYM_128_KEY_SIZE),
            [](std::vector<uint8_t>* p) { delete p; });
    if (c4.empty())
        *stage4 = stage3;
    else if (!decrypt_aes_ecb_openssl(*stage4, c4, stage3, false))
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
    size_t const digest_size = digest_length(digest_algorithm);
    size_t const out_len = out.size();
    size_t const r = out_len / digest_size + ((out_len % digest_size == 0) ? 0 : 1);
    size_t i;

    uint8_t t[SHA512_DIGEST_LENGTH];
    unsigned int t_len = 0;

    for (i = 1; i <= r; i++) {
        uint8_t const loop = i;
        size_t cp_len;

        if (i == r) {
            size_t const mod = out_len % digest_size;
            cp_len = (mod == 0) ? digest_size : mod;
        } else {
            cp_len = digest_size;
        }

        std::shared_ptr<HMAC_CTX> const ctx(new HMAC_CTX(),
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
    std::shared_ptr<EVP_PKEY_CTX> const pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);

    if (EVP_PKEY_derive_init(pctx.get()) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ERROR("EVP_PKEY_derive_init failed: %s", buf);
        return false;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx.get(), digest_mechanism(digest_algorithm)) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ERROR("EVP_PKEY_CTX_set_hkdf_md failed: %s", buf);
        return false;
    }

    const unsigned char default_zero = 0;
    const unsigned char* salt_ptr = salt.empty() ? &default_zero : salt.data();
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt_ptr, static_cast<int>(salt.size())) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ERROR("EVP_PKEY_CTX_set1_hkdf_salt failed: %s", buf);
        return false;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), key.data(), static_cast<int>(key.size())) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ERROR("EVP_PKEY_CTX_set1_hkdf_key failed: %s", buf);
        return false;
    }

    const unsigned char* info_ptr = info.empty() ? &default_zero : info.data();
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info_ptr, static_cast<int>(info.size())) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ERROR("EVP_PKEY_CTX_add1_hkdf_info failed: %s", buf);
        return false;
    }

    size_t length = out.size();
    if (EVP_PKEY_derive(pctx.get(), out.data(), &length) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ERROR("EVP_PKEY_derive failed: %s", buf);
        return false;
    }

    return true;
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

    size_t const key_length = out.size();
    out.resize(0);
    for (size_t i = 0; i < key_length;) {
        std::vector<uint8_t> temp;
        if (!digest(temp, digest_algorithm, key, counter, info))
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

    size_t const key_length = out.size();
    out.resize(0);
    for (size_t i = 0; i < key_length;) {
        std::vector<uint8_t> temp;
        if (!digest(temp, digest_algorithm, counter, key, info))
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
    size_t const key_length = out.size();
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

    std::vector<uint8_t> temp(static_cast<size_t>(AES_BLOCK_SIZE) * 4);
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
        if (EVP_MAC_final(evp_mac_ctx.get(), temp.data() + (static_cast<ptrdiff_t>(i - 1) * AES_BLOCK_SIZE), &length,
                    length) != 1) {
            ERROR("EVP_MAC_final failed");
            return false;
        }
    }
#else
    std::shared_ptr<CMAC_CTX> const ctx(CMAC_CTX_new(), CMAC_CTX_free);
    if (ctx == nullptr)
        return false;

    const EVP_CIPHER* cipher = (key.size() == SYM_128_KEY_SIZE) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    std::vector<uint8_t> temp(static_cast<size_t>(AES_BLOCK_SIZE) * 4);
    for (uint8_t i = 1; i <= 4; ++i) {
        if (CMAC_Init(ctx.get(), key.data(), key.size(), cipher, nullptr) != 1)
            return false;

        if (CMAC_Update(ctx.get(), &i, sizeof(i)) != 1)
            return false;

        if (CMAC_Update(ctx.get(), other_data.data(), other_data.size()) != 1)
            return false;

        size_t length;
        if (CMAC_Final(ctx.get(), temp.data() + (static_cast<ptrdiff_t>(i - 1) * AES_BLOCK_SIZE), &length) != 1)
            return false;
    }
#endif

    memcpy(out.data(), temp.data() + (static_cast<ptrdiff_t>(counter - 1) * AES_BLOCK_SIZE), key_length);
    return true;
}

bool SaKeyBase::netflix_wrapping_key_kdf(
        std::vector<uint8_t>& out,
        const std::vector<uint8_t>& encryption_key,
        const std::vector<uint8_t>& hmac_key) {
    std::vector<uint8_t> const salt({0x02, 0x76, 0x17, 0x98, 0x4f, 0x62, 0x27, 0x53,
            0x9a, 0x63, 0x0b, 0x89, 0x7c, 0x01, 0x7d, 0x69});
    std::vector<uint8_t> const info({0x80, 0x9f, 0x82, 0xa7, 0xad, 0xdf, 0x54, 0x8d,
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
        size_t in_length,
        bool url_encode) {

    if (in == nullptr) {
        ERROR("NULL in");
        throw;
    }

    std::shared_ptr<BIO> const b64(BIO_new(BIO_f_base64()), BIO_free_all);
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
    size_t length = BIO_get_mem_data(sink, &encoded); // NOLINT

    if (url_encode) {
        size_t pad = 0;
        for (size_t i = 0; i < length; i++) {
            if (encoded[i] == '+')
                encoded[i] = '-';
            else if (encoded[i] == '/')
                encoded[i] = '_';
            else if (encoded[i] == '=')
                pad++;
        }

        length -= pad;
    }

    return {encoded, length};
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

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaKeyExportTests,
        SaKeyExportTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_160_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_MAX_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P192),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P224),
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
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyGenerateTests,
        SaKeyGenerateTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_160_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_MAX_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P192),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P224),
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

INSTANTIATE_TEST_SUITE_P(
        SaKeyGetPublicTests,
        SaKeyGetPublicTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P192),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P224),
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

// clang-format on
