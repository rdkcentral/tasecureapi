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

#include "sa_key_unwrap_common.h" // NOLINT
#include "client_test_helpers.h"
#include <openssl/evp.h>

using namespace client_test_helpers;

bool SaKeyUnwrapBase::wrap_key(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm wrapping_algorithm,
        sa_digest_algorithm oaep_digest_algorithm,
        sa_digest_algorithm oaep_mgf1_digest_algorithm,
        size_t oaep_label_length) {

    switch (wrapping_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            return wrap_key_aes_cbc(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key, wrapping_algorithm);

        case SA_CIPHER_ALGORITHM_AES_ECB:
        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            return wrap_key_aes_ecb(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key, wrapping_algorithm);

        case SA_CIPHER_ALGORITHM_AES_CTR:
            return wrap_key_aes_ctr(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key);

        case SA_CIPHER_ALGORITHM_AES_GCM:
            return wrap_key_aes_gcm(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key);

        case SA_CIPHER_ALGORITHM_CHACHA20:
            return wrap_key_chacha20(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key);

        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            return wrap_key_chacha20_poly1305(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key);

        case SA_CIPHER_ALGORITHM_RSA_PKCS1V15:
        case SA_CIPHER_ALGORITHM_RSA_OAEP:
            return wrap_key_rsa(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key, wrapping_algorithm, oaep_digest_algorithm,
                    oaep_mgf1_digest_algorithm, oaep_label_length);

        case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
            sa_elliptic_curve curve;
            if (wrapping_key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P192))
                curve = SA_ELLIPTIC_CURVE_NIST_P192;
            else if (wrapping_key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P224))
                curve = SA_ELLIPTIC_CURVE_NIST_P224;
            else if (wrapping_key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P256))
                curve = SA_ELLIPTIC_CURVE_NIST_P256;
            else if (wrapping_key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P384))
                curve = SA_ELLIPTIC_CURVE_NIST_P384;
            else if (wrapping_key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P521))
                curve = SA_ELLIPTIC_CURVE_NIST_P521;
            else
                return false;

            return wrap_key_el_gamal(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                    wrapping_key_size, clear_key, curve);

        default:
            return false;
    }
}

bool SaKeyUnwrapBase::wrap_key_aes_cbc(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm wrapping_algorithm) {

    sa_rights rights;
    rights_set_allow_all(&rights);

    clear_wrapping_key = random(wrapping_key_size);
    auto iv = random(AES_BLOCK_SIZE);
    if (!encrypt_aes_cbc_openssl(wrapped_key, clear_key, iv, clear_wrapping_key,
                wrapping_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7))
        return false;

    auto* unwrap_parameters_aes_cbc = new sa_unwrap_parameters_aes_cbc;
    unwrap_parameters_aes_cbc->iv = new uint8_t[iv.size()];
    unwrap_parameters_aes_cbc->iv_length = iv.size();
    memcpy(const_cast<void*>(unwrap_parameters_aes_cbc->iv), iv.data(), iv.size());
    auto deleter = [](sa_unwrap_parameters_aes_cbc* p) {
        if (p != nullptr) {
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->iv));
            delete p;
        }
    };

    wrapping_parameters = std::shared_ptr<sa_unwrap_parameters_aes_cbc>(unwrap_parameters_aes_cbc, deleter);

    wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_aes_ecb(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm wrapping_algorithm) {

    sa_rights rights;
    rights_set_allow_all(&rights);

    clear_wrapping_key = random(wrapping_key_size);
    if (!encrypt_aes_ecb_openssl(wrapped_key, clear_key, clear_wrapping_key,
                wrapping_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7))
        return false;

    wrapping_parameters = std::shared_ptr<void>();

    wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_aes_ctr(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key) {

    sa_rights rights;
    rights_set_allow_all(&rights);

    clear_wrapping_key = random(wrapping_key_size);
    auto ctr = random(AES_BLOCK_SIZE);
    if (!encrypt_aes_ctr_openssl(wrapped_key, clear_key, ctr, clear_wrapping_key))
        return false;

    auto* unwrap_parameters_aes_ctr = new sa_unwrap_parameters_aes_ctr;
    unwrap_parameters_aes_ctr->ctr = new uint8_t[ctr.size()];
    unwrap_parameters_aes_ctr->ctr_length = ctr.size();
    memcpy(const_cast<void*>(unwrap_parameters_aes_ctr->ctr), ctr.data(), ctr.size());
    auto deleter = [](sa_unwrap_parameters_aes_ctr* p) {
        if (p != nullptr) {
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->ctr));
            delete p;
        }
    };
    wrapping_parameters = std::shared_ptr<sa_unwrap_parameters_aes_ctr>(unwrap_parameters_aes_ctr, deleter);

    wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_aes_gcm(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key) {

    sa_rights rights;
    rights_set_allow_all(&rights);
    clear_wrapping_key = random(wrapping_key_size);
    auto iv = random(GCM_IV_LENGTH);
    auto aad = random(1024);
    std::vector<uint8_t> tag(AES_BLOCK_SIZE);
    if (!encrypt_aes_gcm_openssl(wrapped_key, clear_key, iv, aad, tag, clear_wrapping_key))
        return false;

    auto* unwrap_parameters_aes_gcm = new sa_unwrap_parameters_aes_gcm;
    unwrap_parameters_aes_gcm->iv = new uint8_t[iv.size()];
    unwrap_parameters_aes_gcm->iv_length = iv.size();
    memcpy(const_cast<void*>(unwrap_parameters_aes_gcm->iv), iv.data(), iv.size());
    unwrap_parameters_aes_gcm->aad = new uint8_t[aad.size()];
    unwrap_parameters_aes_gcm->aad_length = aad.size();
    memcpy(const_cast<void*>(unwrap_parameters_aes_gcm->aad), aad.data(), aad.size());
    unwrap_parameters_aes_gcm->tag = new uint8_t[tag.size()];
    unwrap_parameters_aes_gcm->tag_length = tag.size();
    memcpy(const_cast<void*>(unwrap_parameters_aes_gcm->tag), tag.data(), tag.size());
    auto deleter = [](sa_unwrap_parameters_aes_gcm* p) {
        if (p != nullptr) {
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->iv));
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->aad));
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->tag));
            delete p;
        }
    };
    wrapping_parameters = std::shared_ptr<sa_unwrap_parameters_aes_gcm>(unwrap_parameters_aes_gcm, deleter);

    wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_chacha20(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key) {

    sa_rights rights;
    rights_set_allow_all(&rights);

    clear_wrapping_key = random(wrapping_key_size);
    std::vector<uint8_t> counter = {0, 0, 0, 0};
    auto nonce = random(CHACHA20_NONCE_LENGTH);
    if (!encrypt_chacha20_openssl(wrapped_key, clear_key, counter, nonce, clear_wrapping_key))
        return false;

    auto* unwrap_parameters_chacha20 = new sa_unwrap_parameters_chacha20;
    unwrap_parameters_chacha20->counter = new uint8_t[counter.size()];
    unwrap_parameters_chacha20->counter_length = counter.size();
    memcpy(const_cast<void*>(unwrap_parameters_chacha20->counter), counter.data(), counter.size());
    unwrap_parameters_chacha20->nonce = new uint8_t[nonce.size()];
    unwrap_parameters_chacha20->nonce_length = nonce.size();
    memcpy(const_cast<void*>(unwrap_parameters_chacha20->nonce), nonce.data(), nonce.size());
    auto deleter = [](sa_unwrap_parameters_chacha20* p) {
        if (p != nullptr) {
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->counter));
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->nonce));
            delete p;
        }
    };
    wrapping_parameters = std::shared_ptr<sa_unwrap_parameters_chacha20>(unwrap_parameters_chacha20, deleter);

    wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_chacha20_poly1305(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key) {

    sa_rights rights;
    rights_set_allow_all(&rights);
    clear_wrapping_key = random(wrapping_key_size);
    auto nonce = random(CHACHA20_NONCE_LENGTH);
    auto aad = random(1024);
    std::vector<uint8_t> tag(AES_BLOCK_SIZE);
    if (!encrypt_chacha20_poly1305_openssl(wrapped_key, clear_key, nonce, aad, tag, clear_wrapping_key))
        return false;

    auto* unwrap_parameters_chacha20_poly1305 = new sa_unwrap_parameters_chacha20_poly1305;
    unwrap_parameters_chacha20_poly1305->nonce = new uint8_t[nonce.size()];
    unwrap_parameters_chacha20_poly1305->nonce_length = nonce.size();
    memcpy(const_cast<void*>(unwrap_parameters_chacha20_poly1305->nonce), nonce.data(), nonce.size());
    unwrap_parameters_chacha20_poly1305->aad = new uint8_t[aad.size()];
    unwrap_parameters_chacha20_poly1305->aad_length = aad.size();
    memcpy(const_cast<void*>(unwrap_parameters_chacha20_poly1305->aad), aad.data(), aad.size());
    unwrap_parameters_chacha20_poly1305->tag = new uint8_t[tag.size()];
    unwrap_parameters_chacha20_poly1305->tag_length = tag.size();
    memcpy(const_cast<void*>(unwrap_parameters_chacha20_poly1305->tag), tag.data(), tag.size());
    auto deleter = [](sa_unwrap_parameters_chacha20_poly1305* p) {
        if (p != nullptr) {
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->nonce));
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->aad));
            delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->tag));
            delete p;
        }
    };
    wrapping_parameters =
            std::shared_ptr<sa_unwrap_parameters_chacha20_poly1305>(unwrap_parameters_chacha20_poly1305, deleter);

    wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_rsa(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm wrapping_algorithm,
        sa_digest_algorithm digest_algorithm,
        sa_digest_algorithm mgf1_digest_algorithm,
        size_t label_length) {

    sa_rights rights;
    rights_set_allow_all(&rights);

    clear_wrapping_key = get_rsa_private_key(wrapping_key_size);
    auto rsa = rsa_import_pkcs8(clear_wrapping_key);

    if (wrapping_algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15) {
        wrapping_parameters = std::shared_ptr<void>();
        if (!encrypt_rsa_pkcs1v15_openssl(wrapped_key, clear_key, rsa))
            return false;
    } else {
        auto label = label_length != 0 ? random(label_length) : std::vector<uint8_t>(0);

        auto* unwrap_parameters_rsa_oaep = new sa_unwrap_parameters_rsa_oaep;
        unwrap_parameters_rsa_oaep->digest_algorithm = digest_algorithm;
        unwrap_parameters_rsa_oaep->mgf1_digest_algorithm = mgf1_digest_algorithm;
        unwrap_parameters_rsa_oaep->label = new uint8_t[label.size()];
        memcpy(unwrap_parameters_rsa_oaep->label, label.data(), label.size());
        unwrap_parameters_rsa_oaep->label_length = label.size();
        auto deleter = [](sa_unwrap_parameters_rsa_oaep* p) {
            if (p != nullptr) {
                delete[] const_cast<uint8_t*>(static_cast<const uint8_t*>(p->label));
                delete p;
            }
        };

        wrapping_parameters = std::shared_ptr<sa_unwrap_parameters_rsa_oaep>(unwrap_parameters_rsa_oaep, deleter);
        if (!encrypt_rsa_oaep_openssl(wrapped_key, clear_key, rsa, digest_algorithm, mgf1_digest_algorithm, label))
            return false;
    }

    wrapping_key = create_sa_key_rsa(&rights, clear_wrapping_key);
    return wrapping_key != nullptr;
}

bool SaKeyUnwrapBase::wrap_key_el_gamal(
        std::shared_ptr<sa_key>& wrapping_key,
        std::vector<uint8_t>& clear_wrapping_key,
        std::vector<uint8_t>& wrapped_key,
        std::shared_ptr<void>& wrapping_parameters,
        size_t wrapping_key_size,
        const std::vector<uint8_t>& clear_key,
        sa_elliptic_curve curve) {

    sa_rights rights;
    rights_set_allow_all(&rights);
    // Can only be used with AES_128 keys.
    if (clear_key.size() != SYM_128_KEY_SIZE)
        return false;

    clear_wrapping_key = random_ec(wrapping_key_size);

    auto ec_group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(ec_get_type(curve)), EC_GROUP_free);
    if (ec_group == nullptr) {
        ERROR("ec_group_from_curve failed");
        return false;
    }

    // Copy the key into temp beginning at offset. Leave the rest of the bytes unset. The last 4 bytes of temp
    // are used as a counter so we can make several tries to find a valid point.
    int64_t offset = 4;
    auto temp = random(wrapping_key_size);
    std::copy(clear_key.begin(), clear_key.end(), temp.begin() + offset);

    auto evp_pkey = ec_import_private(curve, clear_wrapping_key);
    if (evp_pkey == nullptr) {
        ERROR("ec_import_private failed");
        return false;
    }

    if (!encrypt_ec_elgamal_openssl(wrapped_key, temp, curve, evp_pkey))
        return false;

    auto* unwrap_parameters_ec_elgamal = new sa_unwrap_parameters_ec_elgamal;
    unwrap_parameters_ec_elgamal->offset = offset;
    unwrap_parameters_ec_elgamal->key_length = clear_key.size();

    wrapping_parameters = std::shared_ptr<sa_unwrap_parameters_ec_elgamal>(unwrap_parameters_ec_elgamal);

    wrapping_key = create_sa_key_ec(&rights, curve, clear_wrapping_key);
    return wrapping_key != nullptr;
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesAesCbcTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CBC, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaAesCbcTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_KEY_TYPE_RSA)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcAesCbcTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_ED25519,
                    SA_ELLIPTIC_CURVE_X25519),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CBC),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcAesCbcPkcs7Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224,
                    SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521,
                    SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_ED448,
                    SA_ELLIPTIC_CURVE_X448),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesAesEcbTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaAesEcbTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_KEY_TYPE_RSA)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcAesEcbTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_ED25519,
                    SA_ELLIPTIC_CURVE_X25519),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_ECB),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcAesEcbPkcs7Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224,
                    SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521,
                    SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_ED448,
                    SA_ELLIPTIC_CURVE_X448),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesAesCtrTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaAesCtrTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_KEY_TYPE_RSA)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcAesCtrTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224,
                    SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521,
                    SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_ED448,
                    SA_ELLIPTIC_CURVE_X448),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesAesGcmTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_GCM),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaAesGcmTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_KEY_TYPE_RSA)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_GCM),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcAesGcmTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224,
                    SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521,
                    SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_ED448,
                    SA_ELLIPTIC_CURVE_X448),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_GCM),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

#if OPENSSL_VERSION_NUMBER >= 0x10100000
INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesChacha20Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20),
                ::testing::Values(SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaChacha20Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_KEY_TYPE_RSA)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20),
                ::testing::Values(SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcChacha20Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224,
                    SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521,
                    SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_ED448,
                    SA_ELLIPTIC_CURVE_X448),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20),
                ::testing::Values(SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesChacha20Poly1305Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305),
                ::testing::Values(SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaChacha20Poly1305Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_KEY_TYPE_RSA)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305),
                ::testing::Values(SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcChacha20Poly1305Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224,
                    SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521,
                    SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_ED448,
                    SA_ELLIPTIC_CURVE_X448),
                ::testing::Values(SA_KEY_TYPE_EC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305),
                ::testing::Values(SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));
#endif

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesRsaPkcs1v15Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_RSA_PKCS1V15),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesRsaOaep1024Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_RSA_OAEP),
                ::testing::Values(RSA_1024_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesRsaOaep2048Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_RSA_OAEP),
                ::testing::Values(RSA_2048_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesRsaOaep3072Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_RSA_OAEP),
                ::testing::Values(RSA_3072_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesRsaOaep4096Tests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_RSA_OAEP),
                ::testing::Values(RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapEcTests,
        SaKeyUnwrapTest,
        ::testing::Combine(
            ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE),
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC)),
            ::testing::Combine(
                ::testing::Values(SA_CIPHER_ALGORITHM_EC_ELGAMAL),
                ::testing::Values(ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P192),
                    ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P224),
                    ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P256),
                    ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P384),
                    ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P521)),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0))));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapAesCbcTests,
        SaKeyUnwrapAesCbcTest,
        ::testing::Values(
            SA_CIPHER_ALGORITHM_AES_CBC,
            SA_CIPHER_ALGORITHM_AES_CBC_PKCS7));

INSTANTIATE_TEST_SUITE_P(
        SaKeyUnwrapRsaTests,
        SaKeyUnwrapRsaTest,
        ::testing::Values(
            SA_CIPHER_ALGORITHM_RSA_OAEP,
            SA_CIPHER_ALGORITHM_RSA_PKCS1V15));
// clang-format on
