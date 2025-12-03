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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_crypto_sign_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaCryptoSign, nominal) {
        auto signature_algorithm = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());
        auto digest_algorithm = std::get<2>(GetParam());
        auto mgf1_digest_algorithm = std::get<3>(GetParam());
        auto salt = std::get<4>(GetParam());
        auto precomputed_digest = std::get<5>(GetParam());

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_key;
        size_t signature_length;
        sa_elliptic_curve curve;
        void* sign_parameters;
        sa_sign_parameters_rsa_pss parameters_rsa_pss;
        sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
        sa_sign_parameters_ecdsa parameters_ecdsa;
        switch (signature_algorithm) {
            case SA_SIGNATURE_ALGORITHM_ECDSA: {
                curve = static_cast<sa_elliptic_curve>(key_length);
                key_length = ec_get_key_size(curve);
                signature_length = key_length * 2;
                parameters_ecdsa = {digest_algorithm, precomputed_digest};
                sign_parameters = &parameters_ecdsa;

                clear_key = ec_generate_key_bytes(curve);
                key = create_sa_key_ec(&rights, curve, clear_key);
                break;
            }
            case SA_SIGNATURE_ALGORITHM_EDDSA: {
                curve = static_cast<sa_elliptic_curve>(key_length);
                key_length = ec_get_key_size(curve);
                signature_length = key_length * 2;
                sign_parameters = nullptr;

                clear_key = ec_generate_key_bytes(curve);
                key = create_sa_key_ec(&rights, curve, clear_key);
                break;
            }
            case SA_SIGNATURE_ALGORITHM_RSA_PSS: {
                signature_length = key_length;
                parameters_rsa_pss = {digest_algorithm, mgf1_digest_algorithm, precomputed_digest, salt};
                sign_parameters = &parameters_rsa_pss;

                clear_key = get_rsa_private_key(key_length);
                key = create_sa_key_rsa(&rights, clear_key);
                break;
            }
            case SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15: {
                signature_length = key_length;
                parameters_rsa_pkcs1v15 = {digest_algorithm, precomputed_digest};
                sign_parameters = &parameters_rsa_pkcs1v15;

                clear_key = get_rsa_private_key(key_length);
                key = create_sa_key_rsa(&rights, clear_key);
                break;
            }
            default:
                FAIL();
        }

        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        size_t out_length = 0;
        sa_status status = sa_crypto_sign(nullptr, &out_length, signature_algorithm, *key, nullptr, 0, sign_parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, signature_length);

        auto in = random(25);
        std::vector<uint8_t> digested;
        if (precomputed_digest) {
            digest(digested, digest_algorithm, in, {}, {});
        }

        auto out = std::vector<uint8_t>(out_length);
        status = sa_crypto_sign(out.data(), &out_length, signature_algorithm, *key,
                precomputed_digest ? digested.data() : in.data(), precomputed_digest ? digested.size() : in.size(),
                sign_parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_OK);
        out.resize(out_length);

        // verify signature using OpenSSL
        switch (signature_algorithm) {
            case SA_SIGNATURE_ALGORITHM_ECDSA: {
                auto ec_key = ec_import_private(curve, clear_key);
                if (reinterpret_cast<uintptr_t>(ec_key.get()) == UNSUPPORTED_OPENSSL_KEY)
                    GTEST_SKIP() << "Unsupported curve";

                ASSERT_NE(ec_key, nullptr);
                ASSERT_TRUE(verify_ec_ecdsa_openssl(ec_key.get(), curve, digest_algorithm, in, out));
                break;
            }
            case SA_SIGNATURE_ALGORITHM_EDDSA: {
                auto ec_key = ec_import_private(curve, clear_key);
                if (reinterpret_cast<uintptr_t>(ec_key.get()) == UNSUPPORTED_OPENSSL_KEY)
                    GTEST_SKIP() << "Unsupported curve";

                ASSERT_NE(ec_key, nullptr);
                ASSERT_TRUE(verify_ec_eddsa_openssl(ec_key.get(), curve, in, out));
                break;
            }
            case SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15: {
                auto rsa_key = rsa_import_pkcs8(clear_key);
                ASSERT_NE(rsa_key, nullptr);
                ASSERT_TRUE(verify_rsa_pkcs1v15_openssl(rsa_key, digest_algorithm, in, out));
                break;
            }
            case SA_SIGNATURE_ALGORITHM_RSA_PSS: {
                auto rsa_key = rsa_import_pkcs8(clear_key);
                ASSERT_NE(rsa_key, nullptr);
                ASSERT_TRUE(verify_rsa_pss_openssl(rsa_key, digest_algorithm, parameters_rsa_pss.mgf1_digest_algorithm,
                        parameters_rsa_pss.salt_length, in, out));
            }
        }
    }

    TEST(SaCryptoSign, failsNullOutLength) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        auto in = random(25);

        sa_sign_parameters_rsa_pss parameters = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, false, 20};
        sa_status const status = sa_crypto_sign(out.data(), nullptr, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, in.data(),
                in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST(SaCryptoSign, failsInvalidSignatureAlgorithm) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);

        sa_sign_parameters_rsa_pss parameters = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, false, 20};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, static_cast<sa_signature_algorithm>(UINT8_MAX),
                *key, in.data(), in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaCryptoSign, failsInvalidDigestAlgorithm) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);

        sa_sign_parameters_rsa_pss parameters =
                {static_cast<sa_digest_algorithm>(UINT8_MAX), SA_DIGEST_ALGORITHM_SHA1, false, 20};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key,
                in.data(), in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaCryptoSign, failsInvalidMgf1DigestAlgorithm) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);

        sa_sign_parameters_rsa_pss parameters = {SA_DIGEST_ALGORITHM_SHA1, static_cast<sa_digest_algorithm>(UINT8_MAX),
                false, 20};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key,
                in.data(), in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaCryptoSign, failsInvalidKey) {
        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);

        sa_sign_parameters_rsa_pss parameters = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, false, 20};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, INVALID_HANDLE,
                in.data(), in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaCryptoSign, failsNotUsageFlagEcEcdsaSha256Ecp256) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto clear_key = ec_generate_key_bytes(curve);
        sa_digest_algorithm const digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SIGN);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);
        sa_sign_parameters_ecdsa parameters = {digest_algorithm, false};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_ECDSA, *key, in.data(),
                in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST(SaCryptoSign, failsNotUsageFlagEcEcdsaSha256Ecp384) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P384;
        auto clear_key = ec_generate_key_bytes(curve);
        sa_digest_algorithm const digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SIGN);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);
        sa_sign_parameters_ecdsa parameters = {digest_algorithm, false};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_ECDSA, *key, in.data(),
                in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST(SaCryptoSign, failsNotUsageFlagEcEcdsaSha256Ecp521) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P521;
        auto clear_key = ec_generate_key_bytes(curve);
        sa_digest_algorithm const digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SIGN);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        auto in = random(25);
        sa_sign_parameters_ecdsa parameters = {digest_algorithm, false};
        sa_status const status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_ECDSA, *key, in.data(),
                in.size(), &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST(SaCryptoSign, failsNullIn) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(4096);

        sa_sign_parameters_rsa_pss parameters = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, false, 20};
        sa_status const status = sa_crypto_sign(out.data(), nullptr, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, nullptr, 1,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Unsupported signature algorithm";

        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
