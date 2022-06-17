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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_unwrap_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyUnwrapEcTest, failsNullKey) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        ASSERT_TRUE(wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                key_size, clear_key, SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0));

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status status = sa_key_unwrap(nullptr, &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, wrapping_parameters.get(), *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failsNullRights) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        ASSERT_TRUE(wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                key_size, clear_key, SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0));

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), nullptr, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, wrapping_parameters.get(), *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failsNotSymmetric) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        ASSERT_TRUE(wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                key_size, clear_key, SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0));

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_RSA, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, wrapping_parameters.get(), *wrapping_key,
                nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failsNullAlgorithmParameters) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        ASSERT_TRUE(wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                key_size, clear_key, SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0));

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, nullptr, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failsNullIn) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        ASSERT_TRUE(wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                key_size, clear_key, SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0));

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, wrapping_parameters.get(), *wrapping_key,
                nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failsUnknownWrappingKey) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        ASSERT_TRUE(wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                key_size, clear_key, SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0));

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, wrapping_parameters.get(), INVALID_HANDLE,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failsWrappingKeyDisallowsUnwrap) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> wrapped_key = random(key_size * 4);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        SA_USAGE_BIT_CLEAR(wrapping_key_rights.usage_flags, SA_USAGE_FLAG_UNWRAP);
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&wrapping_key_rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 0,
                .key_length = SYM_128_KEY_SIZE};
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyUnwrapEcTest, failsWrappingKeyOutsideValidTimeBefore) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> wrapped_key = random(key_size * 4);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        wrapping_key_rights.not_before = time(nullptr) + 60;
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&wrapping_key_rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 0,
                .key_length = SYM_128_KEY_SIZE};
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyUnwrapEcTest, failsWrappingKeyOutsideValidTimeAfter) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> wrapped_key = random(key_size * 4);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        wrapping_key_rights.not_on_or_after = time(nullptr) - 60;
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&wrapping_key_rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 0,
                .key_length = SYM_128_KEY_SIZE};
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyUnwrapEcTest, failsWrappingKeyNotEc) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto key_size = ec_get_key_size(curve);
        std::vector<uint8_t> wrapped_key = random(key_size * 4);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 0,
                .key_length = SYM_128_KEY_SIZE};
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_F(SaKeyUnwrapEcTest, failInvalidKeyLength) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 0,
                .key_length = SYM_128_KEY_SIZE - 1};
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failInvalidOffsetKeyLength) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 17,
                .key_length = SYM_128_KEY_SIZE};
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyUnwrapEcTest, failInvalidInLength) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        sa_unwrap_parameters_ec_elgamal unwrap_parameters_ec_elgamal = {
                .offset = 0,
                .key_length = SYM_128_KEY_SIZE};
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_EC_ELGAMAL, &unwrap_parameters_ec_elgamal, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
