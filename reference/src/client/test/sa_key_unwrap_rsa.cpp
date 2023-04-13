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

#include "sa.h" // NOLINT
#include "client_test_helpers.h"
#include "sa_key_unwrap_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyUnwrapRsaTest, failsNullKey) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> const clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                RSA_2048_BYTE_LENGTH, clear_key, cipher_algorithm, SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1,
                0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        status = sa_key_unwrap(nullptr, &rights, SA_KEY_TYPE_SYMMETRIC, nullptr, cipher_algorithm,
                wrapping_parameters.get(), *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsNullRights) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> const clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                RSA_2048_BYTE_LENGTH, clear_key, cipher_algorithm, SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1,
                0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), nullptr, SA_KEY_TYPE_SYMMETRIC, nullptr, cipher_algorithm,
                wrapping_parameters.get(), *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsNotSymmetric) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> const clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                RSA_2048_BYTE_LENGTH, clear_key, cipher_algorithm, SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1,
                0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_RSA, nullptr, cipher_algorithm,
                wrapping_parameters.get(), *wrapping_key, nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsNullIn) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> const clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                RSA_2048_BYTE_LENGTH, clear_key, cipher_algorithm, SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1,
                0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr, cipher_algorithm,
                wrapping_parameters.get(), *wrapping_key, nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsUnknownWrappingKey) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> const clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                RSA_2048_BYTE_LENGTH, clear_key, cipher_algorithm, SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1,
                0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr, cipher_algorithm,
                wrapping_parameters.get(), INVALID_HANDLE, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsWrappingKeyDisallowsUnwrap) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        SA_USAGE_BIT_CLEAR(wrapping_key_rights.usage_flags, SA_USAGE_FLAG_UNWRAP);
        std::vector<uint8_t> const clear_wrapping_key = get_rsa_private_key(RSA_2048_BYTE_LENGTH);
        std::shared_ptr<sa_key> const wrapping_key = create_sa_key_rsa(&wrapping_key_rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);
        if (*wrapping_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        void* parameters = nullptr;
        sa_unwrap_parameters_rsa_oaep parameters_rsa_oaep;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            parameters_rsa_oaep = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, nullptr, 0};
            parameters = &parameters_rsa_oaep;
        }

        sa_status const status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                cipher_algorithm, parameters, *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsWrappingKeyOutsideValidTimeBefore) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        wrapping_key_rights.not_before = time(nullptr) + 60;
        std::vector<uint8_t> const clear_wrapping_key = get_rsa_private_key(RSA_2048_BYTE_LENGTH);
        std::shared_ptr<sa_key> const wrapping_key = create_sa_key_rsa(&wrapping_key_rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);
        if (*wrapping_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        void* parameters = nullptr;
        sa_unwrap_parameters_rsa_oaep parameters_rsa_oaep;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            parameters_rsa_oaep = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, nullptr, 0};
            parameters = &parameters_rsa_oaep;
        }

        sa_status const status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                cipher_algorithm, parameters, *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsWrappingKeyOutsideValidTimeAfter) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        wrapping_key_rights.not_on_or_after = time(nullptr) - 60;
        std::vector<uint8_t> const clear_wrapping_key = get_rsa_private_key(RSA_2048_BYTE_LENGTH);
        std::shared_ptr<sa_key> const wrapping_key = create_sa_key_rsa(&wrapping_key_rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);
        if (*wrapping_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        void* parameters = nullptr;
        sa_unwrap_parameters_rsa_oaep parameters_rsa_oaep;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            parameters_rsa_oaep = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, nullptr, 0};
            parameters = &parameters_rsa_oaep;
        }

        sa_status const status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                cipher_algorithm, parameters, *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaKeyUnwrapRsaTest, failsWrappingKeyNotRsa) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> const clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> const wrapping_key = create_sa_key_ec(&rights, curve, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);
        if (*wrapping_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        void* parameters = nullptr;
        sa_unwrap_parameters_rsa_oaep parameters_rsa_oaep;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            parameters_rsa_oaep = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, nullptr, 0};
            parameters = &parameters_rsa_oaep;
        }

        sa_status const status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                cipher_algorithm, parameters, *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }

    TEST_P(SaKeyUnwrapRsaTest, failInvalidInLength) {
        auto cipher_algorithm = GetParam();
        std::vector<uint8_t> wrapped_key = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> const clear_wrapping_key = get_rsa_private_key(RSA_2048_BYTE_LENGTH);
        std::shared_ptr<sa_key> const wrapping_key = create_sa_key_rsa(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);
        if (*wrapping_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        void* parameters = nullptr;
        sa_unwrap_parameters_rsa_oaep parameters_rsa_oaep;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            parameters_rsa_oaep = {SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, nullptr, 0};
            parameters = &parameters_rsa_oaep;
        }

        sa_status const status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                cipher_algorithm, parameters, *wrapping_key, wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
