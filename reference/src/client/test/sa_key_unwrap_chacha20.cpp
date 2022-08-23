/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000
#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_unwrap_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyUnwrapChacha20Test, failsNullKey) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                SYM_256_KEY_SIZE, clear_key, SA_CIPHER_ALGORITHM_CHACHA20, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        status = sa_key_unwrap(nullptr, &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, wrapping_parameters.get(), *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsNullRights) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                SYM_256_KEY_SIZE, clear_key, SA_CIPHER_ALGORITHM_CHACHA20, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), nullptr, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, wrapping_parameters.get(), *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsNullIn) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                SYM_256_KEY_SIZE, clear_key, SA_CIPHER_ALGORITHM_CHACHA20, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, wrapping_parameters.get(), *wrapping_key,
                nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsNullAlgorithmParameters) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                SYM_256_KEY_SIZE, clear_key, SA_CIPHER_ALGORITHM_CHACHA20, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, nullptr, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsNullCounter) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = nullptr,
                .counter_length = 0,
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsNullNonce) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nullptr,
                .nonce_length = 0};

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsInvalidCounter) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsInvalidNonce) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH - 1);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsUnknownWrappingKey) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                SYM_256_KEY_SIZE, clear_key, SA_CIPHER_ALGORITHM_CHACHA20, SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA1, 0);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, wrapping_parameters.get(), INVALID_HANDLE,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsWrappingKeyDisallowsUnwrap) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        SA_USAGE_BIT_CLEAR(wrapping_key_rights.usage_flags, SA_USAGE_FLAG_UNWRAP);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&wrapping_key_rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsWrappingKeyOutsideValidTimeBefore) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        wrapping_key_rights.not_before = time(nullptr) + 60;
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&wrapping_key_rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsWrappingKeyOutsideValidTimeAfter) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights wrapping_key_rights;
        sa_rights_set_allow_all(&wrapping_key_rights);
        wrapping_key_rights.not_on_or_after = time(nullptr) - 60;
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&wrapping_key_rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsWrappingKeyNotAes) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = ec_generate_key_bytes(curve);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_ec(&rights, curve,
                clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);
        if (*wrapping_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }

    TEST_F(SaKeyUnwrapChacha20Test, failsWrappingKeyNotValidAesSize) {
        std::vector<uint8_t> wrapped_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_256_KEY_SIZE + 1);
        std::shared_ptr<sa_key> wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        std::vector<uint8_t> counter = {0, 0, 0, 0};
        std::vector<uint8_t> nonce = random(CHACHA20_NONCE_LENGTH);
        sa_unwrap_parameters_chacha20 unwrap_parameters_chacha20 = {
                .counter = counter.data(),
                .counter_length = counter.size(),
                .nonce = nonce.data(),
                .nonce_length = nonce.size()};

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);
        sa_status status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                SA_CIPHER_ALGORITHM_CHACHA20, &unwrap_parameters_chacha20, *wrapping_key,
                wrapped_key.data(), wrapped_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }
} // namespace
#endif
