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
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsBadKeyType) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto clear_key = ec_generate_key_bytes(curve);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        std::vector<uint8_t> counter = {1, 0, 0, 0};
        auto nonce = random(CHACHA20_NONCE_LENGTH);
        sa_cipher_parameters_chacha20 parameters = {counter.data(), counter.size(), nonce.data(), nonce.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsNullParameters) {
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsBadKeySize) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        std::vector<uint8_t> counter = {1, 0, 0, 0};
        auto nonce = random(CHACHA20_NONCE_LENGTH);
        sa_cipher_parameters_chacha20 parameters = {counter.data(), counter.size(), nonce.data(), nonce.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsNullNonce) {
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        std::vector<uint8_t> counter = {1, 0, 0, 0};
        sa_cipher_parameters_chacha20 parameters = {counter.data(), counter.size(), nullptr, CHACHA20_NONCE_LENGTH};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsBadNonceLength) {
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        std::vector<uint8_t> counter = {1, 0, 0, 0};
        auto nonce = random(CHACHA20_NONCE_LENGTH + 1);
        sa_cipher_parameters_chacha20 parameters = {counter.data(), counter.size(), nonce.data(), nonce.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsNullCounter) {
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        std::vector<uint8_t> counter = {1, 0, 0, 0};
        auto nonce = random(CHACHA20_NONCE_LENGTH);
        sa_cipher_parameters_chacha20 parameters = {nullptr, counter.size(), nonce.data(), nonce.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initChacha20FailsBadCounterLength) {
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        std::vector<uint8_t> counter = {1, 0, 0, 0, 0};
        auto nonce = random(CHACHA20_NONCE_LENGTH + 1);
        sa_cipher_parameters_chacha20 parameters = {counter.data(), counter.size(), nonce.data(), nonce.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20, SA_CIPHER_MODE_ENCRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
