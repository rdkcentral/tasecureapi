/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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
#ifndef DISABLE_SVP
#include "sa.h"
#include "ta_sa_svp_common.h"
#include "ta_test_helpers.h"
#include "gtest/gtest.h"

using namespace ta_test_helpers;

namespace {
    TEST_F(TaSvpKeyCheckTest, nominal) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = encrypt_openssl(SA_CIPHER_ALGORITHM_AES_ECB, clear, {}, clear_key);
        ASSERT_FALSE(encrypted.empty());

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(ta_sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size(), client(),
                          ta_uuid()),
                SA_STATUS_OK);
    }

    TEST_F(TaSvpKeyCheckTest, nominalSvp) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = encrypt_openssl(SA_CIPHER_ALGORITHM_AES_ECB, clear, {}, clear_key);
        ASSERT_FALSE(encrypted.empty());

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(ta_sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size(), client(),
                          ta_uuid()),
                SA_STATUS_OK);
    }

    TEST_F(TaSvpKeyCheckTest, failKeyCheck) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, clear);
        ASSERT_EQ(ta_sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size(), client(),
                          ta_uuid()),
                SA_STATUS_VERIFICATION_FAILED);
    }

    TEST_F(TaSvpKeyCheckTest, failNullIn) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        ASSERT_EQ(ta_sa_svp_key_check(*key, nullptr, clear.size(), clear.data(), clear.size(), client(),
                          ta_uuid()),
                SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(TaSvpKeyCheckTest, failNullExpected) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = encrypt_openssl(SA_CIPHER_ALGORITHM_AES_ECB, clear, {}, clear_key);
        ASSERT_FALSE(encrypted.empty());

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(ta_sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), nullptr, clear.size(), client(),
                          ta_uuid()),
                SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(TaSvpKeyCheckTest, failInvalidBytesToProcess) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = encrypt_openssl(SA_CIPHER_ALGORITHM_AES_ECB, clear, {}, clear_key);
        ASSERT_FALSE(encrypted.empty());

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(ta_sa_svp_key_check(*key, encrypted_buffer.get(), clear.size() + 1, clear.data(), clear.size(),
                          client(), ta_uuid()),
                SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(TaSvpKeyCheckTest, failInvalidExpected) {
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = encrypt_openssl(SA_CIPHER_ALGORITHM_AES_ECB, clear, {}, clear_key);
        ASSERT_FALSE(encrypted.empty());
        clear.push_back(1);

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(ta_sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size(), client(),
                          ta_uuid()),
                SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
#endif // DISABLE_SVP
