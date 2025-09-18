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
#include "client_test_helpers.h"
#include "sa.h"
#include "sa_svp_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaSvpKeyCheckTest, nominalClear) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_ecb_openssl(encrypted, clear, clear_key, false));

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size()),
                SA_STATUS_OK);
    }

    TEST_F(SaSvpKeyCheckTest, failNoSvp) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_ecb_openssl(encrypted, clear, clear_key, false));

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size()),
                SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaSvpKeyCheckTest, failNullIn) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        ASSERT_EQ(sa_svp_key_check(*key, nullptr, clear.size(), clear.data(), clear.size()),
                SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpKeyCheckTest, failNullExpected) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_ecb_openssl(encrypted, clear, clear_key, false));

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), nullptr, clear.size()),
                SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpKeyCheckTest, failInvalidBytesToProcess) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_ecb_openssl(encrypted, clear, clear_key, false));

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size() + 1, clear.data(), clear.size()),
                SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaSvpKeyCheckTest, failInvalidExpected) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_ecb_openssl(encrypted, clear, clear_key, false));
        clear.push_back(1);

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size()),
                SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaSvpKeyCheckTest, failKeyNoDecrypt) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_DECRYPT);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_ecb_openssl(encrypted, clear, clear_key, false));

        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size()),
                SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaSvpKeyCheckTest, failNotAes) {
        auto clear_key = ec_generate_key_bytes(SA_ELLIPTIC_CURVE_NIST_P256);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, SA_ELLIPTIC_CURVE_NIST_P256, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto clear = random(AES_BLOCK_SIZE);
        auto encrypted = std::vector<uint8_t>(clear.size());
        auto encrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_EQ(sa_svp_key_check(*key, encrypted_buffer.get(), clear.size(), clear.data(), clear.size()),
                SA_STATUS_INVALID_KEY_TYPE);
    }
} // namespace
#endif //DISABLE_SVP
