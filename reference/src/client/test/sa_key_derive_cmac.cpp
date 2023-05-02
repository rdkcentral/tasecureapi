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
#include "sa_key_derive_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyDeriveCmacTest, nominal) {
        const size_t key_size = std::get<0>(GetParam());
        const size_t other_data_size = std::get<1>(GetParam());
        const uint8_t counter = std::get<2>(GetParam());
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(key_size);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(other_data_size);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = key_size,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = other_data.size(),
                .counter = counter};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> clear_key(key_size);
        ASSERT_TRUE(cmac_kdf(clear_key, symmetric_key, other_data, counter));
        ASSERT_TRUE(key_check_sym(*key, clear_key));
    }

    TEST_F(SaKeyDeriveCmacTest, failsNullKey) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = 513,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = other_data.size(),
                .counter = 1};

        sa_status const status = sa_key_derive(nullptr, &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsNullRights) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = 513,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = other_data.size(),
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), nullptr, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsNullParameters) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsMaxKeyLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = 513,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = other_data.size(),
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsInvalidDigest) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SA_DIGEST_ALGORITHM_SHA1,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = other_data.size(),
                .counter = UINT8_MAX};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsUnknownParent) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = INVALID_HANDLE,
                .other_data = other_data.data(),
                .other_data_length = other_data.size(),
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsNullOtherData) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = *parent_key,
                .other_data = nullptr,
                .other_data_length = 16,
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, fails0Counter) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = 16,
                .counter = 0};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, fails5Counter) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = 16,
                .counter = 5};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsInvalidLengthCtrCombination) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_256_KEY_SIZE,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = 16,
                .counter = 4};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveCmacTest, failsParentDisallowsDerive) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_DERIVE);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = 16,
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyDeriveCmacTest, failsParentNotSymmetric) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto rsa_key = sample_rsa_2048_pkcs8();
        auto parent_key = create_sa_key_rsa(&rights, rsa_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = 16,
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }

    TEST_F(SaKeyDeriveCmacTest, failsParentNotAes) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(20);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto other_data = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_cmac kdf_parameters_cmac = {
                .key_length = SYM_128_KEY_SIZE,
                .parent = *parent_key,
                .other_data = other_data.data(),
                .other_data_length = 16,
                .counter = 1};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status const status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CMAC, &kdf_parameters_cmac);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }
} // namespace
