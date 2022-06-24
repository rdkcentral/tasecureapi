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

#ifdef ENABLE_SOC_KEY_TESTS

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_derive_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

static std::vector<uint8_t> C1 = random(AES_BLOCK_SIZE);
static std::vector<uint8_t> C2 = random(AES_BLOCK_SIZE);
static std::vector<uint8_t> C3 = random(AES_BLOCK_SIZE);
static std::vector<uint8_t> C4 = random(AES_BLOCK_SIZE);

namespace {
    TEST_F(SaKeyDeriveRootKeyLadderTest, nominal) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto derived_key = derive_test_key_ladder(C1, C2, C3, C4);
        ASSERT_TRUE(key_check_sym(*key, *derived_key));
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullKey) {
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status status = sa_key_derive(nullptr, &rights, SA_KDF_ALGORITHM_ROOT_KEY_LADDER, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullRights) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric key_parameters = {.key_length = 16};
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, &key_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        status = sa_key_derive(key.get(), nullptr, SA_KDF_ALGORITHM_ROOT_KEY_LADDER, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullParameters) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric key_parameters = {.key_length = 16};
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, &key_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ROOT_KEY_LADDER, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullC1) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = nullptr, .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullC2) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = nullptr, .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullC3) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = nullptr, .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsNullC4) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = nullptr, .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsC1Length) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = 0,
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsC2Length) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = 0,
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsC3Length) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = 0,
                .c4 = C4.data(), .c4_length = C4.size()};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveRootKeyLadderTest, failsC4Length) {
        sa_kdf_algorithm kdf_algorithm = SA_KDF_ALGORITHM_ROOT_KEY_LADDER;
        // clang-format off
        sa_kdf_parameters_root_key_ladder parameters = {
                .c1 = C1.data(), .c1_length = C1.size(),
                .c2 = C2.data(), .c2_length = C2.size(),
                .c3 = C3.data(), .c3_length = C3.size(),
                .c4 = C4.data(), .c4_length = 0};
        // clang-format on

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, kdf_algorithm, &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace

#endif
