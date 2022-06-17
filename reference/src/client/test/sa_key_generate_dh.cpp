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
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {

    TEST_F(SaKeyGenerateTest, failsDhNullParameters) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhNullP) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp4096 = sample_dh_p_4096();
        std::vector<uint8_t> dhg4096 = sample_dh_g_4096();

        sa_generate_parameters_dh parameters = {nullptr, dhp4096.size(), dhg4096.data(), dhg4096.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhNullG) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp4096 = sample_dh_p_4096();
        std::vector<uint8_t> dhg4096 = sample_dh_g_4096();

        sa_generate_parameters_dh parameters = {dhp4096.data(), dhp4096.size(), nullptr, dhg4096.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhBadP) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp_bad_4096 = sample_dh_bad_p_4096();
        std::vector<uint8_t> dhg4096 = sample_dh_g_4096();

        sa_generate_parameters_dh parameters = {dhp_bad_4096.data(), dhp_bad_4096.size(), dhg4096.data(),
                dhg4096.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhBadPLengthZero) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp4096 = sample_dh_p_4096();
        std::vector<uint8_t> dhg4096 = sample_dh_g_4096();

        sa_generate_parameters_dh parameters = {dhp4096.data(), 0, dhg4096.data(), dhg4096.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhBadGLengthZero) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp4096 = sample_dh_p_4096();
        std::vector<uint8_t> dhg4096 = sample_dh_g_4096();

        sa_generate_parameters_dh parameters = {dhp4096.data(), dhp4096.size(), dhg4096.data(), 0};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhBadPLengthMax) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp4096 = sample_dh_p_4096();
        std::vector<uint8_t> dhg4096 = sample_dh_g_4096();
        dhp4096.push_back(1);
        sa_generate_parameters_dh parameters = {dhp4096.data(), dhp4096.size(), dhg4096.data(), dhg4096.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsDhBadGLength) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp4096 = sample_dh_p_4096();
        std::vector<uint8_t> dhg4096 = random(dhp4096.size() + 1);
        sa_generate_parameters_dh parameters = {dhp4096.data(), dhp4096.size(), dhg4096.data(), dhg4096.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
