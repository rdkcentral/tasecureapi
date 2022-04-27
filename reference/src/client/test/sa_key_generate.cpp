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
    TEST_P(SaKeyGenerateTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        size_t curve;
        std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> dh_parameters;
        void* parameters = nullptr;
        sa_generate_parameters_symmetric parameters_symmetric;
        sa_generate_parameters_ec parameters_ec;
        sa_generate_parameters_dh parameters_dh;
        switch (key_type) {
            case SA_KEY_TYPE_EC: {
                curve = key_length;
                key_length = ec_get_key_size(static_cast<sa_elliptic_curve>(curve));
                parameters_ec.curve = static_cast<sa_elliptic_curve>(curve);
                parameters = &parameters_ec;
                break;
            }
            case SA_KEY_TYPE_SYMMETRIC: {
                parameters_symmetric.key_length = key_length;
                parameters = &parameters_symmetric;
                curve = 0;
                break;
            }
            case SA_KEY_TYPE_DH: {
                dh_parameters = get_dh_parameters(key_length);
                parameters_dh.p = std::get<0>(dh_parameters).data();
                parameters_dh.p_length = std::get<0>(dh_parameters).size();
                parameters_dh.g = std::get<1>(dh_parameters).data();
                parameters_dh.g_length = std::get<1>(dh_parameters).size();
                parameters = &parameters_dh;
                curve = 0;
                break;
            }
            default:
                FAIL();
        }

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_status status = sa_key_generate(key.get(), &rights, key_type, parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_length, header->size);
        ASSERT_EQ(curve, header->param);
        ASSERT_EQ(key_type, header->type);
    }

    TEST_F(SaKeyGenerateTest, failsNullKey) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric parameters = {AES_BLOCK_SIZE};

        sa_status status = sa_key_generate(nullptr, &rights, SA_KEY_TYPE_SYMMETRIC, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsNullRights) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_generate_parameters_symmetric parameters = {AES_BLOCK_SIZE};

        sa_status status = sa_key_generate(key.get(), nullptr, SA_KEY_TYPE_SYMMETRIC, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsBadKeyType) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric parameters = {128};

        sa_status status = sa_key_generate(key.get(), &rights, static_cast<sa_key_type>(UINT8_MAX), &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
