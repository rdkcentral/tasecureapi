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
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyImportTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_key;
        sa_elliptic_curve curve = SA_ELLIPTIC_CURVE_NIST_P256;
        switch (key_type) {
            case SA_KEY_TYPE_EC: {
                curve = static_cast<sa_elliptic_curve>(key_length);
                key_length = ec_get_key_size(curve);
                clear_key = random_ec(key_length);
                key = create_sa_key_ec(&rights, curve, clear_key);
                break;
            }
            case SA_KEY_TYPE_SYMMETRIC: {
                clear_key = random(key_length);
                key = create_sa_key_symmetric(&rights, clear_key);
                break;
            }
            case SA_KEY_TYPE_RSA: {
                clear_key = get_rsa_private_key(key_length);
                key = create_sa_key_rsa(&rights, clear_key);
                break;
            }
            default:
                FAIL();
        }

        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto header = key_header(*key);
        ASSERT_NE(header, nullptr);
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_length, header->size);
        ASSERT_EQ(curve, header->param);
        ASSERT_EQ(key_type, header->type);

        ASSERT_TRUE(key_check(key_type, *key, clear_key));
    }

    TEST_F(SaKeyImportTest, failsNullKey) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        sa_status status = sa_key_import(nullptr, SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_key.data(), clear_key.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsBadFormat) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), static_cast<sa_key_format>(UINT8_MAX), clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsNullIn) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, nullptr, clear_key.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
