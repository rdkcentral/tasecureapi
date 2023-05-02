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
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyImportTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_key;
        sa_elliptic_curve curve;
        auto key = create_sa_key(key_type, key_length, clear_key, curve);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        type_parameters.curve = curve;
        auto header = key_header(*key);
        ASSERT_NE(header, nullptr);
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_length, header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(key_type, header->type);

        ASSERT_TRUE(key_check(key_type, *key, clear_key));
    }

    TEST_F(SaKeyImportTest, failsNullKey) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        sa_status const status = sa_key_import(nullptr, SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsInvalidFormat) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), static_cast<sa_key_format>(UINT8_MAX), clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsNullIn) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, nullptr, clear_key.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
