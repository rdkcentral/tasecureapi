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
    TEST_F(SaKeyImportTest, nominalSymmetricNoAvailableResourceSlot) {
        auto clear_key = random(AES_BLOCK_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        std::vector<std::shared_ptr<sa_key>> keys;
        size_t i = 0;
        sa_status status;
        do {
            auto key = create_uninitialized_sa_key();
            ASSERT_NE(key, nullptr);

            status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_key.data(), clear_key.size(),
                    &parameters);
            ASSERT_LE(i++, MAX_NUM_SLOTS);
            keys.push_back(key);
        } while (status == SA_STATUS_OK);

        ASSERT_EQ(status, SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }

    TEST_F(SaKeyImportTest, failsSymmetricBytesBadInLength15) {
        auto clear_key = random(15);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_key.data(), clear_key.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsSymmetricBytesBadInLength513) {
        auto clear_key = random(513);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_import_parameters_symmetric parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_key.data(), clear_key.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsSymmetricBytesNullParameters) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, nullptr, clear_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsSymmetricBytesNullRights) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_import_parameters_symmetric parameters = {nullptr};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, nullptr, clear_key.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
