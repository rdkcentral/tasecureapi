/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#include "sa.h"
#include "gtest/gtest.h"

namespace {
    TEST(SaGetName, nominalNullName) {
        size_t name_length = 0;
        sa_status status = sa_get_name(nullptr, &name_length);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST(SaGetName, nominal) {
        size_t name_length = 0;
        sa_status status = sa_get_name(nullptr, &name_length);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<char> name;
        name.resize(name_length);
        status = sa_get_name(name.data(), &name_length);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST(SaGetName, failsNullNameLength) {
        std::vector<char> name;
        name.resize(1);
        sa_status status = sa_get_name(name.data(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST(SaGetName, failsBadNameLength) {
        size_t name_length = 0;
        sa_status status = sa_get_name(nullptr, &name_length);
        ASSERT_EQ(status, SA_STATUS_OK);
        name_length--;

        std::vector<char> name;
        name.resize(name_length);
        status = sa_get_name(name.data(), &name_length);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
