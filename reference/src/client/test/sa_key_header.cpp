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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyHeaderTest, nominal) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_header header;
        sa_status status = sa_key_header(&header, *key);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaKeyHeaderTest, failsInvalidKey) {
        sa_header header;
        sa_status status = sa_key_header(&header, INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyHeaderTest, failsNullHeader) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_header(nullptr, *key);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
