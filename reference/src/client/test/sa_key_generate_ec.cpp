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
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {

    TEST_F(SaKeyGenerateTest, failsEcInvalidCurve) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {static_cast<sa_elliptic_curve>(UINT8_MAX)};

        sa_status const status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsEcNullParameters) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status const status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_EC, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
