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
    TEST_F(SaKeyGetPublicTest, failsDhInvalidOutLength) {
        auto p = sample_dh_p_2048();
        auto g = sample_dh_g_2048();

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_dh parameters = {p.data(), p.size(), g.data(), g.size()};

        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length = 0;
        status = sa_key_get_public(nullptr, &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);
        out_length -= 1;
        status = sa_key_get_public(out.data(), &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
