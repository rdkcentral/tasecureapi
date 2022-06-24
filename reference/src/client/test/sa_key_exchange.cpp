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
#include "sa_key_exchange_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyExchangeTest, invalidAlgorithm) {
        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp3072 = sample_dh_p_3072();
        std::vector<uint8_t> dhg3072 = sample_dh_g_3072();

        sa_generate_parameters_dh parameters = {
                .p = dhp3072.data(),
                .p_length = dhp3072.size(),
                .g = dhg3072.data(),
                .g_length = dhg3072.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t dh_public_key_length;
        status = sa_key_get_public(nullptr, &dh_public_key_length, *dh_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> dh_public_key(dh_public_key_length);
        status = sa_key_get_public(dh_public_key.data(), &dh_public_key_length, *dh_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, static_cast<sa_key_exchange_algorithm>(UINT8_MAX), *dh_key,
                dh_public_key.data(), dh_public_key_length, nullptr);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
