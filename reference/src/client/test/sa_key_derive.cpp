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
#include "sa_key_derive_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyDeriveTest, badAlgorithm) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric key_parameters = {.key_length = 16};
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, &key_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto salt = random(AES_BLOCK_SIZE);
        auto info = random(AES_BLOCK_SIZE);
        static sa_kdf_parameters_hkdf parameters = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA256,
                .parent = *key,
                .salt = salt.data(),
                .salt_length = salt.size(),
                .info = info.data(),
                .info_length = info.size()};

        status = sa_key_derive(key.get(), &rights, static_cast<sa_kdf_algorithm>(UINT8_MAX), &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
