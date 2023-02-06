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
#include "sa_key_unwrap_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyUnwrapTest, nominal) {
        auto key_size = std::get<0>(std::get<0>(GetParam()));
        auto key_type = std::get<1>(std::get<0>(GetParam()));
        auto wrapping_algorithm = std::get<0>(std::get<1>(GetParam()));
        auto wrapping_key_size = std::get<1>(std::get<1>(GetParam()));
        auto oaep_digest_algorithm = std::get<2>(std::get<1>(GetParam()));
        auto oaep_mgf1_digest_algorithm = std::get<3>(std::get<1>(GetParam()));
        auto oaep_label_length = std::get<4>(std::get<1>(GetParam()));

        std::vector<uint8_t> clear_key;
        auto curve = static_cast<sa_elliptic_curve>(UINT8_MAX);
        switch (key_type) {
            case SA_KEY_TYPE_SYMMETRIC:
                clear_key = random(key_size);
                break;

            case SA_KEY_TYPE_EC:
                curve = static_cast<sa_elliptic_curve>(key_size);
                clear_key = ec_generate_key_bytes(curve);
                if (clear_key.empty())
                    GTEST_SKIP() << "key type, key size, or curve not supported";
                break;

            case SA_KEY_TYPE_RSA:
                clear_key = get_rsa_private_key(key_size);
                break;

            default:
                FAIL();
        }

        std::shared_ptr<sa_key> wrapping_key;
        std::vector<uint8_t> clear_wrapping_key;
        std::shared_ptr<void> wrapping_parameters;
        std::vector<uint8_t> wrapped_key;
        sa_status status = wrap_key(wrapping_key, clear_wrapping_key, wrapped_key, wrapping_parameters,
                wrapping_key_size, clear_key, wrapping_algorithm, oaep_digest_algorithm, oaep_mgf1_digest_algorithm,
                oaep_label_length);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);

        sa_unwrap_type_parameters_ec unwrap_type_parameters_ec = {curve};
        status = sa_key_unwrap(unwrapped_key.get(), &rights, key_type,
                (key_type == SA_KEY_TYPE_EC) ? &unwrap_type_parameters_ec : nullptr, wrapping_algorithm,
                wrapping_parameters.get(), *wrapping_key, wrapped_key.data(), wrapped_key.size());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_TRUE(key_check(key_type, *unwrapped_key, clear_key));
    }

    TEST(SaKeyUnwrapTest, failsInvalidAlgorithm) {
        auto clear_wrapping_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(wrapping_key, nullptr);

        auto unwrapped_key = create_uninitialized_sa_key();
        ASSERT_NE(unwrapped_key, nullptr);

        auto clear_key = random(SYM_128_KEY_SIZE);
        sa_status const status = sa_key_unwrap(unwrapped_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, nullptr,
                static_cast<sa_cipher_algorithm>(UINT8_MAX), nullptr, *wrapping_key, clear_key.data(),
                clear_key.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
