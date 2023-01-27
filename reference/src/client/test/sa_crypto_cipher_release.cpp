/**
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
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

namespace {
    TEST_P(SaCryptoCipherEncryptTest, releaseNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        parameters.svp_required = false;
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        sa_status status = sa_crypto_cipher_release(*cipher);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_P(SaCryptoCipherDecryptTest, releaseNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        parameters.svp_required = false;
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        parameters.oaep_digest_algorithm = std::get<4>(GetParam());
        parameters.oaep_mgf1_digest_algorithm = std::get<5>(GetParam());
        parameters.oaep_label_length = std::get<6>(GetParam());

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        sa_status status = sa_crypto_cipher_release(*cipher);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, releaseFailsInvalidContext) {
        sa_status status = sa_crypto_cipher_release(INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
