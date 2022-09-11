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
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaCryptoCipherWithoutSvpTest, updateIvRsaOaepFails) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_cipher_parameters_rsa_oaep parameters = {SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA256, nullptr, 0};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_RSA_OAEP, SA_CIPHER_MODE_DECRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        auto iv = random(AES_BLOCK_SIZE);
        status = sa_crypto_cipher_update_iv(*cipher, iv.data(), iv.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
