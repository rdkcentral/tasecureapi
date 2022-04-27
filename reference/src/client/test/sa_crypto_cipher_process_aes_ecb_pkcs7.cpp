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
    TEST_P(SaCryptoCipherWithSvpTest, processAesEcbPkcs7FailsBadInLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        sa_cipher_mode cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, cipher_mode, *key,
                nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(33);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(buffer_type, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithSvpTest, processAesEcbPkcs7BadOutLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        sa_cipher_mode cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, cipher_mode, *key,
                nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(buffer_type, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaCryptoCipherSvpOnlyTest, initAesEcbPkcs7FailsDecryptBadRightsSvpOptionalNotSet) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(AES_BLOCK_SIZE);
        sa_cipher_parameters_aes_cbc parameters = {iv.data(), iv.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB_PKCS7,
                SA_CIPHER_MODE_DECRYPT, *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
