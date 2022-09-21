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
    TEST_P(SaCryptoCipherEncryptTest, initNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        parameters.svp_required = false;
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());

        std::shared_ptr<sa_key> key;
        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";
    }

    TEST_P(SaCryptoCipherDecryptTest, initNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        parameters.oaep_digest_algorithm = std::get<4>(GetParam());
        parameters.oaep_mgf1_digest_algorithm = std::get<5>(GetParam());
        parameters.oaep_label_length = std::get<6>(GetParam());
        parameters.svp_required = false;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";
    }

    TEST_P(SaCryptoCipherDecryptTest, nominalNoAvailableResourceSlot) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        parameters.oaep_digest_algorithm = std::get<4>(GetParam());
        parameters.oaep_mgf1_digest_algorithm = std::get<5>(GetParam());
        parameters.oaep_label_length = std::get<6>(GetParam());
        parameters.svp_required = false;

        ASSERT_TRUE(import_key(parameters, key_type, key_size));
        if (*parameters.key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        std::vector<std::shared_ptr<sa_crypto_cipher_context>> ciphers;
        size_t i = 0;
        sa_status status;
        do {
            auto cipher = create_uninitialized_sa_crypto_cipher_context();
            ASSERT_NE(cipher, nullptr);

            ASSERT_TRUE(get_cipher_parameters(parameters));

            status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                    *parameters.key, parameters.parameters.get());
            if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
                GTEST_SKIP() << "Cipher algorithm not supported";

            ASSERT_LE(i++, MAX_NUM_SLOTS);
            ciphers.push_back(cipher);
        } while (status == SA_STATUS_OK);

        ASSERT_EQ(status, SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }

    TEST_P(SaCryptoCipherWithSvpTest, initFailsNullContext) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_status status = sa_crypto_cipher_init(nullptr, SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT, *key,
                nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithSvpTest, initFailsInvalidAlgorithm) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), static_cast<sa_cipher_algorithm>(UINT8_MAX),
                SA_CIPHER_MODE_ENCRYPT, *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initFailsInvalidMode) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB,
                static_cast<sa_cipher_mode>(UINT8_MAX), *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initFailsInvalidKeySlot) {
        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT,
                INVALID_HANDLE, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initFailsInvalidRightsEncryptNotSet) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ENCRYPT);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initFailsInvalidRightsDecryptNotSet) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_DECRYPT);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initFailsInvalidRightsNotBefore) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        rights.not_before = time(nullptr) + 10000;

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initFailsInvalidRightsNotOnOrAfter) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        rights.not_on_or_after = time(nullptr) - 1;

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
