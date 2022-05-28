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
    TEST_P(SaCryptoCipherElGamalTest, processEcElgamalFailsBadInLength) {
        sa_elliptic_curve curve = std::get<0>(GetParam());
        size_t key_size = ec_get_key_size(curve);
        auto clear_key = random_ec(key_size);

        auto evp_pkey = ec_import_private(curve, clear_key);
        if (reinterpret_cast<uintptr_t>(evp_pkey.get()) == UNSUPPORTED_OPENSSL_KEY)
            GTEST_SKIP() << "Unsupported curve";

        ASSERT_NE(evp_pkey, nullptr);

        auto ec_group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(ec_get_type(curve)), EC_GROUP_free);
        ASSERT_NE(ec_group, nullptr);

        // pick valid random x coordinate
        auto clear = random_ec(key_size);
        while (!ec_is_valid_x_coordinate(ec_group, clear)) {
            clear = random(clear.size());
        }

        auto in = std::vector<uint8_t>(4 * key_size);
        ASSERT_TRUE(encrypt_ec_elgamal_openssl(in, clear, curve, evp_pkey));

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        ASSERT_NE(cipher, nullptr);

        in.resize(in.size() - 1);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, key_size);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_P(SaCryptoCipherElGamalTest, processEcElgamalFailsBadOutLength) {
        sa_elliptic_curve curve = std::get<0>(GetParam());
        size_t key_size = ec_get_key_size(curve);
        auto clear_key = random_ec(key_size);

        auto evp_pkey = ec_import_private(curve, clear_key);
        if (reinterpret_cast<uintptr_t>(evp_pkey.get()) == UNSUPPORTED_OPENSSL_KEY)
            GTEST_SKIP() << "Unsupported curve";

        ASSERT_NE(evp_pkey, nullptr);

        auto ec_group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(ec_get_type(curve)), EC_GROUP_free);
        ASSERT_NE(ec_group, nullptr);

        // pick valid random x coordinate
        auto clear = random_ec(key_size);
        while (!ec_is_valid_x_coordinate(ec_group, clear)) {
            clear = random(clear.size());
        }

        auto in = std::vector<uint8_t>(4 * key_size);
        ASSERT_TRUE(encrypt_ec_elgamal_openssl(in, clear, curve, evp_pkey));

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, key_size - 1);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_P(SaCryptoCipherElGamalTest, processEcElgamalFailsBadBufferType) {
        if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

        sa_elliptic_curve curve = std::get<0>(GetParam());
        size_t key_size = ec_get_key_size(curve);
        auto clear_key = random_ec(key_size);

        auto evp_pkey = ec_import_private(curve, clear_key);
        if (reinterpret_cast<uintptr_t>(evp_pkey.get()) == UNSUPPORTED_OPENSSL_KEY)
            GTEST_SKIP() << "Unsupported curve";

        ASSERT_NE(evp_pkey, nullptr);

        auto ec_group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(ec_get_type(curve)), EC_GROUP_free);
        ASSERT_NE(ec_group, nullptr);

        // pick valid random x coordinate
        auto clear = random_ec(key_size);
        while (!ec_is_valid_x_coordinate(ec_group, clear)) {
            clear = random(clear.size());
        }

        auto in = std::vector<uint8_t>(4 * key_size);
        ASSERT_TRUE(encrypt_ec_elgamal_openssl(in, clear, curve, evp_pkey));

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, key_size - 1);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
