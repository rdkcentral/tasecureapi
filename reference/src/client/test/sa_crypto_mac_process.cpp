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
#include "sa_crypto_mac_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaCryptoMacProcess, nominal) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto in = random(AES_BLOCK_SIZE);

        status = sa_crypto_mac_process(*mac, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process(*mac, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaCryptoMacProcess, failsInvalidContext) {
        auto clear = random(SHA256_DIGEST_LENGTH);

        sa_status const status = sa_crypto_mac_process(INVALID_HANDLE, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoMacProcess, failsNullIn) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), SA_MAC_ALGORITHM_CMAC, *key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(SHA256_DIGEST_LENGTH);

        status = sa_crypto_mac_process(*mac, nullptr, clear.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoMacProcessArgChecks, failsWithInvalidContext) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto in = random(SHA256_DIGEST_LENGTH);

        status = sa_crypto_mac_process(INVALID_HANDLE, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacProcessArgChecks, failsInvalidContextAlreadyUsed) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto in = random(SHA256_DIGEST_LENGTH);

        status = sa_crypto_mac_process(*mac, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t tag_length;
        status = sa_crypto_mac_compute(nullptr, &tag_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto tag = std::vector<uint8_t>(tag_length);
        status = sa_crypto_mac_compute(tag.data(), &tag_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process(*mac, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacProcessArgChecks, failsWithNullData) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto in = random(SHA256_DIGEST_LENGTH);

        status = sa_crypto_mac_process(*mac, nullptr, in.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
