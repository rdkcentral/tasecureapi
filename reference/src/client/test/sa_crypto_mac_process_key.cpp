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
#include "sa_crypto_mac_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaCryptoMacProcessKey, nominal) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);
        status = sa_crypto_mac_process_key(*mac, *mac_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process_key(*mac, *mac_key);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaCryptoMacProcessKey, failsInvalidContext) {
        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);

        sa_status status = sa_crypto_mac_process_key(INVALID_HANDLE, *mac_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoMacProcessKey, failsInvalidKey) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), SA_MAC_ALGORITHM_CMAC, *key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);
        status = sa_crypto_mac_process_key(*mac, INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacProcessKeyArgChecks, failsWithInvalidContext) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);
        status = sa_crypto_mac_process_key(INVALID_HANDLE, *mac_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacProcessKeyArgChecks, failsInvalidContextAlreadyUsed) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);
        status = sa_crypto_mac_process_key(*mac, *mac_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t tag_length;
        status = sa_crypto_mac_compute(nullptr, &tag_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto tag = std::vector<uint8_t>(tag_length);
        status = sa_crypto_mac_compute(tag.data(), &tag_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process_key(*mac, *mac_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoMacProcessKey, failDh) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> dhp2048 = sample_dh_p_2048();
        std::vector<uint8_t> dhg2048 = sample_dh_g_2048();

        sa_generate_parameters_dh parameters = {dhp2048.data(), dhp2048.size(), dhg2048.data(), dhg2048.size()};
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        status = sa_crypto_mac_init(mac.get(), SA_MAC_ALGORITHM_CMAC, *mac_key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process_key(*mac, *key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoMacProcessKey, failEc) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {SA_ELLIPTIC_CURVE_NIST_P256};
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        status = sa_crypto_mac_init(mac.get(), SA_MAC_ALGORITHM_CMAC, *mac_key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process_key(*mac, *key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoMacProcessKey, failRsa) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto rsa_key = sample_rsa_2048_pkcs8();
        sa_import_parameters_rsa_private_key_info rsa_parameters = {&rights};
        auto key = create_sa_key_rsa(&rights, rsa_key);
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, rsa_key.data(),
                rsa_key.size(), &rsa_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear_mac_key = random(SYM_128_KEY_SIZE);
        auto mac_key = create_sa_key_symmetric(&rights, clear_mac_key);
        ASSERT_NE(mac_key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        status = sa_crypto_mac_init(mac.get(), SA_MAC_ALGORITHM_CMAC, *mac_key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process_key(*mac, *key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
