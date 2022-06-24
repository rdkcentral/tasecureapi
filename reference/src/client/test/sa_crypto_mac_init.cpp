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
    TEST_F(SaCryptoMacInit, failsInvalidAlgorithm) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), static_cast<sa_mac_algorithm>(UINT8_MAX), *key, nullptr);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacInit, nominal) {
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
        ASSERT_NE(mac, nullptr);
    }

    TEST_P(SaCryptoMacInit, nominalNoAvailableResourceSlot) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        std::vector<std::shared_ptr<sa_crypto_mac_context>> macs;
        size_t i = 0;
        sa_status status;
        do {

            auto mac = create_uninitialized_sa_crypto_mac_context();
            ASSERT_NE(mac, nullptr);

            status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
            ASSERT_LE(i++, MAX_NUM_SLOTS);
            macs.push_back(mac);
        } while (status == SA_STATUS_OK);

        ASSERT_EQ(status, SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }

    TEST_P(SaCryptoMacInitArgChecks, failsNullMac) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_status status = sa_crypto_mac_init(nullptr, mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoMacInitArgChecks, failsInvalidAlgorithm) {
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), static_cast<sa_mac_algorithm>(UINT8_MAX), *key, parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacInitArgChecks, failsInvalidKeySlot) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, INVALID_HANDLE, parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacInitArgChecks, failsInvalidKeyType) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());

        auto clear_key = ec_generate_key_bytes(curve);
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }

    TEST_P(SaCryptoMacInitKeyRights, failsSignNotSet) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SIGN);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaCryptoMacInitKeyRights, failsNotBefore) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        rights.not_before = time(nullptr) + 10000;

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaCryptoMacInitKeyRights, failsNotOnOrAfter) {
        sa_mac_algorithm mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        rights.not_on_or_after = time(nullptr) - 1;

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaCryptoMacInitInvalidKeyLengths, failsWithInvalidKeyLengths) {
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
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }

    TEST_P(SaCryptoMacInitHmacDigests, failsHmacInvalidDigestAlgorithm) {
        int key_size = std::get<2>(GetParam());

        auto clear_key = random(key_size);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_mac_parameters_hmac parameters = {static_cast<sa_digest_algorithm>(-1)};

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), SA_MAC_ALGORITHM_HMAC, *key, &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
