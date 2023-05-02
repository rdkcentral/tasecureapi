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
    TEST_P(SaCryptoMacComputeMatchesOpenssl, nominal) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());
        int const data_length = std::get<3>(GetParam());
        MacFunctionType mac_func = std::get<4>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(data_length);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto tag = std::vector<uint8_t>(out_length);
        status = sa_crypto_mac_compute(tag.data(), &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        // openssl computed mac
        auto tag_test = std::vector<uint8_t>(out_length);
        mac_func(tag_test, clear_key, clear);

        // compare tag_test and tag
        int const result = memcmp(tag.data(), tag_test.data(), tag_test.size());
        ASSERT_EQ(result, 0);
    }

    TEST_P(SaCryptoMacComputeMatchesOpenssl, nominalKey) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());
        MacFunctionType mac_func = std::get<4>(GetParam());

        auto clear_key = random(key_length);

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

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto tag = std::vector<uint8_t>(out_length);
        status = sa_crypto_mac_compute(tag.data(), &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        // openssl computed mac
        auto tag_test = std::vector<uint8_t>(out_length);
        mac_func(tag_test, clear_key, clear_mac_key);

        // compare tag_test and tag
        int const result = memcmp(tag.data(), tag_test.data(), tag_test.size());
        ASSERT_EQ(result, 0);
    }

    TEST_P(SaCryptoMacComputeOutLength, nominal) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());
        size_t const expected_out_length = std::get<3>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(SHA256_DIGEST_LENGTH);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, expected_out_length);
    }

    TEST_P(SaCryptoMacComputeOutLength, failsWithNullOutLength) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(SHA256_DIGEST_LENGTH);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_compute(nullptr, nullptr, *mac);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoMacComputeArgChecks, failsWithInvalidContext) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);

        status = sa_crypto_mac_compute(out.data(), &out_length, INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacComputeArgChecks, failsWhenProcessCalledAfterCompute) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);

        status = sa_crypto_mac_compute(out.data(), &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacComputeArgChecks, failsWhenMultipleCompute) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);

        status = sa_crypto_mac_compute(out.data(), &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_crypto_mac_compute(out.data(), &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoMacComputeArgChecks, failsWithNullOutLengthWithNonNullData) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE);
        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;
        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);

        status = sa_crypto_mac_compute(out.data(), nullptr, *mac);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoMacComputeArgChecks, failsInvalidOutLength) {
        sa_mac_algorithm const mac_algorithm = std::get<0>(GetParam());
        void* parameters = std::get<1>(GetParam());
        int const key_length = std::get<2>(GetParam());

        auto clear_key = random(key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mac = create_uninitialized_sa_crypto_mac_context();
        ASSERT_NE(mac, nullptr);

        sa_status status = sa_crypto_mac_init(mac.get(), mac_algorithm, *key, parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(SHA256_DIGEST_LENGTH);

        status = sa_crypto_mac_process(*mac, clear.data(), clear.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length;

        status = sa_crypto_mac_compute(nullptr, &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto tag = std::vector<uint8_t>(out_length);
        ASSERT_GT(out_length, 0);
        out_length--;
        status = sa_crypto_mac_compute(tag.data(), &out_length, *mac);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
