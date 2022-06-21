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
#include "sa_key_derive_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyDeriveAnsiX963Test, nominal) {
        std::tuple<sa_key_type, size_t> key_info = std::get<0>(GetParam());
        const sa_digest_algorithm digest_algorithm = std::get<1>(GetParam());
        const size_t key_size = std::get<2>(GetParam());
        const size_t info_size = std::get<3>(GetParam());
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_base_key;
        std::shared_ptr<sa_key> base_key;
        size_t base_key_length = std::get<1>(key_info);
        switch (std::get<0>(key_info)) {
            case SA_KEY_TYPE_SYMMETRIC: {
                clear_base_key = random(base_key_length);
                base_key = create_sa_key_symmetric(&rights, clear_base_key);
                ASSERT_NE(base_key, nullptr);
                if (*base_key == UNSUPPORTED_KEY)
                    GTEST_SKIP() << "key type not supported";

                break;
            }
            case SA_KEY_TYPE_DH: {
                auto dh_parameters = get_dh_parameters(base_key_length);
                base_key = create_uninitialized_sa_key();
                ASSERT_NE(base_key, nullptr);
                ASSERT_TRUE(execute_dh(base_key, clear_base_key, std::get<0>(dh_parameters),
                        std::get<1>(dh_parameters)));
                break;
            }
            case SA_KEY_TYPE_EC: {
                auto curve = static_cast<sa_elliptic_curve>(base_key_length);
                base_key = create_uninitialized_sa_key();
                ASSERT_NE(base_key, nullptr);
                sa_status status = execute_ecdh(curve, base_key, clear_base_key);
                if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
                    GTEST_SKIP() << "Curve not supported";

                ASSERT_EQ(status, SA_STATUS_OK);
                break;
            }
            default:
                FAIL();
        }

        auto info = random(info_size);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = key_size,
                .digest_algorithm = digest_algorithm,
                .parent = *base_key,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> clear_key(key_size);
        ASSERT_TRUE(ansi_x963_kdf(clear_key, clear_base_key, info, digest_algorithm));
        ASSERT_TRUE(key_check_sym(*key, clear_key));
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsNullKey) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric key_parameters = {.key_length = 16};
        auto parent_key = create_uninitialized_sa_key();
        ASSERT_NE(parent_key, nullptr);
        sa_status status = sa_key_generate(parent_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, &key_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto info = random(SYM_128_KEY_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = 0,
                .info = info.data(),
                .info_length = info.size()};

        status = sa_key_derive(nullptr, &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsNullRights) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric key_parameters = {.key_length = 16};
        auto parent_key = create_uninitialized_sa_key();
        ASSERT_NE(parent_key, nullptr);
        sa_status status = sa_key_generate(parent_key.get(), &rights, SA_KEY_TYPE_SYMMETRIC, &key_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto info = random(SYM_128_KEY_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = 0,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_derive(key.get(), nullptr, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsNullParameters) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsMaxKeyLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto info = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = 513,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = *parent_key,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsBadDigest) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto info = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = static_cast<sa_digest_algorithm>(UINT8_MAX),
                .parent = *parent_key,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsUnknownParent) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto info = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = INVALID_HANDLE,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsNullInfo) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = *parent_key,
                .info = nullptr,
                .info_length = 16};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsParentDisallowsDerive) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_DERIVE);

        auto symmetric_key = random(SYM_128_KEY_SIZE);
        auto parent_key = create_sa_key_symmetric(&rights, symmetric_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto info = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = *parent_key,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyDeriveAnsiX963Test, failsParentNotSymmetric) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto rsa_key = sample_rsa_2048_pkcs8();
        auto parent_key = create_sa_key_rsa(&rights, rsa_key);
        ASSERT_NE(parent_key, nullptr);
        if (*parent_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto info = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_ansi_x963 kdf_parameters_ansi_x963 = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .parent = *parent_key,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_ANSI_X963, &kdf_parameters_ansi_x963);
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }
} // namespace
