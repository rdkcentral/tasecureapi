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
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyExportTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_status status;
        std::vector<uint8_t> clear_key;
        auto curve = static_cast<sa_elliptic_curve>(0);
        switch (key_type) {
            case SA_KEY_TYPE_EC: {
                curve = static_cast<sa_elliptic_curve>(key_length);
                key_length = ec_get_key_size(curve);
                clear_key = random_ec(key_length);
                key = create_sa_key_ec(&rights, curve, clear_key);
                break;
            }
            case SA_KEY_TYPE_SYMMETRIC: {
                clear_key = random(key_length);
                key = create_sa_key_symmetric(&rights, clear_key);
                break;
            }
            case SA_KEY_TYPE_RSA: {
                clear_key = get_rsa_private_key(key_length);
                key = create_sa_key_rsa(&rights, clear_key);
                break;
            }
            case SA_KEY_TYPE_DH: {
                std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> dh_parameters = get_dh_parameters(key_length);
                key = create_sa_key_dh(&rights, dh_parameters);
                break;
            }
            default:
                FAIL();
        }

        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        size_t exported_key_length = 0;
        status = sa_key_export(nullptr, &exported_key_length, nullptr, 0, *key);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_TRUE(exported_key_length > sizeof(sa_header));

        auto exported_key = std::vector<uint8_t>(exported_key_length);
        status = sa_key_export(exported_key.data(), &exported_key_length, nullptr, 0, *key);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Reimport key and test.
        auto reimported_key = create_uninitialized_sa_key();
        ASSERT_NE(reimported_key, nullptr);
        status = sa_key_import(reimported_key.get(), SA_KEY_FORMAT_EXPORTED, exported_key.data(), exported_key.size(),
                nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);
        auto exported_key_header = key_header(*reimported_key);
        ASSERT_NE(nullptr, exported_key_header.get());
        ASSERT_TRUE(memcmp(&rights, &exported_key_header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_length, exported_key_header->size);
        ASSERT_EQ(curve, exported_key_header->param);
        ASSERT_EQ(key_type, exported_key_header->type);
        ASSERT_TRUE(key_check(key_type, *reimported_key, clear_key));
    }

    TEST_P(SaKeyExportTest, nominalWithMixin) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_status status;
        std::vector<uint8_t> clear_key;
        auto curve = static_cast<sa_elliptic_curve>(0);
        switch (key_type) {
            case SA_KEY_TYPE_EC: {
                curve = static_cast<sa_elliptic_curve>(key_length);
                key_length = ec_get_key_size(curve);
                clear_key = random_ec(key_length);
                key = create_sa_key_ec(&rights, curve, clear_key);
                break;
            }
            case SA_KEY_TYPE_SYMMETRIC: {
                clear_key = random(key_length);
                key = create_sa_key_symmetric(&rights, clear_key);
                break;
            }
            case SA_KEY_TYPE_RSA: {
                clear_key = get_rsa_private_key(key_length);
                key = create_sa_key_rsa(&rights, clear_key);
                break;
            }
            case SA_KEY_TYPE_DH: {
                std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> dh_parameters = get_dh_parameters(key_length);
                key = create_sa_key_dh(&rights, dh_parameters);
                break;
            }
            default:
                FAIL();
        }

        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto mixin = random(AES_BLOCK_SIZE);
        size_t exported_key_length = 0;
        status = sa_key_export(nullptr, &exported_key_length, mixin.data(), mixin.size(), *key);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_TRUE(exported_key_length > sizeof(sa_header));

        auto exported_key = std::vector<uint8_t>(exported_key_length);
        status = sa_key_export(exported_key.data(), &exported_key_length, mixin.data(), mixin.size(), *key);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Reimport key and test.
        auto reimported_key = create_uninitialized_sa_key();
        ASSERT_NE(reimported_key, nullptr);

        status = sa_key_import(reimported_key.get(), SA_KEY_FORMAT_EXPORTED, exported_key.data(), exported_key.size(),
                nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);
        auto exported_key_header = key_header(*reimported_key);
        ASSERT_NE(nullptr, exported_key_header.get());
        ASSERT_TRUE(memcmp(&rights, &exported_key_header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_length, exported_key_header->size);
        ASSERT_EQ(curve, exported_key_header->param);
        ASSERT_EQ(key_type, exported_key_header->type);
        ASSERT_TRUE(key_check(key_type, *reimported_key, clear_key));
    }

    TEST_F(SaKeyExportTest, failsNoCacheableFlag) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        size_t out_length = 0;
        sa_status status = sa_key_export(nullptr, &out_length, nullptr, 0, *key);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyExportTest, failsNullOutLength) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto out = std::vector<uint8_t>(4096);
        sa_status status = sa_key_export(out.data(), nullptr, nullptr, 0, *key);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExportTest, failsBadMixinLength) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto mixin = random(17);
        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        sa_status status = sa_key_export(out.data(), &out_length, mixin.data(), mixin.size(), *key);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyExportTest, failsBadKey) {
        size_t out_length = 0;
        sa_status status = sa_key_export(nullptr, &out_length, nullptr, 0, INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
