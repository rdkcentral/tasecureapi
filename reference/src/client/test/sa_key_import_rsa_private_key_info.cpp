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
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyImportTest, nominalRsaPrivateKeyInfo1024E3) {
        sa_rights rights;
        rights_set_allow_all(&rights);
        auto clear_key = sample_rsa_1024_pkcs8_e3();
        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(128, header->size);
        ASSERT_EQ(0, header->param);
        ASSERT_EQ(SA_KEY_TYPE_RSA, header->type);

        ASSERT_TRUE(key_check_rsa(*key, clear_key));
    }
    TEST_F(SaKeyImportTest, nominalRsaNoAvailableResourceSlot) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_import_parameters_rsa_private_key_info parameters = {&rights};

        std::vector<std::shared_ptr<sa_key>> keys;
        size_t i = 0;
        sa_status status;
        do {
            auto key = create_uninitialized_sa_key();
            ASSERT_NE(key, nullptr);

            status = sa_key_import(key.get(), SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, clear_key.data(), clear_key.size(),
                    &parameters);
            ASSERT_LE(i++, MAX_NUM_SLOTS);
            keys.push_back(key);
        } while (status == SA_STATUS_OK);

        ASSERT_EQ(status, SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }

    TEST_F(SaKeyImportTest, failsRsaPrivateKeyInfoBadKeySize) {
        auto clear_key = sample_rsa_6144_pkcs8();

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_import_parameters_rsa_private_key_info parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsRsaPrivateKeyInfoBadPkcs8) {
        auto clear_key = std::vector<uint8_t>(256);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_import_parameters_rsa_private_key_info parameters = {&rights};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_FORMAT);
    }

    TEST_F(SaKeyImportTest, failsRsaPrivateKeyInfoNullParameters) {
        auto clear_key = sample_rsa_2048_pkcs8();

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, clear_key.data(),
                clear_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyImportTest, failsRsaPrivateKeyInfoNullRights) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_import_parameters_rsa_private_key_info parameters = {nullptr};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
