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
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    // Nominal tests are executed in sa_key_export.cpp

    TEST_F(SaKeyImportTest, nominalExportedPreservesUsageFlags) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        rights.usage_flags = 0;
        SA_USAGE_BIT_SET(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE);

        auto imported_key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(imported_key, nullptr);

        std::vector<uint8_t> mixin = {};

        auto exported = export_key(mixin, *imported_key);
        ASSERT_NE(exported, nullptr);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_EXPORTED, exported->data(), exported->size(),
                nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_key.size(), header->size);
        ASSERT_EQ(0, header->type_parameters.curve);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header->type);
    }

    TEST_F(SaKeyImportTest, nominalExportedRsaE3) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(imported_key, nullptr);
        if (*imported_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        std::vector<uint8_t> mixin = {};

        auto exported = export_key(mixin, *imported_key);
        ASSERT_NE(exported, nullptr);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_EXPORTED, exported->data(), exported->size(),
                nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(128, header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(SA_KEY_TYPE_RSA, header->type);

        ASSERT_TRUE(key_check_rsa(*key, clear_key));

        // Get the public key.

        size_t out_length = 0;
        status = sa_key_get_public(nullptr, &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);
        status = sa_key_get_public(out.data(), &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_OK);
        out.resize(out_length);

        // extract public using OpenSSL
        auto public_openssl = std::vector<uint8_t>(4096);
        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);
        ASSERT_TRUE(export_public_key(public_openssl, rsa));

        // compare public from OpenSSL and SecApi
        ASSERT_EQ(out, public_openssl);
    }
} // namespace
