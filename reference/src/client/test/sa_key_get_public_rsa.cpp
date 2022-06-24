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

#include "sa.h"
#include "client_test_helpers.h"
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyGetPublicTest, nominalRsa1024E3) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        size_t out_length = 0;
        sa_status status = sa_key_get_public(nullptr, &out_length, *key);
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

    TEST_F(SaKeyGetPublicTest, failsRsaInvalidOutLength) {
        auto clear_key = sample_rsa_1024_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        size_t out_length = 0;
        sa_status status = sa_key_get_public(nullptr, &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);
        out_length -= 1;
        status = sa_key_get_public(out.data(), &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
        out.resize(out_length);
    }
} // namespace
