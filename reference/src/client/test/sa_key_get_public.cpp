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
    TEST_P(SaKeyGetPublicTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status status;
        std::vector<uint8_t> clear_key;
        sa_elliptic_curve curve;
        auto key = create_sa_key(key_type, key_length, clear_key, curve);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        size_t out_length = 0;
        status = sa_key_get_public(nullptr, &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);
        status = sa_key_get_public(out.data(), &out_length, *key);
        ASSERT_EQ(status, SA_STATUS_OK);
        out.resize(out_length);

        switch (key_type) {
            case SA_KEY_TYPE_EC: {
                // extract public using OpenSSL
                auto public_openssl = std::vector<uint8_t>(out_length);
                auto evp_pkey = ec_import_private(curve, clear_key);
                if (reinterpret_cast<uintptr_t>(evp_pkey.get()) == UNSUPPORTED_OPENSSL_KEY)
                    GTEST_SKIP() << "Unsupported curve";

                ASSERT_NE(evp_pkey, nullptr);
                ASSERT_TRUE(export_public_key(public_openssl, evp_pkey));

                // compare public from OpenSSL and SecApi
                ASSERT_EQ(out, public_openssl);
                break;
            }
            case SA_KEY_TYPE_DH: {
                auto evp_pkey = std::shared_ptr<EVP_PKEY>(sa_import_public_key(out.data(), out.size()), EVP_PKEY_free);
                ASSERT_NE(evp_pkey, nullptr);
                break;
            }
            case SA_KEY_TYPE_RSA: {
                // extract public using OpenSSL
                auto public_openssl = std::vector<uint8_t>(out_length);
                auto rsa = rsa_import_pkcs8(clear_key);
                ASSERT_NE(rsa, nullptr);
                ASSERT_TRUE(export_public_key(public_openssl, rsa));

                // compare public from OpenSSL and SecApi
                ASSERT_EQ(out, public_openssl);
            }
            default:
                break;
        }
    }

    TEST_F(SaKeyGetPublicTest, failsNullOutLength) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        auto clear_key = ec_generate_key_bytes(curve);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_ec(&rights, curve, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto out = std::vector<uint8_t>(512);

        sa_status status = sa_key_get_public(out.data(), nullptr, *key);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGetPublicTest, failsInvalidKey) {
        auto out = std::vector<uint8_t>(512);
        size_t out_length = out.size();
        sa_status status = sa_key_get_public(out.data(), &out_length, INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
