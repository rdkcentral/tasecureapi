/*
 * Copyright 2020-2026 Comcast Cable Communications Management, LLC
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
#include <string>
#include <tuple>
#include <vector>

using namespace client_test_helpers;

namespace {
    class SaKeyImportTypejIvBase : public SaKeyImportTypejBase {
    protected:
        // Imports a correctly signed v2/v3 container with the given base64 contentKeyTransportIv.
        static sa_status import_with_iv(
                int version,
                const std::string& iv_b64) {

            auto macclear_key = random(SYM_128_KEY_SIZE);
            sa_rights mackey_rights;
            sa_rights_set_allow_all(&mackey_rights);
            auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
            if (mackey == nullptr)
                return SA_STATUS_INTERNAL_ERROR;

            auto encclear_key = random(SYM_128_KEY_SIZE);
            sa_rights enckey_rights;
            sa_rights_set_allow_all(&enckey_rights);
            auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
            if (enckey == nullptr)
                return SA_STATUS_INTERNAL_ERROR;

            std::string body_json = "{\"contentKeyContainerVersion\": " + std::to_string(version) + ",";
            body_json += R"("contentKeyTransportAlgorithm": "aesCbcNone",)";
            body_json += R"("contentKeyTransportIv": ")" + iv_b64 + R"(",)";
            body_json += "\"contentKeyLength\": 16,"
                         "\"contentKey\": \"AAAAAAAAAAAAAAAAAAAAAA==\","
                         "\"contentKeyId\": \"id\","
                         "\"contentKeyRights\": \"AQ==\","
                         "\"contentKeyUsage\": 0,"
                         "\"contentKeyNotBefore\": \"1970-01-01T00:00:00Z\","
                         "\"contentKeyNotOnOrAfter\": \"2100-01-01T00:00:00Z\","
                         "\"contentKeyCacheable\": true}";
            std::string const hdr = generate_header();
            std::string const body = b64_encode(body_json.data(), body_json.size(), true);
            std::vector<uint8_t> signed_data(hdr.begin(), hdr.end());
            signed_data.push_back(static_cast<uint8_t>('.'));
            signed_data.insert(signed_data.end(), body.begin(), body.end());
            std::vector<uint8_t> mac_bytes(SHA256_DIGEST_LENGTH);
            if (!hmac_openssl(mac_bytes, macclear_key, signed_data, SA_DIGEST_ALGORITHM_SHA256))
                return SA_STATUS_INTERNAL_ERROR;

            std::string const typej = hdr + "." + body + "." + b64_encode(mac_bytes.data(), mac_bytes.size(), true);

            sa_import_parameters_typej parameters = {
                    .kcipher = *enckey,
                    .khmac = *mackey};

            auto key = create_uninitialized_sa_key();
            if (key == nullptr)
                return SA_STATUS_INTERNAL_ERROR;

            return sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(), &parameters);
        }
    };

    class SaKeyImportTypejIvTest : public ::testing::TestWithParam<int>,
                                   public SaKeyImportTypejIvBase {};

    class SaKeyImportTypejInvalidIvTest : public ::testing::TestWithParam<std::tuple<int, std::string>>,
                                          public SaKeyImportTypejIvBase {};

    // The same container with a 16 byte IV is accepted, so the failures below come from the IV length.
    TEST_P(SaKeyImportTypejIvTest, nominal) {
        ASSERT_EQ(import_with_iv(GetParam(), "AAAAAAAAAAAAAAAAAAAAAA=="), SA_STATUS_OK);
    }

    // A correctly signed v2/v3 container whose contentKeyTransportIv does not decode to 16 bytes is rejected.
    TEST_P(SaKeyImportTypejInvalidIvTest, failsInvalidIvLength) {
        ASSERT_EQ(import_with_iv(std::get<0>(GetParam()), std::get<1>(GetParam())), SA_STATUS_INVALID_KEY_FORMAT);
    }

    INSTANTIATE_TEST_SUITE_P(
            SaKeyImportTypejIvTests,
            SaKeyImportTypejIvTest,
            ::testing::Values(2, 3));

    INSTANTIATE_TEST_SUITE_P(
            SaKeyImportTypejInvalidIvTests,
            SaKeyImportTypejInvalidIvTest,
            ::testing::Combine(
                    ::testing::Values(2, 3),
                    ::testing::Values(
                            "AAAAAAAAAAA=",                                    // 8 bytes
                            "AAAAAAAAAAAAAAAAAAAA",                            // 15 bytes
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))); // 32 bytes
} // namespace
