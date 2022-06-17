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

#ifndef SA_KEY_IMPORT_COMMON_H
#define SA_KEY_IMPORT_COMMON_H

#include "sa_key.h"
#include "sa_key_common.h"
#include "gtest/gtest.h"
#include <memory>
#include <vector>

#define DATA_AND_KEY_MASK 0

#define DATA_ONLY_MASK SA_USAGE_BIT_MASK(SA_USAGE_FLAG_UNWRAP)

#define KEY_ONLY_MASK (SA_USAGE_BIT_MASK(SA_USAGE_FLAG_DECRYPT) | \
                       SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ENCRYPT) | \
                       SA_USAGE_BIT_MASK(SA_USAGE_FLAG_SIGN) | \
                       SA_USAGE_BIT_MASK(SA_USAGE_FLAG_DERIVE))

#define NO_ALLOWED_OUTPUTS_MASK (SA_USAGE_BIT_MASK(SA_USAGE_FLAG_SVP_OPTIONAL) | \
                                 SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED) | \
                                 SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) | \
                                 SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14) | \
                                 SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22) | \
                                 SA_USAGE_BIT_MASK(SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP))

#define NOT_CACHEABLE_MASK SA_USAGE_BIT_MASK(SA_USAGE_FLAG_CACHEABLE)

#define SVP_REQUIRED_MASK SA_USAGE_BIT_MASK(SA_USAGE_FLAG_SVP_OPTIONAL) | SA_USAGE_BIT_MASK(SA_USAGE_FLAG_UNWRAP)

#define RIGHT_NOT_SET 0x00
#define RIGHT_SVP_REQUIRED 0x01
#define RIGHT_DIGITAL_OPL_DTCP_ALLOWED 0x02
#define RIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED 0x03
#define RIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED 0x04
#define RIGHT_ANALOG_OUTPUT_ALLOWED 0x05
#define RIGHT_CGMSA_REQUIRED 0x08

class SaKeyImportBase : public SaKeyBase {
protected:
    static std::shared_ptr<std::vector<uint8_t>> export_key(
            std::vector<uint8_t>& mixin,
            sa_key key);

    static bool convert_uuid(
            std::string uuid_str,
            sa_uuid* uuid);
};

class SaKeyImportTest : public ::testing::TestWithParam<SaKeyType>, public SaKeyImportBase {};

class SaKeyImportTypejBase : public SaKeyImportBase {
protected:
    static std::string generate_header();

    static std::string generate_content_key(
            sa_cipher_algorithm cipher_algorithm,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& enckey);

    static std::string generate_content_key_rights(const sa_rights* rights);

    static size_t generate_content_key_usage(const sa_rights* rights);

    static std::string generate_body_v1(
            const sa_rights* rights,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& enckey);

    static const char* typej_algorithm_string(sa_cipher_algorithm cipher_algorithm);

    static std::string generate_body_v2(
            sa_cipher_algorithm cipher_algorithm,
            const sa_rights* rights,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& enckey);

    static std::string generate_body_v3(
            sa_cipher_algorithm cipher_algorithm,
            const sa_rights* rights,
            std::vector<std::string>& entitled_ta_ids,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& enckey);

    static std::string generate_typej_v1(
            const sa_rights* rights,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& mackey,
            const std::vector<uint8_t>& enckey,
            bool good_signature = true);

    static std::string generate_typej_v2(
            sa_cipher_algorithm cipher_algorithm,
            const sa_rights* rights,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& mackey,
            const std::vector<uint8_t>& enckey,
            bool good_signature = true);

    static std::string generate_typej_v3(
            sa_cipher_algorithm cipher_algorithm,
            const sa_rights* rights,
            std::vector<std::string>& entitled_ta_ids,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& mackey,
            const std::vector<uint8_t>& enckey,
            bool good_signature = true);

    static void typej_rights_set_allow_all(sa_rights* rights);
};

using SaKeyImportTypejType = std::tuple<size_t, sa_cipher_algorithm, uint64_t>;

class SaKeyImportTypejTest : public ::testing::TestWithParam<SaKeyImportTypejType>, public SaKeyImportTypejBase {};

class SaKeyImportTypejTaIdRangeTest : public ::testing::TestWithParam<int>, public SaKeyImportTypejBase {};

class SaKeyImportSocBase : public SaKeyImportBase {
protected:
    static std::vector<std::string> ENTITLED_TA_IDS;

    static std::string generate_encrypted_key(
            uint8_t container_version,
            std::string& key_type,
            std::vector<uint8_t>& key,
            std::vector<uint8_t>& iv,
            uint8_t key_usage,
            uint8_t decrypted_key_usage,
            std::vector<std::string>& entitled_ta_ids,
            std::vector<uint8_t>& c1,
            std::vector<uint8_t>& c2,
            std::vector<uint8_t>& c3,
            std::vector<uint8_t>& tag);

    static std::string generate_header();

    static std::string generate_payload(
            uint8_t container_version,
            std::string& key_type,
            std::vector<uint8_t>& key,
            std::vector<uint8_t>& iv,
            uint8_t key_usage,
            uint8_t decrypted_key_usage,
            std::vector<std::string>& entitled_ta_ids,
            std::vector<uint8_t>& c1,
            std::vector<uint8_t>& c2,
            std::vector<uint8_t>& c3,
            std::vector<uint8_t>& tag);

    static void set_key_usage_flags(
            uint8_t key_usage,
            uint8_t decrypted_key_usage,
            sa_rights& rights,
            sa_key_type key_type);

    static sa_status import_key(
            sa_key* key,
            uint8_t container_version,
            std::string& key_type,
            sa_key_type clear_key_type,
            std::vector<uint8_t>& clear_key,
            std::vector<uint8_t>& iv,
            uint8_t key_usage,
            uint8_t decrypted_key_usage,
            std::vector<std::string>& entitled_ta_ids,
            sa_rights& key_rights,
            std::vector<uint8_t>& c1,
            std::vector<uint8_t>& c2,
            std::vector<uint8_t>& c3);
};

class SaKeyImportSocTest : public ::testing::Test, public SaKeyImportSocBase {};

using SaKeyImportSocAllKeyCombosType =
        std::tuple<std::string, size_t, sa_key_type, uint8_t, uint8_t>;

class SaKeyImportSocAllKeyCombosTest
    : public ::testing::TestWithParam<SaKeyImportSocAllKeyCombosType>,
      public SaKeyImportSocBase {};

class SaKeyImportSocTaIdRangeTest : public ::testing::TestWithParam<int>, public SaKeyImportSocBase {};

#endif // SA_KEY_IMPORT_COMMON_H
