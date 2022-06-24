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

#ifdef ENABLE_SOC_KEY_TESTS

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

#define SOC_CONTAINER_VERSION 4

namespace {
    TEST_P(SaKeyImportSocAllKeyCombosTest, nominal) {
        std::string key_type_string = std::get<0>(GetParam());
        size_t key_size = std::get<1>(GetParam());
        sa_key_type key_type = std::get<2>(GetParam());
        uint8_t key_usage = std::get<3>(GetParam());
        uint8_t decrypted_key_usage = std::get<4>(GetParam());
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);

        auto curve = static_cast<sa_elliptic_curve>(0);
        std::vector<uint8_t> clear_key;
        if (key_type == SA_KEY_TYPE_EC) {
            curve = static_cast<sa_elliptic_curve>(key_size);
            key_size = ec_get_key_size(curve);
            clear_key = ec_generate_key_bytes(curve);
            if (clear_key.empty())
                GTEST_SKIP() << "Curve not supported";
        } else if (key_type == SA_KEY_TYPE_SYMMETRIC) {
            clear_key = random(key_size);
        } else if (key_type == SA_KEY_TYPE_RSA) {
            clear_key = get_rsa_private_key(key_size);
        }

        ASSERT_FALSE(clear_key.empty());
        sa_rights key_rights;
        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type_string, key_type, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        type_parameters.curve = curve;
        ASSERT_TRUE(memcmp(&key_rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_size, header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(key_type, header->type);

        // Test exporting and re-importing key
        auto mixin = random(AES_BLOCK_SIZE);
        auto exported_key_data = export_key(mixin, *key);
        ASSERT_NE(exported_key_data, nullptr);

        auto exported_key = create_uninitialized_sa_key();
        ASSERT_NE(exported_key, nullptr);

        status = sa_key_import(exported_key.get(), SA_KEY_FORMAT_EXPORTED, exported_key_data->data(),
                exported_key_data->size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);
        auto exported_key_header = key_header(*exported_key);
        ASSERT_NE(nullptr, exported_key_header.get());
        ASSERT_TRUE(memcmp(&key_rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_size, exported_key_header->size);
        ASSERT_EQ(memcmp(&type_parameters, &exported_key_header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(key_type, exported_key_header->type);

        ASSERT_TRUE(key_check(key_type, *exported_key, clear_key));
    }

    TEST_F(SaKeyImportSocTest, invalidKeyUsage1) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "HMAC-128";
        uint8_t key_usage = 2;
        uint8_t decrypted_key_usage = 2;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, invalidKeyUsage2) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "HMAC-160";
        uint8_t key_usage = 2;
        uint8_t decrypted_key_usage = 2;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, invalidKeyUsage3) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "HMAC-256";
        uint8_t key_usage = 2;
        uint8_t decrypted_key_usage = 2;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, invalidContainerVersion) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), 0, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, missingIv) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        std::vector<uint8_t> iv;
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, missingC1) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        std::vector<uint8_t> c1;
        auto iv = random(GCM_IV_LENGTH);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, missingC2) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        std::vector<uint8_t> c2;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, missingC3) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        std::vector<uint8_t> c3;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, unknownKeyType) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-64";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, unknownKeyUsage1) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 0;
        uint8_t decrypted_key_usage = 0;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, unknownKeyUsage2) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 4;
        uint8_t decrypted_key_usage = 0;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, unknownDecryptedKeyUsage1) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 2;
        uint8_t decrypted_key_usage = 0;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, unknownDecryptedKeyUsage2) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 2;
        uint8_t decrypted_key_usage = 4;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        sa_rights key_rights;

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, ENTITLED_TA_IDS, key_rights, c1, c2, c3);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportSocTest, failsDisallowedKey) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);

        std::vector<std::string> entitled_ta_ids = {"157f768f-bad0-470b-929d-0d7dec29d220"};

        sa_rights key_rights;
        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, entitled_ta_ids, key_rights, c1, c2, c3);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        // Key usage should fail due to disallowed TA ID.
        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_DECRYPT, *key,
                nullptr);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaKeyImportSocTaIdRangeTest, multipleEntitledTaIdsCounts) {
        std::vector<uint8_t> clear_key = random(SYM_128_KEY_SIZE);
        std::string key_type = "AES-128";
        uint8_t key_usage = 3;
        uint8_t decrypted_key_usage = 0;
        std::vector<std::string> entitled_ta_ids;
        auto iv = random(GCM_IV_LENGTH);
        auto c1 = random(AES_BLOCK_SIZE);
        auto c2 = random(AES_BLOCK_SIZE);
        auto c3 = random(AES_BLOCK_SIZE);
        int count = GetParam();
        sa_rights key_rights;

        for (int i = 0; i < count; i++) {
            std::string ta_id = "157f768f-bad0-470b-929d-0d7dec29d2";
            ta_id += static_cast<char>('0' + (i / 10));
            ta_id += static_cast<char>('0' + (i % 10));

            entitled_ta_ids.push_back(ta_id);

            if (i < MAX_NUM_ALLOWED_TA_IDS)
                convert_uuid(ta_id, &key_rights.allowed_tas[i]);
        }

        auto key = create_uninitialized_sa_key();
        sa_status status = import_key(key.get(), SOC_CONTAINER_VERSION, key_type, SA_KEY_TYPE_SYMMETRIC, clear_key, iv,
                key_usage, decrypted_key_usage, entitled_ta_ids, key_rights, c1, c2, c3);
        if (count > MAX_NUM_ALLOWED_TA_IDS) {
            ASSERT_NE(status, SA_STATUS_OK);
        } else {
            ASSERT_EQ(status, SA_STATUS_OK);

            sa_type_parameters type_parameters;
            memset(&type_parameters, 0, sizeof(sa_type_parameters));
            auto header = key_header(*key);
            ASSERT_NE(nullptr, header.get());
            ASSERT_TRUE(memcmp(&key_rights, &header->rights, sizeof(sa_rights)) == 0);
            ASSERT_EQ(clear_key.size(), header->size);
            ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
            ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header->type);

            // 0 entitled TAs implicitly adds the all TA IDs allowed value. 1 or more means the REE TA ID is disallowed
            // and it should fail.
            if (count == 0) {
                ASSERT_TRUE(key_check_sym(*key, clear_key));
            } else {
                ASSERT_FALSE(key_check_sym(*key, clear_key));
            }
        }
    }
} // namespace

#endif
