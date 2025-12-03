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
    TEST_F(SaKeyImportTypejTest, nominalTypejV1) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v1(&key_rights, clear_key, macclear_key, encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&key_rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_key.size(), header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header->type);

        ASSERT_TRUE(key_check_sym(*key, clear_key));
    }

    TEST_P(SaKeyImportTypejTest, nominalV2) {
        auto key_size = std::get<0>(GetParam());
        auto algorithm = std::get<1>(GetParam());
        auto usage_flags_mask = std::get<2>(GetParam());

        // SVP not supported - always clear SVP_OPTIONAL flag
        SA_USAGE_BIT_CLEAR(usage_flags_mask, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto clear_key = random(key_size);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);
        key_rights.usage_flags &= ~usage_flags_mask;

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v2(algorithm, &key_rights, clear_key, macclear_key, encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&key_rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_key.size(), header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header->type);

        if (std::get<2>(GetParam()) != NO_ALLOWED_OUTPUTS_MASK) {
            ASSERT_TRUE(key_check_sym(*key, clear_key));
        }

        // Test exporting and re-importing key
        auto mixin = random(AES_BLOCK_SIZE);
        auto exported_key_data = export_key(mixin, *key);
        if (usage_flags_mask == NOT_CACHEABLE_MASK) {
            ASSERT_EQ(exported_key_data, nullptr);
        } else {
            ASSERT_NE(exported_key_data, nullptr);

            auto exported_key = create_uninitialized_sa_key();
            ASSERT_NE(exported_key, nullptr);

            status = sa_key_import(exported_key.get(), SA_KEY_FORMAT_EXPORTED, exported_key_data->data(),
                    exported_key_data->size(), nullptr);
            ASSERT_EQ(status, SA_STATUS_OK);
            auto exported_key_header = key_header(*exported_key);
            ASSERT_NE(nullptr, exported_key_header.get());
            ASSERT_TRUE(memcmp(&key_rights, &exported_key_header->rights, sizeof(sa_rights)) == 0);
            ASSERT_EQ(clear_key.size(), exported_key_header->size);
            ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
            ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, exported_key_header->type);

            if (std::get<2>(GetParam()) != NO_ALLOWED_OUTPUTS_MASK) {
                ASSERT_TRUE(key_check_sym(*exported_key, clear_key));
            }
        }
    }

    TEST_P(SaKeyImportTypejTest, nominalV3) {
        auto key_size = std::get<0>(GetParam());
        auto algorithm = std::get<1>(GetParam());
        auto usage_flags_mask = std::get<2>(GetParam());

        // SVP not supported - always clear SVP_OPTIONAL flag
        SA_USAGE_BIT_CLEAR(usage_flags_mask, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto clear_key = random(key_size);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);
        key_rights.usage_flags &= ~usage_flags_mask;

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        std::vector<std::string> entitled_ta_ids;
        auto typej = generate_typej_v3(algorithm, &key_rights, entitled_ta_ids, clear_key, macclear_key, encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&key_rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_key.size(), header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header->type);

        if (std::get<2>(GetParam()) != NO_ALLOWED_OUTPUTS_MASK) {
            ASSERT_TRUE(key_check_sym(*key, clear_key));
        }

        // Test exporting and re-importing key
        auto mixin = random(AES_BLOCK_SIZE);
        auto exported_key_data = export_key(mixin, *key);
        if (usage_flags_mask == NOT_CACHEABLE_MASK) {
            ASSERT_EQ(exported_key_data, nullptr);
        } else {
            ASSERT_NE(exported_key_data, nullptr);

            auto exported_key = create_uninitialized_sa_key();
            ASSERT_NE(exported_key, nullptr);

            status = sa_key_import(exported_key.get(), SA_KEY_FORMAT_EXPORTED, exported_key_data->data(),
                    exported_key_data->size(), nullptr);
            ASSERT_EQ(status, SA_STATUS_OK);

            auto exported_key_header = key_header(*exported_key);
            ASSERT_NE(nullptr, exported_key_header.get());
            ASSERT_TRUE(memcmp(&key_rights, &exported_key_header->rights, sizeof(sa_rights)) == 0);
            ASSERT_EQ(clear_key.size(), exported_key_header->size);
            ASSERT_EQ(memcmp(&type_parameters, &exported_key_header->type_parameters, sizeof(sa_type_parameters)), 0);
            ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, exported_key_header->type);

            if (std::get<2>(GetParam()) != NO_ALLOWED_OUTPUTS_MASK) {
                ASSERT_TRUE(key_check_sym(*exported_key, clear_key));
            }
        }
    }

    TEST_F(SaKeyImportTypejTest, failsDisallowedKey) {
        auto key_size = SYM_128_KEY_SIZE;
        auto algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
        auto usage_flags_mask = DATA_AND_KEY_MASK;

        // SVP not supported - always clear SVP_OPTIONAL flag
        SA_USAGE_BIT_CLEAR(usage_flags_mask, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto clear_key = random(key_size);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);
        key_rights.usage_flags &= ~usage_flags_mask;

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        std::vector<std::string> entitled_ta_ids = {"157f768f-bad0-470b-929d-0d7dec29d220"};
        auto typej = generate_typej_v3(algorithm, &key_rights, entitled_ta_ids, clear_key, macclear_key, encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Key usage should fail due to disallowed TA ID.
        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_DECRYPT, *key,
                nullptr);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaKeyImportTypejTaIdRangeTest, multipleEntitledTaIdsCounts) {
        auto key_size = SYM_128_KEY_SIZE;
        auto algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
        auto usage_flags_mask = DATA_AND_KEY_MASK;
        int const count = GetParam();
        std::vector<std::string> entitled_ta_ids;

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);
        key_rights.usage_flags &= ~usage_flags_mask;

        for (int i = 0; i < count; i++) {
            std::string ta_id = "157f768f-bad0-470b-929d-0d7dec29d2";
            ta_id += static_cast<char>('0' + (i / 10));
            ta_id += static_cast<char>('0' + (i % 10));

            entitled_ta_ids.push_back(ta_id);

            if (i < MAX_NUM_ALLOWED_TA_IDS)
                convert_uuid(ta_id, &key_rights.allowed_tas[i]);
        }

        auto clear_key = random(key_size);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v3(algorithm, &key_rights, entitled_ta_ids, clear_key, macclear_key, encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
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

    TEST_F(SaKeyImportTypejTest, failsTypejInvalidKeyContainer) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, clear_key.data(),
                clear_key.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportTypejTest, failsTypejInvalidSignature) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v2(SA_CIPHER_ALGORITHM_AES_ECB, &key_rights, clear_key, macclear_key,
                encclear_key, false);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyImportTypejTest, failsTypejNullParameters) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v2(SA_CIPHER_ALGORITHM_AES_ECB, &key_rights, clear_key, macclear_key,
                encclear_key, false);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyImportTypejTest, failsTypejInvalidKcipherHandle) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        auto typej = generate_typej_v2(SA_CIPHER_ALGORITHM_AES_ECB, &key_rights, clear_key, macclear_key,
                encclear_key, false);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_import_parameters_typej parameters = {
                .kcipher = INVALID_HANDLE,
                .khmac = *mackey};

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyImportTypejTest, failsTypejInvalidKmacHandle) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v2(SA_CIPHER_ALGORITHM_AES_ECB, &key_rights, clear_key, macclear_key,
                encclear_key, false);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = INVALID_HANDLE};

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyImportTypejTest, failsTypejKcipherNoUnwrapFlag) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);
        SA_USAGE_BIT_CLEAR(enckey_rights.usage_flags, SA_USAGE_FLAG_UNWRAP);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v2(SA_CIPHER_ALGORITHM_AES_ECB, &key_rights, clear_key, macclear_key,
                encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyImportTypejTest, failsTypejKmacNoSignFlag) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights key_rights;
        typej_rights_set_allow_all(&key_rights);

        auto macclear_key = random(SYM_128_KEY_SIZE);

        sa_rights mackey_rights;
        sa_rights_set_allow_all(&mackey_rights);
        SA_USAGE_BIT_CLEAR(mackey_rights.usage_flags, SA_USAGE_FLAG_SIGN);

        auto mackey = create_sa_key_symmetric(&mackey_rights, macclear_key);
        ASSERT_NE(mackey, nullptr);

        auto encclear_key = random(SYM_128_KEY_SIZE);

        sa_rights enckey_rights;
        sa_rights_set_allow_all(&enckey_rights);

        auto enckey = create_sa_key_symmetric(&enckey_rights, encclear_key);
        ASSERT_NE(enckey, nullptr);

        auto typej = generate_typej_v2(SA_CIPHER_ALGORITHM_AES_ECB, &key_rights, clear_key, macclear_key,
                encclear_key);

        sa_import_parameters_typej parameters = {
                .kcipher = *enckey,
                .khmac = *mackey};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_status const status = sa_key_import(key.get(), SA_KEY_FORMAT_TYPEJ, typej.data(), typej.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
