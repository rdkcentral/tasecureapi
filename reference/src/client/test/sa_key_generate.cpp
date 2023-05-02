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
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyGenerateTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        sa_elliptic_curve curve;
        std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> dh_parameters;
        void* parameters;
        sa_generate_parameters_symmetric parameters_symmetric;
        sa_generate_parameters_ec parameters_ec;
        sa_generate_parameters_dh parameters_dh;
        sa_generate_parameters_rsa parameters_rsa;
        switch (key_type) {
            case SA_KEY_TYPE_EC: {
                curve = static_cast<sa_elliptic_curve>(key_length);
                key_length = ec_get_key_size(static_cast<sa_elliptic_curve>(curve));
                parameters_ec.curve = static_cast<sa_elliptic_curve>(curve);
                parameters = &parameters_ec;
                break;
            }
            case SA_KEY_TYPE_SYMMETRIC: {
                parameters_symmetric.key_length = key_length;
                parameters = &parameters_symmetric;
                break;
            }
            case SA_KEY_TYPE_RSA: {
                parameters_rsa.modulus_length = key_length;
                parameters = &parameters_rsa;
                break;
            }
            case SA_KEY_TYPE_DH: {
                dh_parameters = get_dh_parameters(key_length);
                parameters_dh.p = std::get<0>(dh_parameters).data();
                parameters_dh.p_length = std::get<0>(dh_parameters).size();
                parameters_dh.g = std::get<1>(dh_parameters).data();
                parameters_dh.g_length = std::get<1>(dh_parameters).size();
                parameters = &parameters_dh;
                break;
            }
            default:
                FAIL();
        }

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status status = sa_key_generate(key.get(), &rights, key_type, parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        memset(&type_parameters, 0, sizeof(sa_type_parameters));
        if (key_type == SA_KEY_TYPE_DH) {
            memcpy(type_parameters.dh_parameters.p, std::get<0>(dh_parameters).data(),
                    std::get<0>(dh_parameters).size());
            type_parameters.dh_parameters.p_length = std::get<0>(dh_parameters).size();
            memcpy(type_parameters.dh_parameters.g, std::get<1>(dh_parameters).data(),
                    std::get<1>(dh_parameters).size());
            type_parameters.dh_parameters.g_length = std::get<1>(dh_parameters).size();
        } else if (key_type == SA_KEY_TYPE_EC) {
            type_parameters.curve = curve;
        }

        auto header = key_header(*key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(key_length, header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(key_type, header->type);

        auto clear_data = random(AES_BLOCK_SIZE);
        std::vector<uint8_t> encrypted_data;
        sa_cipher_algorithm cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
        if (key_type == SA_KEY_TYPE_EC || key_type == SA_KEY_TYPE_RSA) {
            size_t public_key_length = 0;
            ASSERT_EQ(sa_key_get_public(nullptr, &public_key_length, *key), SA_STATUS_OK);
            std::vector<uint8_t> public_key(public_key_length);
            ASSERT_EQ(sa_key_get_public(public_key.data(), &public_key_length, *key), SA_STATUS_OK);
            std::shared_ptr<EVP_PKEY> const evp_public_key =
                    {sa_import_public_key(public_key.data(), public_key.size()), EVP_PKEY_free};
            ASSERT_NE(evp_public_key, nullptr);

            if (key_type == SA_KEY_TYPE_RSA) {
                ASSERT_TRUE(encrypt_rsa_pkcs1v15_openssl(encrypted_data, clear_data, evp_public_key));
                cipher_algorithm = SA_CIPHER_ALGORITHM_RSA_PKCS1V15;
            } else if (is_pcurve(curve)) {
                std::vector<uint8_t> in(ec_get_key_size(curve));
                std::copy(clear_data.begin(), clear_data.end(), in.begin() + 1);
                ASSERT_TRUE(encrypt_ec_elgamal_openssl(encrypted_data, in, curve, evp_public_key));
                cipher_algorithm = SA_CIPHER_ALGORITHM_EC_ELGAMAL;
            }
        } else if (key_type == SA_KEY_TYPE_SYMMETRIC &&
                   (key_length == SYM_128_KEY_SIZE || key_length == SYM_256_KEY_SIZE)) {
            cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
            auto cipher = create_uninitialized_sa_crypto_cipher_context();
            status = sa_crypto_cipher_init(cipher.get(), cipher_algorithm, SA_CIPHER_MODE_ENCRYPT, *key, nullptr);
            ASSERT_EQ(status, SA_STATUS_OK);
            size_t encrypted_data_length = clear_data.size();
            sa_buffer in = {SA_BUFFER_TYPE_CLEAR, {.clear = {clear_data.data(), clear_data.size(), 0}}};
            ASSERT_EQ(sa_crypto_cipher_process(nullptr, *cipher, &in, &encrypted_data_length), SA_STATUS_OK);
            encrypted_data.resize(encrypted_data_length);
            encrypted_data_length = clear_data.size();
            sa_buffer out = {SA_BUFFER_TYPE_CLEAR, {.clear = {encrypted_data.data(), encrypted_data.size(), 0}}};
            ASSERT_EQ(sa_crypto_cipher_process(&out, *cipher, &in, &encrypted_data_length), SA_STATUS_OK);
        }

        if (!encrypted_data.empty()) {
            auto cipher = create_uninitialized_sa_crypto_cipher_context();
            sa_buffer in = {SA_BUFFER_TYPE_CLEAR, {.clear = {encrypted_data.data(), encrypted_data.size(), 0}}};
            status = sa_crypto_cipher_init(cipher.get(), cipher_algorithm, SA_CIPHER_MODE_DECRYPT, *key, nullptr);
            ASSERT_EQ(status, SA_STATUS_OK);
            size_t decrypted_data_length = encrypted_data.size();
            ASSERT_EQ(sa_crypto_cipher_process(nullptr, *cipher, &in, &decrypted_data_length), SA_STATUS_OK);
            std::vector<uint8_t> decrypted_data(decrypted_data_length);
            decrypted_data_length = encrypted_data.size();
            sa_buffer out = {SA_BUFFER_TYPE_CLEAR, {.clear = {decrypted_data.data(), decrypted_data.size(), 0}}};
            ASSERT_EQ(sa_crypto_cipher_process(&out, *cipher, &in, &decrypted_data_length), SA_STATUS_OK);
            decrypted_data.resize(decrypted_data_length);
            if (key_type == SA_KEY_TYPE_EC) {
                decrypted_data.erase(decrypted_data.begin());
                decrypted_data.resize(clear_data.size());
            }

            ASSERT_EQ(clear_data, decrypted_data);
        }
    }

    TEST_F(SaKeyGenerateTest, failsNullKey) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric parameters = {AES_BLOCK_SIZE};

        sa_status const status = sa_key_generate(nullptr, &rights, SA_KEY_TYPE_SYMMETRIC, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsNullRights) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_generate_parameters_symmetric parameters = {AES_BLOCK_SIZE};

        sa_status const status = sa_key_generate(key.get(), nullptr, SA_KEY_TYPE_SYMMETRIC, &parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyGenerateTest, failsInvalidKeyType) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_symmetric parameters = {128};

        sa_status const status = sa_key_generate(key.get(), &rights, static_cast<sa_key_type>(UINT8_MAX), &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
