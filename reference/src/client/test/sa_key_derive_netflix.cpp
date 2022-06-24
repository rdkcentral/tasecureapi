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
#include "sa_key_derive_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaKeyDeriveNetflixTest, nominal) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        auto hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(hmac_key, nullptr);
        if (*hmac_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> clear_key(SYM_128_KEY_SIZE);
        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_key, clear_encryption_key, clear_hmac_key));
        ASSERT_TRUE(key_check_sym(*key, clear_key));
    }

    TEST_F(SaKeyDeriveNetflixTest, failsNullKey) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = INVALID_HANDLE};

        sa_status status = sa_key_derive(nullptr, &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsNullRights) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = INVALID_HANDLE};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), nullptr, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsNullParameters) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsUnknownEncryptionKey) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        auto hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(hmac_key, nullptr);
        if (*hmac_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = INVALID_HANDLE,
                .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsUnknownHmacKey) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = INVALID_HANDLE};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsEncKeyDisallowsDerive) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_DERIVE);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        SA_USAGE_BIT_SET(rights.usage_flags, SA_USAGE_FLAG_DERIVE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        auto hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(hmac_key, nullptr);
        if (*hmac_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsHmacKeyDisallowsDerive) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_DERIVE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        auto hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(hmac_key, nullptr);
        if (*hmac_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsEncKeyNotSymmetric) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto rsa_key = sample_rsa_2048_pkcs8();
        auto encryption_key = create_sa_key_rsa(&rights, rsa_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        auto hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(hmac_key, nullptr);
        if (*hmac_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }

    TEST_F(SaKeyDeriveNetflixTest, failsHmacKeyNotSymmetric) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        ASSERT_NE(encryption_key, nullptr);
        if (*encryption_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        auto rsa_key = sample_rsa_2048_pkcs8();
        auto hmac_key = create_sa_key_rsa(&rights, rsa_key);
        ASSERT_NE(hmac_key, nullptr);
        if (*hmac_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
                .kenc = *encryption_key,
                .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_TYPE);
    }
} // namespace
