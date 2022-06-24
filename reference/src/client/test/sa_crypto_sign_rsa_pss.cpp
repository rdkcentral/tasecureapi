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
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST(SaCryptoSign, nominal2048RsaPssSha256Salt32EmptyIn) {
        auto clear_key = sample_rsa_2048_pkcs8();
        sa_digest_algorithm digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
        sa_digest_algorithm mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_sign_parameters_rsa_pss parameters = {digest_algorithm, mgf1_digest_algorithm, false, 32};
        size_t out_length = 0;
        sa_status status = sa_crypto_sign(nullptr, &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, nullptr, 0,
                &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, 256);

        auto out = std::vector<uint8_t>(out_length);
        auto in = std::vector<uint8_t>(0);
        status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, in.data(), in.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);
        out.resize(out_length);

        // verify signature using OpenSSL
        auto rsa_key = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa_key, nullptr);

        ASSERT_TRUE(verify_rsa_pss_openssl(rsa_key, digest_algorithm, parameters.mgf1_digest_algorithm,
                parameters.salt_length, in, out));
    }

    TEST(SaCryptoSign, failsRsaPssInvalidOutLength) {
        auto clear_key = sample_rsa_2048_pkcs8();
        sa_digest_algorithm digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
        sa_digest_algorithm mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        sa_sign_parameters_rsa_pss parameters = {digest_algorithm, mgf1_digest_algorithm, false, 32};
        size_t out_length = 0;
        sa_status status = sa_crypto_sign(nullptr, &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, nullptr, 0,
                &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, 256);

        auto out = std::vector<uint8_t>(out_length);
        out_length -= 1;
        auto in = random(25);
        status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, in.data(), in.size(),
                &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaCryptoSign, failsRsaPssNullParameters) {
        auto clear_key = sample_rsa_2048_pkcs8();

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto out = std::vector<uint8_t>(512);
        size_t out_length = out.size();
        auto in = random(25);
        sa_status status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, in.data(),
                in.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST(SaCryptoSign, failsRsaPssInvalidSaltLength) {
        auto clear_key = sample_rsa_2048_pkcs8();
        sa_digest_algorithm digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
        sa_digest_algorithm mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        // max salt length is mod_length - digest_length - 2 = 222
        sa_sign_parameters_rsa_pss parameters = {digest_algorithm, mgf1_digest_algorithm, false, 223};
        auto out = std::vector<uint8_t>(512);
        size_t out_length = out.size();
        auto in = random(25);
        sa_status status = sa_crypto_sign(out.data(), &out_length, SA_SIGNATURE_ALGORITHM_RSA_PSS, *key, in.data(),
                in.size(), &parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
