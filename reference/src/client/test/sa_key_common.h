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

#ifndef SA_KEY_COMMON_H
#define SA_KEY_COMMON_H

#include "common.h"
#include "sa_types.h"
#include "gtest/gtest.h"
#include <memory>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <vector>

class SaKeyBase {
protected:
    static bool get_root_key(std::vector<uint8_t>& key);

    static bool dh_generate_key(
            std::shared_ptr<EVP_PKEY>& evp_pkey,
            std::vector<uint8_t>& public_key,
            const std::vector<uint8_t>& p,
            const std::vector<uint8_t>& g);

    static bool dh_compute_secret(
            std::vector<uint8_t>& shared_secret,
            const std::shared_ptr<EVP_PKEY>& private_key,
            const std::shared_ptr<EVP_PKEY>& other_public_key,
            const std::vector<uint8_t>& p,
            const std::vector<uint8_t>& g);

    static sa_status ec_generate_key(
            sa_elliptic_curve curve,
            std::shared_ptr<EVP_PKEY>& private_key,
            std::vector<uint8_t>& public_key);

    static bool ecdh_compute_secret(
            sa_elliptic_curve curve,
            std::vector<uint8_t>& shared_secret,
            const std::shared_ptr<EVP_PKEY>& private_key,
            const std::shared_ptr<EVP_PKEY>& other_public_key);

    static bool execute_dh(
            std::shared_ptr<sa_key>& shared_secret,
            std::vector<uint8_t>& clear_shared_secret,
            const std::vector<uint8_t>& dhp,
            const std::vector<uint8_t>& dhg);

    static sa_status execute_ecdh(
            sa_elliptic_curve curve,
            std::shared_ptr<sa_key>& shared_secret,
            std::vector<uint8_t>& clear_shared_secret);

    static std::shared_ptr<std::vector<uint8_t>> derive_test_key_ladder(
            std::vector<uint8_t>& c1,
            std::vector<uint8_t>& c2,
            std::vector<uint8_t>& c3,
            std::vector<uint8_t>& c4);

    static bool hkdf(
            std::vector<uint8_t>& out,
            std::vector<uint8_t>& key,
            std::vector<uint8_t>& salt,
            std::vector<uint8_t>& info,
            sa_digest_algorithm digest_algorithm);

    static bool ansi_x963_kdf(
            std::vector<uint8_t>& out,
            std::vector<uint8_t>& key,
            std::vector<uint8_t>& info,
            sa_digest_algorithm digest_algorithm);

    static bool concat_kdf(
            std::vector<uint8_t>& out,
            std::vector<uint8_t>& key,
            std::vector<uint8_t>& info,
            sa_digest_algorithm digest_algorithm);

    static bool cmac_kdf(
            std::vector<uint8_t>& out,
            std::vector<uint8_t>& key,
            std::vector<uint8_t>& other_data,
            uint8_t counter);

    static bool netflix_wrapping_key_kdf(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& encryption_key,
            const std::vector<uint8_t>& hmac_key);

    static std::string b64_encode(
            const void* in,
            size_t in_length,
            bool url_encode);

    static bool key_check(
            sa_key_type key_type,
            sa_key key,
            std::vector<uint8_t>& clear_key);

private:
    static std::vector<uint8_t> root_key;
};

using SaKeyType = std::tuple<sa_key_type, size_t>;

class SaKeyGetPublicTest : public ::testing::TestWithParam<SaKeyType>, public SaKeyBase {};

class SaKeyGenerateTest : public ::testing::TestWithParam<SaKeyType> {};

class SaKeyExportTest : public ::testing::TestWithParam<SaKeyType>, public SaKeyBase {};

class SaKeyHeaderTest : public ::testing::Test {};

class SaKeyReleaseTest : public ::testing::Test {};

using SaKeyDigestType = std::tuple<sa_key_type, size_t, sa_digest_algorithm>;

class SaKeyDigestTest : public ::testing::TestWithParam<SaKeyDigestType> {};

#endif // SA_KEY_COMMON_H
