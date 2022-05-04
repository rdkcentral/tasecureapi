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
#ifndef SA_KEY_EXCHANGE_COMMON_H
#define SA_KEY_EXCHANGE_COMMON_H

#include "sa_key.h"
#include "sa_key_common.h"
#include "gtest/gtest.h"
#include <memory>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <vector>

class SaKeyExchangeTest : public ::testing::Test {};

using SaKeyExchangeDhTestType = std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>;

class SaKeyExchangeDhTest : public ::testing::TestWithParam<SaKeyExchangeDhTestType>, public SaKeyBase {};

using SaKeyExchangeEcdhTestType = std::tuple<sa_elliptic_curve>;

class SaKeyExchangeEcdhTest : public ::testing::TestWithParam<SaKeyExchangeEcdhTestType>, public SaKeyBase {};

using SaKeyExchangeNetflixTestType = std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>;

class SaKeyExchangeNetflixTest : public ::testing::TestWithParam<SaKeyExchangeNetflixTestType>, public SaKeyBase {
protected:
    static bool netflix_compute_secret(
            std::vector<uint8_t>& kenc,
            std::vector<uint8_t>& khmac,
            std::vector<uint8_t>& kwrap,
            const std::vector<uint8_t>& kd,
            const std::vector<uint8_t>& shared_secret);

    static bool setup_key_exchange(
            std::shared_ptr<sa_key>& kd,
            std::vector<uint8_t>& clear_kd,
            std::shared_ptr<sa_key>& dh_key,
            std::shared_ptr<EVP_PKEY>& dh_public_key,
            std::shared_ptr<EVP_PKEY>& other_dh,
            std::vector<uint8_t>& other_public_key,
            const std::vector<uint8_t>& dhp,
            const std::vector<uint8_t>& dhg);
};

#endif // SA_KEY_EXCHANGE_COMMON_H
