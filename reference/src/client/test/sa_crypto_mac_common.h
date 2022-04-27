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

#ifndef SA_CRYPTO_MAC_COMMON_H
#define SA_CRYPTO_MAC_COMMON_H

#include "sa.h"
#include "gtest/gtest.h"

class SaCryptoMacBase {
public:
    static bool hmac_sha1_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& in);

    static bool hmac_sha256_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& in);

    static bool hmac_sha384_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& in);

    static bool hmac_sha512_openssl(
            std::vector<uint8_t>& out,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& in);
};

using SaCryptoMacType = std::tuple<sa_mac_algorithm, void*, int>;

class SaCryptoMacInit : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacInitArgChecks : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacInitKeyRights : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacInitInvalidKeyLengths : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacInitHmacDigests : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacCompute : public ::testing::TestWithParam<SaCryptoMacType> {};

class SaCryptoMacComputeOutLength
    : public ::testing::TestWithParam<std::tuple<sa_mac_algorithm, void*, int, size_t>> {};

using MacFunctionType = bool (*)(std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&);

class SaCryptoMacComputeMatchesOpenssl
    : public ::testing::TestWithParam<std::tuple<sa_mac_algorithm, void*, int, int, MacFunctionType>> {};

class SaCryptoMacComputeArgChecks : public ::testing::TestWithParam<std::tuple<sa_mac_algorithm, void*, int>> {};

class SaCryptoMacProcess : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacProcessKey : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacProcessArgChecks : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacProcessKeyArgChecks : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacRelease : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

class SaCryptoMacReleaseArgChecks : public ::testing::TestWithParam<SaCryptoMacType>, public SaCryptoMacBase {};

#endif // SA_CRYPTO_MAC_COMMON_H
