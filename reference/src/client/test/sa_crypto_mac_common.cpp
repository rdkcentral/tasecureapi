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

#include "sa_crypto_mac_common.h" // NOLINT
#include "client_test_helpers.h"

using namespace client_test_helpers;

namespace {
    int cmac_key_lengths[] = {16, 32};
    int hmac_key_lengths[] = {16, 32, 64, 512};

    sa_mac_parameters_hmac hmac_sha1_params = {SA_DIGEST_ALGORITHM_SHA1};
    sa_mac_parameters_hmac hmac_sha256_params = {SA_DIGEST_ALGORITHM_SHA256};
    sa_mac_parameters_hmac hmac_sha384_params = {SA_DIGEST_ALGORITHM_SHA384};
    sa_mac_parameters_hmac hmac_sha512_params = {SA_DIGEST_ALGORITHM_SHA512};

    void* hmac_params_list[] = {
            static_cast<void*>(&hmac_sha1_params),
            static_cast<void*>(&hmac_sha256_params),
            static_cast<void*>(&hmac_sha384_params),
            static_cast<void*>(&hmac_sha512_params),
    };
} // namespace

bool SaCryptoMacBase::hmac_sha1_openssl(
        std::vector<uint8_t>& out,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& in) {

    return hmac_openssl(out, key, in, SA_DIGEST_ALGORITHM_SHA1);
}

bool SaCryptoMacBase::hmac_sha256_openssl(
        std::vector<uint8_t>& out,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& in) {

    return hmac_openssl(out, key, in, SA_DIGEST_ALGORITHM_SHA256);
}

bool SaCryptoMacBase::hmac_sha384_openssl(
        std::vector<uint8_t>& out,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& in) {

    return hmac_openssl(out, key, in, SA_DIGEST_ALGORITHM_SHA384);
}

bool SaCryptoMacBase::hmac_sha512_openssl(
        std::vector<uint8_t>& out,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& in) {

    return hmac_openssl(out, key, in, SA_DIGEST_ALGORITHM_SHA512);
}

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacInit,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacInitArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacInitKeyRights,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacInitInvalidKeyLengths,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::Values(18, 25, 64)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacInit,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacInitArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacInitKeyRights,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacInitHmacDigests,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacComputeOutLength,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths),
                ::testing::Values(16)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacComputeMatchesOpenssl,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths),
                ::testing::Values(0, 1, 8, 16, 32, 1023, 1024, 1025),
                ::testing::Values(cmac_openssl)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacComputeArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

// HMAC-SHA1
INSTANTIATE_TEST_SUITE_P(
        HmacSha1,
        SaCryptoMacComputeOutLength,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha1_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(20)));

INSTANTIATE_TEST_SUITE_P(
        HmacSha1,
        SaCryptoMacComputeMatchesOpenssl,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha1_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(0, 1, 8, 16, 32, 1023, 1024, 1025),
                ::testing::Values(SaCryptoMacBase::hmac_sha1_openssl)));

// HMAC-SHA256
INSTANTIATE_TEST_SUITE_P(
        HmacSha256,
        SaCryptoMacComputeOutLength,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha256_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(32)));

INSTANTIATE_TEST_SUITE_P(
        HmacSha256,
        SaCryptoMacComputeMatchesOpenssl,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha256_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(0, 1, 8, 16, 32, 1023, 1024, 1025),
                ::testing::Values(SaCryptoMacBase::hmac_sha256_openssl)));

// HMAC-SHA384
INSTANTIATE_TEST_SUITE_P(
        HmacSha384,
        SaCryptoMacComputeOutLength,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha384_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(48)));

INSTANTIATE_TEST_SUITE_P(
        HmacSha384,
        SaCryptoMacComputeMatchesOpenssl,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha384_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(0, 1, 8, 16, 32, 1023, 1024, 1025),
                ::testing::Values(SaCryptoMacBase::hmac_sha384_openssl)));

// HMAC-SHA512
INSTANTIATE_TEST_SUITE_P(
        HmacSha512,
        SaCryptoMacComputeOutLength,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha512_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(64)));

INSTANTIATE_TEST_SUITE_P(
        HmacSha512,
        SaCryptoMacComputeMatchesOpenssl,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::Values((void*) &hmac_sha512_params),
                ::testing::ValuesIn(hmac_key_lengths),
                ::testing::Values(0, 1, 8, 16, 32, 1023, 1024, 1025),
                ::testing::Values(SaCryptoMacBase::hmac_sha512_openssl)));

// Common argument checking tests.
INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacComputeArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacProcess,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacProcessKey,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacProcessArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacProcessKeyArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacProcess,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacProcessKey,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacProcessArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacProcessKeyArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacRelease,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Cmac,
        SaCryptoMacReleaseArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_CMAC),
                ::testing::Values(nullptr),
                ::testing::ValuesIn(cmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacRelease,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));

INSTANTIATE_TEST_SUITE_P(
        Hmac,
        SaCryptoMacReleaseArgChecks,
        ::testing::Combine(
                ::testing::Values(SA_MAC_ALGORITHM_HMAC),
                ::testing::ValuesIn(hmac_params_list),
                ::testing::ValuesIn(hmac_key_lengths)));
