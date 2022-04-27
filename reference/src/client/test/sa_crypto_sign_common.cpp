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

#include "sa_crypto_sign_common.h" // NOLINT
#include "client_test_helpers.h"

INSTANTIATE_TEST_SUITE_P(
        SaCryptoSignEC,
        SaCryptoSign,
        ::testing::Combine(
                ::testing::Values(SA_SIGNATURE_ALGORITHM_ECDSA),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384, SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0),
                ::testing::Values(true, false)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoSignED,
        SaCryptoSign,
        ::testing::Combine(
                ::testing::Values(SA_SIGNATURE_ALGORITHM_EDDSA),
                ::testing::Values(SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_ED448),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0),
                ::testing::Values(false)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoSignRsaPkcs1v15,
        SaCryptoSign,
        ::testing::Combine(
                ::testing::Values(SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH, RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384, SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0),
                ::testing::Values(true, false)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoSignRsaPss,
        SaCryptoSign,
        ::testing::Combine(
                ::testing::Values(SA_SIGNATURE_ALGORITHM_RSA_PSS),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH, RSA_4096_BYTE_LENGTH),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384, SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 32),
                ::testing::Values(true, false)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoSignRsaPssMax,
        SaCryptoSign,
        ::testing::Values(
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 106, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 94, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 78, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 62, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 234, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 222, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 206, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 190, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 362, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 350, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 334, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 318, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 490, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 478, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 462, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 446, true),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 106, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 94, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 78, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_1024_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 62, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 234, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 222, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 206, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_2048_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 190, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 362, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 350, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 334, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_3072_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 318, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA1, 490, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA256, 478, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA384, 462, false),
                std::make_tuple(SA_SIGNATURE_ALGORITHM_RSA_PSS, RSA_4096_BYTE_LENGTH, SA_DIGEST_ALGORITHM_SHA512, 446, false)));
