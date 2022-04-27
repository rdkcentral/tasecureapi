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

#include "sa_key_derive_common.h"
#include "client_test_helpers.h"

INSTANTIATE_TEST_SUITE_P(
        SaKeyDeriveNominalTests,
        SaKeyDeriveAnsiX963Test,
        ::testing::Combine(
                ::testing::Values(
                        std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                        std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_768_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_1024_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_1536_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_2048_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_3072_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_4096_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448)),
                ::testing::Values(
                        SA_DIGEST_ALGORITHM_SHA1,
                        SA_DIGEST_ALGORITHM_SHA256,
                        SA_DIGEST_ALGORITHM_SHA384,
                        SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyDeriveNominalTests,
        SaKeyDeriveCmacTest,
        ::testing::Values(
                std::make_tuple(SYM_128_KEY_SIZE, 0, 1),
                std::make_tuple(SYM_128_KEY_SIZE, 0, 2),
                std::make_tuple(SYM_128_KEY_SIZE, 0, 3),
                std::make_tuple(SYM_128_KEY_SIZE, 0, 4),
                std::make_tuple(SYM_256_KEY_SIZE, 0, 1),
                std::make_tuple(SYM_256_KEY_SIZE, 0, 3),
                std::make_tuple(SYM_128_KEY_SIZE, 16, 1),
                std::make_tuple(SYM_128_KEY_SIZE, 16, 2),
                std::make_tuple(SYM_128_KEY_SIZE, 16, 3),
                std::make_tuple(SYM_128_KEY_SIZE, 16, 4),
                std::make_tuple(SYM_256_KEY_SIZE, 16, 1),
                std::make_tuple(SYM_256_KEY_SIZE, 16, 3)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyDeriveNominalTests,
        SaKeyDeriveConcatTest,
        ::testing::Combine(
                ::testing::Values(
                        std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                        std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_768_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_1024_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_1536_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_2048_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_3072_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_4096_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448)),
                ::testing::Values(
                        SA_DIGEST_ALGORITHM_SHA1,
                        SA_DIGEST_ALGORITHM_SHA256,
                        SA_DIGEST_ALGORITHM_SHA384,
                        SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyDeriveNominalTests,
        SaKeyDeriveHkdfTest,
        ::testing::Combine(
                ::testing::Values(
                        std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                        std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_768_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_1024_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_1536_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_2048_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_3072_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_DH, DH_4096_BYTE_LENGTH),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                        std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448)),
                ::testing::Values(
                        SA_DIGEST_ALGORITHM_SHA1,
                        SA_DIGEST_ALGORITHM_SHA256,
                        SA_DIGEST_ALGORITHM_SHA384,
                        SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(0, 16),
                ::testing::Values(0, 16)));
