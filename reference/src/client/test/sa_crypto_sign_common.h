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

#ifndef SA_CRYPTO_SIGN_COMMON_H
#define SA_CRYPTO_SIGN_COMMON_H

#include "gtest/gtest.h"
#include <sa_types.h>

// clang-format off
using SaCryptoSignTestType = std::tuple<sa_signature_algorithm, size_t, sa_digest_algorithm, sa_digest_algorithm,
        size_t, bool>;

class SaCryptoSign : public ::testing::TestWithParam<SaCryptoSignTestType> {};
// clang-format on

#endif //SA_CRYPTO_SIGN_COMMON_H
