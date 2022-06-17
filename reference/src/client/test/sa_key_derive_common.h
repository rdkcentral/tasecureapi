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
#ifndef SA_KEY_DERIVE_COMMON_H
#define SA_KEY_DERIVE_COMMON_H

#include "sa_key_common.h"

// clang-format off
class SaKeyDeriveTest : public ::testing::Test {};

using SaKeyDeriveAnsiX963TestType = std::tuple<std::tuple<sa_key_type, size_t>, sa_digest_algorithm, size_t, size_t>;

class SaKeyDeriveAnsiX963Test : public ::testing::TestWithParam<SaKeyDeriveAnsiX963TestType>, public SaKeyBase {};

using SaKeyDeriveConcatTestType = std::tuple<std::tuple<sa_key_type, size_t>, sa_digest_algorithm, size_t, size_t>;

class SaKeyDeriveConcatTest : public ::testing::TestWithParam<SaKeyDeriveConcatTestType>, public SaKeyBase {};

using SaKeyDeriveHkdfTestType = std::tuple<std::tuple<sa_key_type, size_t>, sa_digest_algorithm, size_t, size_t,
        size_t>;

class SaKeyDeriveHkdfTest : public ::testing::TestWithParam<SaKeyDeriveHkdfTestType>, public SaKeyBase {};

using SaKeyDeriveCmacTestType = std::tuple<size_t, size_t, uint8_t>;

class SaKeyDeriveCmacTest : public ::testing::TestWithParam<SaKeyDeriveCmacTestType>, public SaKeyBase {};

class SaKeyDeriveNetflixTest : public ::testing::Test, public SaKeyBase {};

class SaKeyDeriveRootKeyLadderTest : public ::testing::Test, public SaKeyBase {};

// clang-format off
#endif // SA_KEY_DERIVE_COMMON_H
