/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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
#include "sa_engine.h"
#include "sa_key_common.h"
#include <gtest/gtest.h>
#include <memory>
#include <openssl/crypto.h>
#include <vector>

#ifndef SA_ENGINE_COMMON_H
#define SA_ENGINE_COMMON_H

class SaEngineTest {
protected:
    static bool verifyEncrypt(
            std::vector<uint8_t>& encrypted,
            std::vector<uint8_t>& clear,
            std::vector<uint8_t>& clear_key,
            std::vector<uint8_t>& iv,
            std::vector<uint8_t>& aad,
            std::vector<uint8_t>& tag,
            const EVP_CIPHER* cipher,
            int padded);

    static bool doEncrypt(
            std::vector<uint8_t>& encrypted,
            std::vector<uint8_t>& clear,
            std::vector<uint8_t>& clear_key,
            std::vector<uint8_t>& iv,
            std::vector<uint8_t>& aad,
            std::vector<uint8_t>& tag,
            const EVP_CIPHER* cipher,
            int padded);
};

using SaEngineCipherTestType = std::tuple<int, int, int, int>;

class SaEngineCipherTest : public ::testing::TestWithParam<SaEngineCipherTestType>,
                           public SaEngineTest {};

using SaEnginePkeySignTestType = std::tuple<sa_key_type, size_t, int, int, int>;

class SaEnginePkeySignTest : public ::testing::TestWithParam<SaEnginePkeySignTestType>,
                             public SaEngineTest {};

using SaEnginePkeySignEdTestType = std::tuple<sa_key_type, size_t>;

class SaEnginePkeySignEdTest : public ::testing::TestWithParam<SaEnginePkeySignEdTestType>,
                               public SaEngineTest {};

using SaEnginePkcs7TestType = std::tuple<sa_key_type, size_t>;

class SaEnginePkcs7Test : public ::testing::TestWithParam<SaEnginePkcs7TestType>,
                          public SaEngineTest {};

class SaEnginePkcs7EdTest : public ::testing::TestWithParam<SaEnginePkcs7TestType>,
                            public SaEngineTest {};

using SaEnginePkeyEncryptTestType = std::tuple<sa_key_type, size_t, int>;

class SaEnginePkeyEncryptTest : public ::testing::TestWithParam<SaEnginePkeyEncryptTestType>,
                                public SaEngineTest {};

using SaEnginePkeyDeriveTestType = std::tuple<sa_key_type, size_t>;

class SaEnginePkeyDeriveTest : public ::testing::TestWithParam<SaEnginePkeyDeriveTestType>,
                                public SaKeyBase {};

using SaEnginePkeyMacTestType = std::tuple<sa_key_type, size_t, sa_digest_algorithm, sa_mac_algorithm>;

class SaEnginePkeyMacTest : public ::testing::TestWithParam<SaEnginePkeyMacTestType> {};

#endif //SA_ENGINE_COMMON_H
