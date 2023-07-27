/*
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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

#ifndef SA_ENGINE_COMMON_H
#define SA_ENGINE_COMMON_H

#include "sa_engine_internal.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_common.h"
#include <gtest/gtest.h>
#include <memory>
#include <openssl/crypto.h>
#include <vector>

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

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

typedef std::tuple<int, int, int, int> SaEngineCipherTestType;

class SaEngineCipherTest : public ::testing::TestWithParam<SaEngineCipherTestType>,
                           public SaEngineTest {};

typedef std::tuple<sa_key_type, size_t, int, int, int, int> SaEnginePkeySignTestType;

class SaEnginePkeySignTest : public ::testing::TestWithParam<SaEnginePkeySignTestType>,
                             public SaEngineTest {};

typedef std::tuple<sa_key_type, size_t> SaEnginePkeySignEdTestType;

class SaEnginePkeySignEdTest : public ::testing::TestWithParam<SaEnginePkeySignEdTestType>,
                               public SaEngineTest {};

typedef std::tuple<sa_key_type, size_t> SaEnginePkcs7TestType;

class SaEnginePkcs7Test : public ::testing::TestWithParam<SaEnginePkcs7TestType>,
                          public SaEngineTest {};

typedef std::tuple<sa_key_type, size_t, int, sa_digest_algorithm, sa_digest_algorithm, int> SaEnginePkeyEncryptTestType;

class SaEnginePkeyEncryptTest : public ::testing::TestWithParam<SaEnginePkeyEncryptTestType>,
                                public SaEngineTest {};

typedef std::tuple<sa_key_type, size_t> SaEnginePkeyDeriveTestType;

class SaEnginePkeyDeriveTest : public ::testing::TestWithParam<SaEnginePkeyDeriveTestType>,
                               public SaKeyBase {};

typedef std::tuple<sa_key_type, size_t, sa_digest_algorithm, sa_mac_algorithm> SaEnginePkeyMacTestType;

class SaEnginePkeyMacTest : public ::testing::TestWithParam<SaEnginePkeyMacTestType> {};

#endif
#endif //SA_ENGINE_COMMON_H
