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

#ifndef SA_PROVIDER_COMMON_H
#define SA_PROVIDER_COMMON_H

#include "sa_provider.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key_common.h"
#include <gtest/gtest.h>
#include <memory>
#include <openssl/crypto.h>
#include <vector>

class SaProviderTest : public SaKeyBase {
protected:
    static const char* get_key_name(
            sa_key_type key_type,
            sa_elliptic_curve curve);

    static bool verifyEncrypt(
            std::vector<uint8_t>& encrypted,
            std::vector<uint8_t>& clear,
            std::vector<uint8_t>& clear_key,
            std::vector<uint8_t>& iv,
            std::vector<uint8_t>& aad,
            std::vector<uint8_t>& tag,
            const char* algorithm_name,
            int padded);

    static bool doEncrypt(
            std::vector<uint8_t>& encrypted,
            std::vector<uint8_t>& clear,
            std::vector<uint8_t>& clear_key,
            std::vector<uint8_t>& iv,
            std::vector<uint8_t>& aad,
            std::vector<uint8_t>& tag,
            const char* algorithm_name,
            int padded);

    static std::shared_ptr<EVP_PKEY> generate_sa_key(
            OSSL_LIB_CTX* lib_ctx,
            sa_key_type key_type,
            size_t& key_length,
            sa_elliptic_curve& curve);
};

typedef std::tuple<const char*, int, int, int> SaProviderCipherTestType;

class SaProviderCipherTest : public ::testing::TestWithParam<SaProviderCipherTestType>,
                             public SaProviderTest {};

typedef std::tuple<sa_key_type, size_t, const char*, const char*, int, int> SaProviderSignTestType;

class SaProviderSignTest : public ::testing::TestWithParam<SaProviderSignTestType>,
                           public SaProviderTest {};

typedef std::tuple<sa_key_type, size_t, const char*> SaProviderSignWithGenerateTestType;

class SaProviderSignWithGenerateTest : public ::testing::TestWithParam<SaProviderSignWithGenerateTestType>,
                                       public SaProviderTest {};

typedef std::tuple<sa_key_type, size_t> SaProviderSignDefaultDigestSignTestType;

class SaProviderSignDefaultDigestSignTest : public ::testing::TestWithParam<SaProviderSignDefaultDigestSignTestType>,
                                            public SaProviderTest {};

typedef std::tuple<sa_key_type, size_t> SaProviderSignEdTestType;

class SaProviderSignEdTest : public ::testing::TestWithParam<SaProviderSignEdTestType>,
                             public SaProviderTest {};

typedef std::tuple<sa_key_type, size_t, const char*> SaProviderPkcs7TestType;

class SaProviderPkcs7Test : public ::testing::TestWithParam<SaProviderPkcs7TestType>,
                            public SaProviderTest {};

typedef std::tuple<sa_key_type, size_t, int, sa_digest_algorithm, sa_digest_algorithm, int>
        SaProviderAsymCipherTestType;

class SaProviderAsymCipherTest : public ::testing::TestWithParam<SaProviderAsymCipherTestType>,
                                 public SaProviderTest {};

typedef std::tuple<size_t, const char*, const char*> SaProviderMacTestType;

class SaProviderMacTest : public ::testing::TestWithParam<SaProviderMacTestType> {};

typedef std::tuple<sa_key_type, size_t> SaProviderKeyExchangeTestType;

class SaProviderKeyExchangeTest : public ::testing::TestWithParam<SaProviderKeyExchangeTestType>,
                                  public SaProviderTest {};

typedef std::tuple<const char*, const char*> SaProviderKdfTestType;

class SaProviderKdfTest : public ::testing::TestWithParam<SaProviderKdfTestType>,
                          public SaProviderTest {};

#endif
#endif //SA_PROVIDER_COMMON_H
