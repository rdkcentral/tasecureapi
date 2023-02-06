/**
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

using SaProviderCipherTestType = std::tuple<const char*, int, int, int>;

class SaProviderCipherTest : public ::testing::TestWithParam<SaProviderCipherTestType>,
                             public SaProviderTest {};

using SaProviderSignTestType = std::tuple<sa_key_type, size_t, const char*, const char*, int, int>;

class SaProviderSignTest : public ::testing::TestWithParam<SaProviderSignTestType>,
                           public SaProviderTest {};

using SaProviderSignWithGenerateTestType = std::tuple<sa_key_type, size_t, const char*>;

class SaProviderSignWithGenerateTest : public ::testing::TestWithParam<SaProviderSignWithGenerateTestType>,
                                       public SaProviderTest {};

using SaProviderSignDefaultDigestSignTestType = std::tuple<sa_key_type, size_t>;

class SaProviderSignDefaultDigestSignTest : public ::testing::TestWithParam<SaProviderSignDefaultDigestSignTestType>,
                                            public SaProviderTest {};

using SaProviderSignEdTestType = std::tuple<sa_key_type, size_t>;

class SaProviderSignEdTest : public ::testing::TestWithParam<SaProviderSignEdTestType>,
                             public SaProviderTest {};

using SaProviderPkcs7TestType = std::tuple<sa_key_type, size_t, const char*>;

class SaProviderPkcs7Test : public ::testing::TestWithParam<SaProviderPkcs7TestType>,
                            public SaProviderTest {};

using SaProviderAsymCipherTestType =
        std::tuple<sa_key_type, size_t, int, sa_digest_algorithm, sa_digest_algorithm, int>;

class SaProviderAsymCipherTest : public ::testing::TestWithParam<SaProviderAsymCipherTestType>,
                                 public SaProviderTest {};

using SaProviderMacTestType = std::tuple<size_t, const char*, const char*>;

class SaProviderMacTest : public ::testing::TestWithParam<SaProviderMacTestType> {};

using SaProviderKeyExchangeTestType = std::tuple<sa_key_type, size_t>;

class SaProviderKeyExchangeTest : public ::testing::TestWithParam<SaProviderKeyExchangeTestType>,
                                  public SaProviderTest {};

using SaProviderKdfTestType = std::tuple<const char*, const char*>;

class SaProviderKdfTest : public ::testing::TestWithParam<SaProviderKdfTestType>,
                          public SaProviderTest {};

#endif
#endif //SA_PROVIDER_COMMON_H
