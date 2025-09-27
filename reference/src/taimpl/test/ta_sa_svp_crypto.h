/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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

#ifndef TA_SA_SVP_CRYPTO_H
#define TA_SA_SVP_CRYPTO_H

#include "sa_types.h"
#include "test_process_common_encryption.h"
#include "gtest/gtest.h"

class TaCryptoCipherBase {
protected:
    static std::shared_ptr<sa_key> import_key(
            std::vector<uint8_t>& clear_key,
            bool svp);

    static std::vector<uint8_t> encrypt_openssl(
            sa_cipher_algorithm cipher_algorithm,
            const std::vector<uint8_t>& in,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& key);
};

typedef std::tuple<sa_cipher_algorithm, sa_cipher_mode, size_t, size_t> TaCryptoCipherTestType;

class TaCryptoCipherTest : public ::testing::TestWithParam<TaCryptoCipherTestType>, public TaCryptoCipherBase {
protected:
    void SetUp() override;
};

using TaProcessCommonEncryptionType =
        std::tuple<std::tuple<size_t, int64_t>, size_t, size_t, size_t, sa_cipher_algorithm>;

class TaProcessCommonEncryptionTest : public ::testing::TestWithParam<TaProcessCommonEncryptionType>,
                                      public TaCryptoCipherBase,
                                      public ProcessCommonEncryptionBase {
protected:
    void SetUp() override;
#ifndef DISABLE_SVP
    sa_status svp_buffer_write(
            sa_svp_buffer out,
            const void* in,
            size_t in_length) override;
#endif
};

#endif //TA_SA_SVP_CRYPTO_H
