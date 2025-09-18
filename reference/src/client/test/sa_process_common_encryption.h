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

#ifndef SA_PROCESS_COMMON_ENCRYPTION_H
#define SA_PROCESS_COMMON_ENCRYPTION_H

#include "sa.h"
#include "sa_crypto_cipher_common.h"
#include "test_process_common_encryption.h"
#include "gtest/gtest.h"
#include <memory>
#include <vector>

// clang-format off
typedef std::tuple<std::tuple<size_t, int64_t>, size_t, size_t, size_t, sa_cipher_algorithm,
    std::tuple<sa_buffer_type, sa_buffer_type>> SaProcessCommonEncryptionType;

class SaProcessCommonEncryptionBase : public ProcessCommonEncryptionBase {
protected:
    sa_status svp_buffer_write(
        sa_svp_buffer out,
        const void* in,
        size_t in_length) override;
    ~SaProcessCommonEncryptionBase() = default;

};

class SaProcessCommonEncryptionTest : public ::testing::TestWithParam<SaProcessCommonEncryptionType>,
                                      public SaProcessCommonEncryptionBase, public SaCipherCryptoBase {
protected:
    void SetUp() override;
};

class SaProcessCommonEncryptionNegativeTest : public ::testing::Test, public SaProcessCommonEncryptionBase,
                                              public SaCipherCryptoBase {};

class SaProcessCommonEncryptionAlternativeTest : public ::testing::Test, public SaProcessCommonEncryptionBase,
                                                 public SaCipherCryptoBase {};
// clang-format on

#endif // SA_PROCESS_COMMON_ENCRYPTION_H
