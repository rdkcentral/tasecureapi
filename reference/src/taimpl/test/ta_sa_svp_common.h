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

#ifndef DISABLE_SVP

#ifndef TA_SA_SVP_COMMON_H
#define TA_SA_SVP_COMMON_H

#include "sa_types.h"
#include "ta_sa_svp_crypto.h"
#include <cstddef> // NOLINT
#include <gtest/gtest.h>
#include <memory>

class TaSvpBase : public ::testing::Test {
protected:
    void SetUp() override;
    static std::shared_ptr<sa_svp_buffer> create_sa_svp_buffer(size_t size);
};

class TaSvpBufferCheckTest : public ::testing::WithParamInterface<sa_digest_algorithm>, public TaSvpBase {};

class TaSvpKeyCheckTest : public TaSvpBase, public TaCryptoCipherBase {};

typedef std::tuple<long> TaSvpBufferTestType; // NOLINT

class TaSvpBufferCopyTest : public ::testing::WithParamInterface<TaSvpBufferTestType>, public TaSvpBase {};

class TaSvpBufferWriteTest : public ::testing::WithParamInterface<TaSvpBufferTestType>, public TaSvpBase {};

#endif // TA_SA_SVP_COMMON_H

#endif // DISABLE_SVP

