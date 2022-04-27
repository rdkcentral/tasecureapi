/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#ifndef SA_SVP_COMMON_H
#define SA_SVP_COMMON_H

#include "sa.h"
#include <cstddef>
#include <gtest/gtest.h>
#include <memory>

class SaSvpBase : public ::testing::Test {
protected:
    void SetUp() override;
    static std::shared_ptr<sa_svp_buffer> create_sa_svp_buffer(size_t size);
};

class SaSvpBufferAllocTest : public SaSvpBase {};

class SaSvpBufferCheckTest : public ::testing::WithParamInterface<sa_digest_algorithm>, public SaSvpBase {};

class SaSvpBufferCopyTest : public SaSvpBase {};

class SaSvpBufferCreateTest : public SaSvpBase {};

class SaSvpBufferReleaseTest : public SaSvpBase {};

class SaSvpBufferWriteTest : public SaSvpBase {};

class SaSvpKeyCheckTest : public SaSvpBase {};

#endif // SA_SVP_COMMON_H
