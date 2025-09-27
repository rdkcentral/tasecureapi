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
#include "client_test_helpers.h"
#include "sa.h"
#include "sa_svp_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaSvpBufferCheckTest, failsRee) {
        auto buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(buffer, nullptr);
        std::vector<uint8_t> hash(SHA1_DIGEST_LENGTH);
        sa_status const status = sa_svp_buffer_check(*buffer, 0, 1024, SA_DIGEST_ALGORITHM_SHA1, hash.data(),
                hash.size());
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
#endif
