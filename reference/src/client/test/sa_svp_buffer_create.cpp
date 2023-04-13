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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_svp_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaSvpBufferCreateTest, nominal) {
        void* svp_memory;
        sa_status status = sa_svp_memory_alloc(&svp_memory, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_OK);
        sa_svp_buffer svp_buffer;
        status = sa_svp_buffer_create(&svp_buffer, svp_memory, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_OK);
        void* out = nullptr;
        size_t out_length = 0;
        status = sa_svp_buffer_release(&out, &out_length, svp_buffer);
        ASSERT_EQ(status, SA_STATUS_OK);

        status = sa_svp_memory_free(svp_memory);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferCreateTest, failsNullSvpBuffer) {
        void* svp_memory;
        sa_status status = sa_svp_memory_alloc(&svp_memory, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_OK);
        status = sa_svp_buffer_create(nullptr, svp_memory, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);

        status = sa_svp_memory_free(svp_memory);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferCreateTest, failsNullBuffer) {
        sa_svp_buffer svp_buffer;
        sa_status const status = sa_svp_buffer_create(&svp_buffer, nullptr, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
