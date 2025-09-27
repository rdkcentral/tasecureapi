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
    TEST_F(SaSvpBufferReleaseTest, nominal) {
        sa_svp_buffer svp_buffer;
        sa_status status = sa_svp_buffer_alloc(&svp_buffer, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_OK);
        void* out = nullptr;
        size_t out_length = 0;
        status = sa_svp_buffer_release(&out, &out_length, svp_buffer);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, AES_BLOCK_SIZE);
        ASSERT_NE(out, nullptr);

        sa_svp_memory_free(out);
    }

    TEST_F(SaSvpBufferReleaseTest, failsInvalidSvpBuffer) {
        void* out = nullptr;
        size_t out_length = 0;
        sa_status const status = sa_svp_buffer_release(&out, &out_length, INVALID_HANDLE);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
#endif // DISABLE_SVP
