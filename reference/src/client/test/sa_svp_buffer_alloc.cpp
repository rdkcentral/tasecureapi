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
    TEST_F(SaSvpBufferAllocTest, nominal) {
        sa_svp_buffer svp_buffer;
        sa_status status = sa_svp_buffer_alloc(&svp_buffer, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_OK);
        status = sa_svp_buffer_free(svp_buffer);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferAllocTest, nominalNoAvailableResourceSlot) {
        std::vector<std::shared_ptr<sa_svp_buffer>> svp_buffers;
        size_t i = 0;
        sa_status status;
        do {
            auto svp_buffer = std::shared_ptr<sa_svp_buffer>(
                    new sa_svp_buffer(INVALID_HANDLE),
                    [](const sa_svp_buffer* p) {
                        if (p != nullptr) {
                            if (*p != INVALID_HANDLE) {
                                sa_svp_buffer_free(*p);
                            }

                            delete p;
                        }
                    });

            status = sa_svp_buffer_alloc(svp_buffer.get(), AES_BLOCK_SIZE);
            ASSERT_LE(i++, MAX_NUM_SLOTS);
            svp_buffers.push_back(svp_buffer);
        } while (status == SA_STATUS_OK);

        ASSERT_EQ(status, SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }

    TEST_F(SaSvpBufferAllocTest, failsNullSvpBuffer) {
        sa_status const status = sa_svp_buffer_alloc(nullptr, AES_BLOCK_SIZE);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
#endif // DISABLE_SVP
