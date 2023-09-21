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
    TEST_P(SaSvpBufferCopyTest, nominal) {
        auto offset_length = std::get<0>(GetParam());

        auto out = create_sa_svp_memory(1024);
        ASSERT_NE(out, nullptr);
        auto in = create_sa_svp_memory(1024);
        ASSERT_NE(in, nullptr);
        auto in_data = random(1024);
        sa_svp_offset write_offset = {0, 0, 1024};
        sa_status status = sa_svp_write(in.get(), in_data.data(), in_data.size(), &write_offset, 1);
        ASSERT_EQ(status, SA_STATUS_OK);
        long chunk_size = offset_length > 1 ? (1024 / (2 * offset_length)) : 1024; // NOLINT
        std::vector<uint8_t> digest_vector;
        sa_svp_offset offsets[offset_length];
        for (long i = 0; i < offset_length; i++) { // NOLINT
            offsets[i].out_offset = i * chunk_size;
            offsets[i].in_offset = i * 2 * chunk_size;
            offsets[i].length = chunk_size;
            std::copy(in_data.begin() + i * 2 * chunk_size, in_data.begin() + i * 2 * chunk_size + chunk_size,
                    std::back_inserter(digest_vector));
        }

        status = sa_svp_copy(out.get(), in.get(), offsets, offset_length);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Copy verified in taimpltest.
    }

    TEST_F(SaSvpBufferCopyTest, failsOutBufferTooSmall) {
        auto out = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(out, nullptr);
        auto in = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(in, nullptr);
        sa_svp_offset offset = {1, 0, AES_BLOCK_SIZE};
        sa_status const status = sa_svp_copy(out.get(), in.get(), &offset, 1);
        ASSERT_EQ(status, SA_STATUS_INVALID_SVP_MEMORY);
    }

    TEST_F(SaSvpBufferCopyTest, failsOffsetOverflow) {
        auto out = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(out, nullptr);
        auto in = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(in, nullptr);
        sa_svp_offset offset = {SIZE_MAX - 4, 0, AES_BLOCK_SIZE};
        sa_status const status = sa_svp_copy(out.get(), in.get(), &offset, 1);
        ASSERT_EQ(status, SA_STATUS_INVALID_SVP_MEMORY);
    }

    TEST_F(SaSvpBufferCopyTest, failsInBufferTooSmall) {
        auto out = create_sa_svp_memory(AES_BLOCK_SIZE + 1);
        ASSERT_NE(out, nullptr);
        auto in = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(in, nullptr);
        sa_svp_offset offset = {0, 1, AES_BLOCK_SIZE};
        sa_status const status = sa_svp_copy(out.get(), in.get(), &offset, 1);
        ASSERT_EQ(status, SA_STATUS_INVALID_SVP_MEMORY);
    }

    TEST_F(SaSvpBufferCopyTest, failsNullOffset) {
        auto out = create_sa_svp_memory(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        ASSERT_NE(out, nullptr);
        auto in = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(in, nullptr);
        auto in_data = random(AES_BLOCK_SIZE);
        sa_status const status = sa_svp_copy(out.get(), in.get(), nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpBufferCopyTest, failsNullOut) {
        auto in = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(in, nullptr);
        sa_svp_offset offset = {0, 0, 1};
        sa_status const status = sa_svp_copy(nullptr, in.get(), &offset, 1);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpBufferCopyTest, failsNullIn) {
        auto out = create_sa_svp_memory(AES_BLOCK_SIZE);
        ASSERT_NE(out, nullptr);
        sa_svp_offset offset = {0, 0, 1};
        sa_status const status = sa_svp_copy(out.get(), nullptr, &offset, 1);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
