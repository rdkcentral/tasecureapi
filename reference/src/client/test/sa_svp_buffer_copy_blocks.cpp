/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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
    TEST_F(SaSvpBufferCopyBlocksTest, nominal) {
        auto out_buffer = create_sa_svp_buffer(384);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(768);
        ASSERT_NE(in_buffer, nullptr);
        auto in1 = random(128);
        auto in2 = random(128);
        auto in3 = random(128);
        auto in4 = random(128);
        std::vector<uint8_t> in;
        std::copy(in1.begin(), in1.end(), std::back_inserter(in));
        std::copy(in4.begin(), in4.end(), std::back_inserter(in));
        std::copy(in2.begin(), in2.end(), std::back_inserter(in));
        std::copy(in4.begin(), in4.end(), std::back_inserter(in));
        std::copy(in3.begin(), in3.end(), std::back_inserter(in));
        std::copy(in4.begin(), in4.end(), std::back_inserter(in));

        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        sa_svp_block blocks[3] = {
                {0, 0, 128},
                {128, 256, 128},
                {256, 512, 128}};
        status = sa_svp_buffer_copy_blocks(*out_buffer, *in_buffer, blocks, 3);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, in1, in2, in3));
        status = sa_svp_buffer_check(*out_buffer, 0, 384, SA_DIGEST_ALGORITHM_SHA256, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferCopyBlocksTest, failsOutBufferTooSmall) {
        auto out_buffer = create_sa_svp_buffer(383);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(768);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        sa_svp_block blocks[3] = {
                {0, 0, 128},
                {128, 256, 128},
                {256, 512, 128}};
        status = sa_svp_buffer_copy_blocks(*out_buffer, *in_buffer, blocks, 3);
        ASSERT_EQ(status, SA_STATUS_BAD_SVP_BUFFER);
    }

    TEST_F(SaSvpBufferCopyBlocksTest, failsInBufferTooSmall) {
        auto out_buffer = create_sa_svp_buffer(384);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(639);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        sa_svp_block blocks[3] = {
                {0, 0, 128},
                {128, 256, 128},
                {256, 512, 128}};
        status = sa_svp_buffer_copy_blocks(*out_buffer, *in_buffer, blocks, 3);
        ASSERT_EQ(status, SA_STATUS_BAD_SVP_BUFFER);
    }

    TEST_F(SaSvpBufferCopyBlocksTest, failsNullBlocks) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE * 2);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        status = sa_svp_buffer_copy_blocks(*out_buffer, *in_buffer, nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpBufferCopyBlocksTest, failsInvalidOut) {
        auto in_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(in_buffer, nullptr);
        sa_svp_block blocks[3] = {
                {0, 0, 128},
                {128, 256, 128},
                {256, 512, 128}};
        sa_status status = sa_svp_buffer_copy_blocks(INVALID_HANDLE, *in_buffer, blocks, 3);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaSvpBufferCopyBlocksTest, failsInvalidIn) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        sa_svp_block blocks[3] = {
                {0, 0, 128},
                {128, 256, 128},
                {256, 512, 128}};
        sa_status status = sa_svp_buffer_copy_blocks(*out_buffer, INVALID_HANDLE, blocks, 3);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
