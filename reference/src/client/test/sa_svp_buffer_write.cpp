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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_svp_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaSvpBufferWriteTest, nominal) {
        auto out_buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(1024);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*out_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());

        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, in, {}, {}));
        status = sa_svp_buffer_check(*out_buffer, 0, 1024, SA_DIGEST_ALGORITHM_SHA256, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferWriteTest, nominalWithOffset) {
        auto out_buffer = create_sa_svp_buffer(2048);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(1024);
        size_t out_offset = 1024;
        sa_status status = sa_svp_buffer_write(*out_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size() + 1024);

        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, in, {}, {}));
        status = sa_svp_buffer_check(*out_buffer, 1024, 1024, SA_DIGEST_ALGORITHM_SHA256, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferWriteTest, failsOutBufferTooSmall) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 1;
        sa_status status = sa_svp_buffer_write(*out_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_BAD_SVP_BUFFER);
    }

    TEST_F(SaSvpBufferWriteTest, failsNullOutOffset) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        sa_status status = sa_svp_buffer_write(*out_buffer, nullptr, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpBufferWriteTest, failsInvalidOut) {
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(INVALID_HANDLE, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaSvpBufferWriteTest, failsNullIn) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*out_buffer, &out_offset, nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
