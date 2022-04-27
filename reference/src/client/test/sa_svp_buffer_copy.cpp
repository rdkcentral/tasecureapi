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
    TEST_F(SaSvpBufferCopyTest, nominal) {
        auto out_buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(1024);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        out_offset = 0;
        size_t in_offset = 0;
        status = sa_svp_buffer_copy(*out_buffer, &out_offset, *in_buffer, &in_offset, in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, 1024);
        ASSERT_EQ(in_offset, 1024);

        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, in, {}, {}));
        status = sa_svp_buffer_check(*out_buffer, 0, 1024, SA_DIGEST_ALGORITHM_SHA256, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferCopyTest, nominalWithOutOffset) {
        auto out_buffer = create_sa_svp_buffer(2048);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(1024);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        size_t in_offset = 0;
        status = sa_svp_buffer_copy(*out_buffer, &out_offset, *in_buffer, &in_offset, in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, 2048);
        ASSERT_EQ(in_offset, 1024);

        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, in, {}, {}));
        status = sa_svp_buffer_check(*out_buffer, 1024, 1024, SA_DIGEST_ALGORITHM_SHA256, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferCopyTest, nominalWithInOffset) {
        auto out_buffer = create_sa_svp_buffer(2048);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(1025);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(1025);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        out_offset = 0;
        size_t in_offset = 1;
        status = sa_svp_buffer_copy(*out_buffer, &out_offset, *in_buffer, &in_offset, 1024);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, 1024);
        ASSERT_EQ(in_offset, 1025);

        std::vector<uint8_t> in2(in.begin() + 1, in.end());
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, in2, {}, {}));
        status = sa_svp_buffer_check(*out_buffer, 0, 1024, SA_DIGEST_ALGORITHM_SHA256, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaSvpBufferCopyTest, failsOutBufferTooSmall) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE * 2);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        out_offset++;
        size_t in_offset = 0;
        status = sa_svp_buffer_copy(*out_buffer, &out_offset, *in_buffer, &in_offset, in.size());
        ASSERT_EQ(status, SA_STATUS_BAD_SVP_BUFFER);
    }

    TEST_F(SaSvpBufferCopyTest, failsInBufferTooSmall) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE * 2);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        size_t in_offset = 1;
        status = sa_svp_buffer_copy(*out_buffer, &out_offset, *in_buffer, &in_offset, in.size());
        ASSERT_EQ(status, SA_STATUS_BAD_SVP_BUFFER);
    }

    TEST_F(SaSvpBufferCopyTest, failsNullOutOffset) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE * 2);
        ASSERT_NE(out_buffer, nullptr);
        auto in_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(in_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        size_t out_offset = 0;
        sa_status status = sa_svp_buffer_write(*in_buffer, &out_offset, in.data(), in.size());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_offset, in.size());
        size_t in_offset = 0;
        status = sa_svp_buffer_copy(*out_buffer, nullptr, *in_buffer, &in_offset, in.size());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpBufferCopyTest, failsInvalidOut) {
        auto in_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(in_buffer, nullptr);
        size_t out_offset = 0;
        size_t in_offset = 0;
        sa_status status = sa_svp_buffer_copy(INVALID_HANDLE, &out_offset, *in_buffer, &in_offset, 0);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaSvpBufferCopyTest, failsInvalidIn) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        size_t out_offset = 0;
        size_t in_offset = 0;
        sa_status status = sa_svp_buffer_copy(*out_buffer, &out_offset, INVALID_HANDLE, &in_offset, 0);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
