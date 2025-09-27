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
#include "common.h"
#include "ta_sa.h"
#include "ta_sa_svp_common.h"
#include "ta_test_helpers.h"
#include "gtest/gtest.h"

using namespace ta_test_helpers;

namespace {
    TEST_P(TaSvpBufferWriteTest, nominal) {
        auto offset_length = std::get<0>(GetParam());

        auto out_buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(1024);
        long chunk_size = offset_length > 1 ? (1024 / (2 * offset_length)) : 1024; // NOLINT
        std::vector<uint8_t> digest_vector;
        std::vector<sa_svp_offset> offsets(offset_length);
        for (long i = 0; i < offset_length; i++) { // NOLINT
            offsets[i].out_offset = i * chunk_size;
            offsets[i].in_offset = i * 2 * chunk_size;
            offsets[i].length = chunk_size;
            std::copy(in.begin() + i * 2 * chunk_size, in.begin() + i * 2 * chunk_size + chunk_size,
                    std::back_inserter(digest_vector));
        }
        sa_status status = ta_sa_svp_buffer_write(*out_buffer, in.data(), in.size(), offsets.data(), offset_length, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        ASSERT_TRUE(digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, digest_vector, {}, {}));
        status = ta_sa_svp_buffer_check(*out_buffer, 0, offset_length * chunk_size, SA_DIGEST_ALGORITHM_SHA256,
                hash.data(), hash.size(), client(), ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(TaSvpBufferWriteTest, failsOutOffsetOverflow) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        sa_svp_offset offset = {SIZE_MAX - 4, 0, in.size()};
        sa_status const status = ta_sa_svp_buffer_write(*out_buffer, in.data(), in.size(), &offset, 1, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_SVP_BUFFER);
    }

    TEST_F(TaSvpBufferWriteTest, failsInOffsetOverflow) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        sa_svp_offset offset = {0, SIZE_MAX - 4, in.size()};
        sa_status const status = ta_sa_svp_buffer_write(*out_buffer, in.data(), in.size(), &offset, 1, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_SVP_BUFFER);
    }

    TEST_F(TaSvpBufferWriteTest, failsOutBufferTooSmall) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        sa_svp_offset offset = {1, 0, in.size()};
        sa_status const status = ta_sa_svp_buffer_write(*out_buffer, in.data(), in.size(), &offset, 1, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_SVP_BUFFER);
    }

    TEST_F(TaSvpBufferWriteTest, failsNullOutOffset) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        auto in = random(AES_BLOCK_SIZE);
        sa_status const status = ta_sa_svp_buffer_write(*out_buffer, in.data(), in.size(), nullptr, 0, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(TaSvpBufferWriteTest, failsInvalidOut) {
        auto in = random(AES_BLOCK_SIZE);
        sa_svp_offset offset = {0, 0, in.size()};
        sa_status const status = ta_sa_svp_buffer_write(INVALID_HANDLE, in.data(), in.size(), &offset, 1, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(TaSvpBufferWriteTest, failsNullIn) {
        auto out_buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(out_buffer, nullptr);
        sa_svp_offset offset = {0, 0, 1};
        sa_status const status = ta_sa_svp_buffer_write(*out_buffer, nullptr, 0, &offset, 1, client(), ta_uuid());
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
#endif // DISABLE_SVP
