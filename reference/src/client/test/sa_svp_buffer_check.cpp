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
    TEST_P(SaSvpBufferCheckTest, nominal) {
        auto digest = GetParam();
        auto buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(buffer, nullptr);
        auto in = random(1024);
        sa_svp_offset offset = {0, 0, in.size()};
        sa_status status = sa_svp_buffer_write(*buffer, in.data(), in.size(), &offset, 1);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t length = digest_length(digest);
        std::vector<uint8_t> hash(length);
        ASSERT_TRUE(digest_openssl(hash, digest, in, {}, {}));
        status = sa_svp_buffer_check(*buffer, 0, 1024, digest, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_P(SaSvpBufferCheckTest, failsHashMismatch) {
        auto digest = GetParam();
        auto buffer = create_sa_svp_buffer(1024);
        ASSERT_NE(buffer, nullptr);
        auto in = random(1024);
        sa_svp_offset offset = {0, 0, in.size()};
        sa_status status = sa_svp_buffer_write(*buffer, in.data(), in.size(), &offset, 1);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t length = digest_length(digest);
        std::vector<uint8_t> hash(length);
        ASSERT_TRUE(digest_openssl(hash, digest, in, {}, {}));
        hash[0]++;
        status = sa_svp_buffer_check(*buffer, 0, 1024, digest, hash.data(), hash.size());
        ASSERT_EQ(status, SA_STATUS_VERIFICATION_FAILED);
    }

    TEST_F(SaSvpBufferCheckTest, failsHashWrongSize) {
        auto buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(buffer, nullptr);
        std::vector<uint8_t> hash(SHA1_DIGEST_LENGTH);
        sa_status status = sa_svp_buffer_check(*buffer, 0, AES_BLOCK_SIZE, SA_DIGEST_ALGORITHM_SHA256, hash.data(),
                hash.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaSvpBufferCheckTest, failsNullHash) {
        auto buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(buffer, nullptr);
        sa_status status = sa_svp_buffer_check(*buffer, 0, AES_BLOCK_SIZE, SA_DIGEST_ALGORITHM_SHA256, nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaSvpBufferCheckTest, failsInvalidBuffer) {
        auto in = random(AES_BLOCK_SIZE);
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        sa_status status = sa_svp_buffer_check(INVALID_HANDLE, 0, AES_BLOCK_SIZE, SA_DIGEST_ALGORITHM_SHA256,
                hash.data(),
                hash.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaSvpBufferCheckTest, failsInvalidSize) {
        auto buffer = create_sa_svp_buffer(AES_BLOCK_SIZE);
        ASSERT_NE(buffer, nullptr);
        std::vector<uint8_t> hash(SHA1_DIGEST_LENGTH);
        sa_status status = sa_svp_buffer_check(*buffer, 1, AES_BLOCK_SIZE, SA_DIGEST_ALGORITHM_SHA256, hash.data(),
                hash.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
