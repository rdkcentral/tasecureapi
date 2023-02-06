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
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST(SaCryptoRandom, nominalSize1) {
        auto out = std::vector<uint8_t>(1);
        sa_status const status = sa_crypto_random(out.data(), out.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST(SaCryptoRandom, nominalSize16) {
        auto out = std::vector<uint8_t>(AES_BLOCK_SIZE);
        sa_status const status = sa_crypto_random(out.data(), out.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST(SaCryptoRandom, nominalSize512) {
        auto out = std::vector<uint8_t>(512);
        sa_status const status = sa_crypto_random(out.data(), out.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST(SaCryptoRandom, failsNullOut) {
        sa_status const status = sa_crypto_random(nullptr, 16);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
