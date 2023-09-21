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

#include "ta_sa_svp_common.h" // NOLINT
#include "ta_test_helpers.h"

using namespace ta_test_helpers;

void TaSvpBase::SetUp() {
    if (ta_sa_svp_supported(client(), ta_uuid()) == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

std::shared_ptr<void> TaSvpBase::create_sa_svp_memory(size_t size) {
    void* svp_memory = nullptr;
    if (ta_sa_svp_memory_alloc(&svp_memory, size) == SA_STATUS_OK) {
        return {svp_memory,
                [](void* p) {
                    if (p != nullptr) {
                        ta_sa_svp_memory_free(p);
                    }
                }};
    }

    return {};
}

INSTANTIATE_TEST_SUITE_P(
        TaSvpBufferCheckNominalTests,
        TaSvpCheckTest,
        ::testing::Values(
                SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA256,
                SA_DIGEST_ALGORITHM_SHA384,
                SA_DIGEST_ALGORITHM_SHA512));

INSTANTIATE_TEST_SUITE_P(
        TaSvpBufferCopyTests,
        TaSvpCopyTest,
        ::testing::Values(1, 3, 10));

INSTANTIATE_TEST_SUITE_P(
        TaSvpBufferWriteTests,
        TaSvpWriteTest,
        ::testing::Values(1, 3, 10));
