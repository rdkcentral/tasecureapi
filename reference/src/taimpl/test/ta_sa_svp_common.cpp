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
#include "ta_sa_svp_common.h" // NOLINT
#include "log.h"
#include "ta_test_helpers.h"

using namespace ta_test_helpers;

void TaSvpBase::SetUp() {
    if (ta_sa_svp_supported(client(), ta_uuid()) == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

std::shared_ptr<sa_svp_buffer> TaSvpBase::create_sa_svp_buffer(size_t size) {
    auto svp_buffer = std::shared_ptr<sa_svp_buffer>(
            new sa_svp_buffer(INVALID_HANDLE),
            [](const sa_svp_buffer* p) {
                if (p != nullptr) {
                    if (*p != INVALID_HANDLE) {
                        void* svp_memory = nullptr;
                        size_t svp_memory_size = 0;
                        ta_sa_svp_buffer_release(&svp_memory, &svp_memory_size, *p, client(), ta_uuid());
                        ta_sa_svp_memory_free(svp_memory);
                    }

                    delete p;
                }
            });

    void* svp_memory = nullptr;
    sa_status status = ta_sa_svp_memory_alloc(&svp_memory, size);
    if (status != SA_STATUS_OK) {
        ERROR("ta_sa_svp_memory_alloc failed");
        return nullptr;
    }

    status = ta_sa_svp_buffer_create(svp_buffer.get(), svp_memory, size, client(), ta_uuid());
    if (status != SA_STATUS_OK) {
        ERROR("ta_sa_svp_buffer_create failed");
        return nullptr;
    }

    return svp_buffer;
}

INSTANTIATE_TEST_SUITE_P(
        TaSvpBufferCheckNominalTests,
        TaSvpBufferCheckTest,
        ::testing::Values(
                SA_DIGEST_ALGORITHM_SHA1,
                SA_DIGEST_ALGORITHM_SHA256,
                SA_DIGEST_ALGORITHM_SHA384,
                SA_DIGEST_ALGORITHM_SHA512));

INSTANTIATE_TEST_SUITE_P(
        TaSvpBufferCopyTests,
        TaSvpBufferCopyTest,
        ::testing::Values(1, 3, 10));

INSTANTIATE_TEST_SUITE_P(
        TaSvpBufferWriteTests,
        TaSvpBufferWriteTest,
        ::testing::Values(1, 3, 10));

#endif // DISABLE_SVP
