/**
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

#include "sa_svp_common.h" // NOLINT
#include "client_test_helpers.h"

using namespace client_test_helpers;

void SaSvpBase::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

std::shared_ptr<sa_svp_buffer> SaSvpBase::create_sa_svp_buffer(size_t size) {
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

    sa_status status = sa_svp_buffer_alloc(svp_buffer.get(), size);
    if (status != SA_STATUS_OK) {
        ERROR("sa_svp_buffer_alloc failed");
        return nullptr;
    }

    return svp_buffer;
}

INSTANTIATE_TEST_SUITE_P(
        SaSvpBufferCopyTests,
        SaSvpBufferCopyTest,
        ::testing::Values(1, 3, 10));

INSTANTIATE_TEST_SUITE_P(
        SaSvpBufferWriteTests,
        SaSvpBufferWriteTest,
        ::testing::Values(1, 3, 10));
