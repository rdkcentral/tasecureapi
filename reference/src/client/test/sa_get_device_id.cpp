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

#include "sa.h"
#include "gtest/gtest.h"

namespace {
    TEST(SaGetDeviceId, nominal) {
        uint64_t id;
        sa_status const status = sa_get_device_id(&id);
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST(SaGetDeviceId, failsNullId) {
        sa_status const status = sa_get_device_id(nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
