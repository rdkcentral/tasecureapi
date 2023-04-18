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

#include "ta_sa.h"
#include "ta_test_helpers.h"
#include "gtest/gtest.h"

using namespace ta_test_helpers;

namespace {
    TEST(TaSaInit, nominalNoAvailableResourceSlot) {
        std::vector<std::shared_ptr<ta_client>> clients;
        size_t i = 0;
        sa_status status;
        do {
            std::shared_ptr<ta_client> const client(new ta_client,
                    [](const ta_client* p) {
                        if (p != nullptr) {
                            if (*p != INVALID_HANDLE) {
                                ta_sa_close(*p, ta_uuid());
                            }

                            delete p;
                        }
                    });

            status = ta_sa_init(client.get(), ta_uuid());
            ASSERT_LE(i++, MAX_CLIENT_SLOTS);
            clients.push_back(client);
        } while (status == SA_STATUS_OK);

        ASSERT_EQ(status, SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }
} // namespace
