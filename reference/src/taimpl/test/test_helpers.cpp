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

#include "test_helpers.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define ERROR(msg) printf("%s:%d %s\n", __FILE__, __LINE__, msg);

namespace test_helpers {
    void rights_allow_all(sa_rights* rights) {
        memset(rights->id, 0, sizeof(rights->id));

        rights->not_before = 0;
        rights->not_on_or_after = UINT64_MAX;

        rights->usage_flags = 0;
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DERIVE);
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_UNWRAP);
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_ENCRYPT);
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_DECRYPT);
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_SIGN);
        rights->usage_flags |= SA_USAGE_OUTPUT_PROTECTIONS_MASK;
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE);
    }

    const sa_uuid* uuid() {
        static sa_uuid uuid = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

        return &uuid;
    }

    static void ta_client_shutdown() {
        ta_client client = test_helpers::client();
        ta_sa_close(client, uuid());
    }

    ta_client client() {
        const auto INVALID_CLIENT = static_cast<uint32_t>(UINT32_MAX);
        static ta_client client = INVALID_CLIENT;

        if (client == INVALID_CLIENT) {
            if (SA_STATUS_OK != ta_sa_init(&client, uuid())) {
                ERROR("ta_sa_init failed")
                return client;
            }

            atexit(ta_client_shutdown);
        }

        return client;
    }
} // namespace test_helpers
