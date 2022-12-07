/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#include "sa_rights.h"
#include <memory.h>

void sa_rights_set_allow_all(sa_rights* rights) {
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

    rights->child_usage_flags = 0;

    memset(rights->allowed_tas, 0, sizeof(rights->allowed_tas));

    const sa_uuid ALL_MATCH = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

    memcpy(&rights->allowed_tas[0], &ALL_MATCH, sizeof(sa_uuid));
}
