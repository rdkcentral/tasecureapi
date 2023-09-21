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

#include "log.h"
#include "sa.h"
#include "svp.h"
#include "ta_client.h"

sa_status sa_svp_memory_alloc(
        void** svp_memory,
        size_t size) {

    if (svp_memory == NULL) {
        ERROR("NULL svp_memory");
        return SA_STATUS_NULL_PARAMETER;
    }

    // TODO SoC Vendor: replace this call with a call to allocate secure memory.
    svp_memory_s* temp = malloc(sizeof(svp_memory_s));
    if (temp == NULL) {
        ERROR("malloc failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    temp->svp_memory = malloc(size);
    if (temp->svp_memory == NULL) {
        ERROR("malloc failed");
        free(temp);
        return SA_STATUS_INTERNAL_ERROR;
    }

    temp->svp_memory_size = size;
    *svp_memory = temp;
    return SA_STATUS_OK;
}
