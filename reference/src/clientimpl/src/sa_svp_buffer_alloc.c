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
#include "log.h"
#include "sa.h"

sa_status sa_svp_buffer_alloc(
        sa_svp_buffer* svp_buffer,
        size_t size) {

    if (svp_buffer == NULL) {
        ERROR("NULL svp_buffer");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* svp_memory;
    sa_status status;
    do {
        status = sa_svp_memory_alloc(&svp_memory, size);
        if (status != SA_STATUS_OK) {
            ERROR("sa_svp_memory_alloc failed");
            break;
        }

        status = sa_svp_buffer_create(svp_buffer, svp_memory, size);
        if (status != SA_STATUS_OK) {
            sa_svp_memory_free(svp_memory);
            ERROR("sa_svp_buffer_create failed");
            break;
        }
    } while (0);

    return status;
}
#endif // DISABLE_SVP
