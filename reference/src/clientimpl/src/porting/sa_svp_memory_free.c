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
#include "sa.h"
#include "ta_client.h"

sa_status sa_svp_memory_free(void* svp_memory) {

    // TODO SoC Vendor: replace this call to a call to free secure memory.
    if (svp_memory != NULL)
        free(svp_memory);

    return SA_STATUS_OK;
}
#endif // DISABLE_SVP
