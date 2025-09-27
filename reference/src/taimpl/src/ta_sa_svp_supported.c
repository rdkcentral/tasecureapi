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
#include "log.h"
#include "svp_store.h"
#include "ta_sa.h"

sa_status ta_sa_svp_supported(
        ta_client client_slot,
        const sa_uuid* caller_uuid) {
#ifdef DISABLE_SVP
	return SA_STATUS_OPERATION_NOT_SUPPORTED;
#endif // DISABLE_SVP
    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid: client_slot %d", client_slot);
        return SA_STATUS_NULL_PARAMETER;
    }

    return svp_supported();
}
