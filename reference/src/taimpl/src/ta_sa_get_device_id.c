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
#include "porting/otp.h"
#include "ta_sa.h"

sa_status ta_sa_get_device_id(
        uint64_t* id,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    DEBUG("client_slot %d", client_slot);

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (id == NULL) {
        ERROR("NULL id");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (otp_device_id(id) != SA_STATUS_OK) {
        ERROR("otp_device_id failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}
