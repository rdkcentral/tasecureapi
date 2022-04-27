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

#include "transport.h" // NOLINT
#include "log.h"
#include <string.h>

sa_status transport_authenticate_caller(sa_uuid* uuid) {
    if (uuid == NULL) {
        ERROR("NULL uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    // SecApi TA obtains the caller UUID from the underlying transport mechanism which is
    // platform dependent. The caller must be authenticated to prevent spoofing.
    // TODO Soc Vendor: add code here to retrieve the authenticated caller UUID.

    // This is the default value to be used when the TA is not able to authenticate the calling entity as another
    // secure TA. The TA will assume that the caller is an insecure host application and cannot be trusted. No key
    // rights will use this UUID, so the TA will only allow keys that have no key rights UUIDs specified or have the
    // ALL MATCH UUID specified (0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // 0xff, 0xff).
    static sa_uuid REE_UUID = {
            .id = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};

    memcpy(uuid, &REE_UUID, sizeof(sa_uuid));

    return SA_STATUS_OK;
}
