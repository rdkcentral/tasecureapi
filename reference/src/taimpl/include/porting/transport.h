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

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Obtains the caller uuid. This simulates the platform dependent TEE mechanism for obtaining and
 * validating the originator TA for a message received by the SecApi TA. This call shall be replaced
 * by the implementor, in the SecApi TA, by using TEE OS services to securely obtain the calling
 * TA UUID.
 *
 * @param[out] uuid caller TA UUID.
 * @return status of the operation.
 */
sa_status transport_authenticate_caller(sa_uuid* uuid);

/**
 * Determines if the calling entity is the REE.
 *
 * @param uuid the UUID of the caller.
 * @return true if this is the REE UUID or false if not.
 */
bool is_ree(const sa_uuid* uuid);

#ifdef __cplusplus
}
#endif

#endif // TRANSPORT_H
