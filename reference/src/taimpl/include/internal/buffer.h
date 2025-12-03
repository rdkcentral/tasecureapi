/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

/** @section Description
 * @file buffer.h
 *
 * This file contains the functions implementing buffer access.
 */

#ifndef BUFFER_H
#define BUFFER_H

#include "client_store.h"
#include "sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts a sa_buffer into byte and checks the parameters for validity.
 *
 * @param[out] bytes the array of bytes.
 * @param[in] buffer the buffer to convert.
 * @param[in] bytes_to_process the number of bytes that will be written to or read from the buffer.
 * @param[in] client the client.
 * @param[in] caller_uuid the UUID of the caller.
 * @return the status of the validity check.
 */
sa_status convert_buffer(
        uint8_t** bytes,
        const sa_buffer* buffer,
        size_t bytes_to_process,
        const client_t* client,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // BUFFER_H
