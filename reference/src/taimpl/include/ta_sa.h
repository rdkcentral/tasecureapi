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

/** @section Description
 * @file ta_sa.h
 *
 * This file contains the TA implementation of "info" module functions. Please refer to sa.h
 * file for method and parameter documentation.
 */

#ifndef TA_SA_H
#define TA_SA_H

#include "sa_types.h"
#include "ta_sa_cenc.h"
#include "ta_sa_crypto.h"
#include "ta_sa_key.h"
#include "ta_sa_types.h"

#ifdef __cplusplus

#include <cstddef>

extern "C" {
#else
#include <stddef.h>
#endif

/**
 * Initializes the TA.
 *
 * @param[out] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - No available client slots.
 * + SA_STATUS_NULL_PARAMETER - version is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_init(
        ta_client* client_slot,
        const sa_uuid* caller_uuid);

/**
 * Closes the TA.
 *
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - version is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_close(
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the firmware version.
 *
 * @param[out] version Pointer to structure where the version information will be written.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - version is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_get_version(
        sa_version* version,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the SecAPI implementation name, e.g. SoC manufacturer.
 *
 * @param[out] name Buffer where implementation name will be written. Can be set to NULL to
 * obtain the required length.
 * @param[in,out] name_length Length of the name buffer. Set to number of bytes required to
 * store the name.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - name_length is NULL.
 * + SA_STATUS_INVALID_PARAMETER - name is not NULL and *name_length value is smaller than required to
 * store the name.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_get_name(
        char* name,
        size_t* name_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the device ID. ID will be formatted according to the "SoC Identifier Specification"
 * specification.
 *
 * @param[out] id Device ID.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - id is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_get_device_id(
        uint64_t* id,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the UUID of the TA making this call.
 *
 * @param[out] uuid TA uuid.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - uuid is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_get_ta_uuid(
        sa_uuid* uuid,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif
