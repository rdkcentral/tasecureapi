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

/**
 * @file sa.h Include file for the SecAPI library.
 *
 * sa.h header file includes all other SecAPI headers. Applications should only include this
 * one header file to import all SecAPI declarations.
 *
 * Functions are separated into 4 different modules. "key" module functions perform operations
 * related to importing, generating, deriving, and negotiating new keys. "crypto" module contains
 * functions for performing cryptographic operations in generally accessible RAM. "svp" module
 * contains functions for performing cryptographic operations in Secure Video Pipeline protected
 * memory region. "info" module, in this file, contains functions for obtaining implementation
 * and device information.
 */

#ifndef SA_H
#define SA_H

#include "sa_cenc.h"
#include "sa_crypto.h"
#include "sa_key.h"
#include "sa_types.h"

/**
 * SecAPI specification major version
 */
#define SA_SPECIFICATION_MAJOR 3

/**
 * SecAPI specification minor version
 */
#define SA_SPECIFICATION_MINOR 4

/**
 * SecAPI specification revision
 */
#define SA_SPECIFICATION_REVISION 1

/**
 * Stringify helper macro.
 */
#define STR(arg) #arg

/**
 * Stringify helper macro.
 */
// clang-format off
#define VERSION_STR(x, y, z) STR(x) "." STR(y) "." STR(z)
// clang-format on

/**
 * SecAPI version string.
 */
#define SA_SPECIFICATION_STR VERSION_STR(SA_SPECIFICATION_MAJOR, SA_SPECIFICATION_MINOR, SA_SPECIFICATION_REVISION)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Obtain the firmware version.
 *
 * @param[out] version Pointer to structure where the version information will be written.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - version is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_get_version(sa_version* version);

/**
 * Obtain the SecAPI implementation name, e.g. SoC manufacturer.
 *
 * @param[out] name Buffer where implementation name will be written. Can be set to NULL to
 * obtain the required length.
 * @param[in,out] name_length Length of the name buffer. Set to number of bytes required to
 * store the name.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - name_length is NULL.
 * + SA_STATUS_INVALID_PARAMETER - name is not NULL and *name_length value is smaller than required to
 * store the name.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_get_name(
        char* name,
        size_t* name_length);

/**
 * Obtain the device ID. ID will be formatted according to the "SoC Identifier Specification"
 * specification.
 *
 * @param[out] id Device ID.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - id is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_get_device_id(uint64_t* id);

/**
 * Obtain the UUID of the TA making this call.
 *
 * @param[out] uuid TA uuid.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - uuid is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_get_ta_uuid(sa_uuid* uuid);

#ifdef __cplusplus
}
#endif

#endif /* SA_H */
