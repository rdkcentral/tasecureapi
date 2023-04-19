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
 * @file otp.h
 *
 * This file contains the functions and structures simulating reading of OTP data as well as
 * performing the OTP rooted key ladder operations. Implementors shall replace this functionality
 * with hardened hardware based implementation.
 */

#ifndef OTP_H
#define OTP_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

/**
 * Obtain the 8 byte unique device id.
 *
 * @param[out] id device id.
 * @return true if the call succeeded, false otherwise.
 */
sa_status otp_device_id(uint64_t* id);

/**
 * Derive a key from OTP based root key using a 4 stage key ladder. First 3 stages will be performed
 * in a hardware key ladder.
 *
 * @param[out] stored_key_derived the derived 16 byte key.
 * @param[in] rights rights for the derived key.
 * @param[in] c1 16 byte input for the first stage of the key ladder.
 * @param[in] c2 16 byte input for the second stage of the key ladder.
 * @param[in] c3 16 byte input for the third stage of the key ladder.
 * @param[in] c4 16 byte input for the fourth stage of the key ladder.
 * @return SA_STATUS_OK if the call succeeded.
 */
sa_status otp_root_key_ladder(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        const void* c1,
        const void* c2,
        const void* c3,
        const void* c4);

/**
 * Derive a key from common based root key using a 4 stage key ladder. First 3 stages will be performed
 * in a hardware key ladder. SOCs that do not support a common root key should return false.
 *
 * @param[out] stored_key_derived the derived 16 byte key.
 * @param[in] rights rights for the derived key.
 * @param[in] c1 16 byte input for the first stage of the key ladder.
 * @param[in] c2 16 byte input for the second stage of the key ladder.
 * @param[in] c3 16 byte input for the third stage of the key ladder.
 * @param[in] c4 16 byte input for the fourth stage of the key ladder.
 * @return SA_STATUS_OK if the call succeeded, SA_STATUS_OPERATION_NOT_SUPPORTED if the SoC does not support a common
 * root key.
 */
sa_status otp_common_root_key_ladder(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        const void* c1,
        const void* c2,
        const void* c3,
        const void* c4);

#ifdef __cplusplus
}
#endif

#endif // OTP_H
