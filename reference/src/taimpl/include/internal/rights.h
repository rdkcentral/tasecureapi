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

/** @section Description
 * @file rights.h
 *
 * This file contains the functions and structures for validating key rights required for
 * cryptographic operations.
 */

#ifndef RIGHTS_H
#define RIGHTS_H

#include "porting/video_output.h"
#include "sa_types.h"

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
 * Length of an ASCII UUID.
 */
#define UUID_LENGTH 36

/**
 * Key usage values as defined in TypeJ and SOC key containers.
 */
typedef enum {
    TYPEJ_DATA_AND_KEY = 0,
    DATA_ONLY = 1,
    KEY_ONLY = 2,
    SOC_DATA_AND_KEY = 3
} key_usage;

/**
 * UUID value that matches no TA IDs.
 */
extern const sa_uuid NO_MATCH;

/**
 * UUID value that matches any TA ID.
 */
extern const sa_uuid ALL_MATCH;

/**
 * Validate rights format.
 *
 * @param[in] rights rights.
 * @return true if valid, false otherwise.
 */
bool rights_validate_format(const sa_rights* rights);

/**
 * Check whether derive operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_derive(const sa_rights* rights);

/**
 * Check whether key exchange operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_exchange(const sa_rights* rights);

/**
 * Check whether unwrap operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_unwrap(const sa_rights* rights);

/**
 * Check whether decrypt operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @param[in] key_type key type.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_decrypt(
        const sa_rights* rights,
        sa_key_type key_type);

/**
 * Check whether encrypt operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @param[in] key_type key type.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_encrypt(
        const sa_rights* rights,
        sa_key_type key_type);

/**
 * Check whether clear operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_clear(const sa_rights* rights);

/**
 * Check whether sign operation is allowed using the given key and current state of outputs.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_sign(const sa_rights* rights);

/**
 * Check whether specified time is within validity time specified in key rights.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_time(
        const sa_rights* rights,
        uint64_t time);

/**
 * Check whether current video output state satisfies requirements in key rights.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_video_output_state(
        const sa_rights* rights,
        const video_output_state_t* video_output_state);

/**
 * Check whether the uuid is in allowed TA list.
 *
 * @param[in] rights rights.
 * @return true if allowed, false otherwise.
 */
bool rights_allowed_uuid(
        const sa_rights* rights,
        const sa_uuid* caller_uuid);

/**
 * Convert a key_usage byte to usage_flags.
 * @param usage_flags usage flags bitfield.
 * @param key_usage key usage byte.
 * @param key_type the type of the key.
 * @return
 */
sa_status key_usage_to_usage_flags(
        uint64_t* usage_flags,
        int64_t key_usage,
        sa_key_type key_type);

/**
 * Converts a UUID from string form to uint_8 array form.
 * @param uuid_str the UUID string to convert.
 * @param uuid_str_length the length of the UUID string.
 * @param uuid the uint8_t array to put the converted UUID into
 * @return true if the UUID is properly formatted and false if not.
 */
bool convert_uuid(
        const char* uuid_str,
        size_t uuid_str_length,
        sa_uuid* uuid);

#ifdef __cplusplus
}
#endif

#endif // RIGHTS_H
