/**
 * Copyright 2019-2021 Comcast Cable Communications Management, LLC
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
 * @file json.h
 *
 * This file contains the functions and structures implementing JSON parsing.
 */

#ifndef JSON_H
#define JSON_H

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

// clang-format off
#define b64_decoded_length(x) ((x / 4 + (x % 4 > 0 ? 1 : 0)) * 3)
// clang-format on

typedef enum {
    JSON_TYPE_BOOL = 0,
    JSON_TYPE_DOUBLE,
    JSON_TYPE_ARRAY,
    JSON_TYPE_MAP,
    JSON_TYPE_INT,
    JSON_TYPE_NUMBER,
    JSON_TYPE_STRING
} json_type_e;

typedef struct json_value_s json_value_t;

typedef struct {
    const char* key;
    size_t key_length;
    const json_value_t* value;
} json_key_value_t;

/**
 * Parse JSON bytes.
 *
 * @param[in] in input buffer.
 * @param[in] in_length input buffer length.
 * @return parsed value.
 */
json_value_t* json_parse_bytes(
        const void* in,
        size_t in_length);

/**
 * Free parsed value. Noop on NULL value.
 *
 * @param[in] value parsed value.
 */
void json_value_free(json_value_t* value);

/**
 * Get value type.
 *
 * @param[in] value parsed value.
 * @return type of value. -1 if value is NULL.
 */
json_type_e json_value_get_type(const json_value_t* value);

/**
 * Get boolean value.
 *
 * @param[in] value parsed value.
 * @return contained boolean value. false if value is NULL or not a boolean.
 */
bool json_value_as_bool(const json_value_t* value);

/**
 * Get double value.
 *
 * @param[in] value parsed value.
 * @return contained double value. 0 if value is NULL or not a double.
 */
double json_value_as_double(const json_value_t* value);

/**
 * Get values contained in the array. Returned array must be freed by the caller using
 * memory_internal_free.
 *
 * @param[out] count number of elements in the array.
 * @param[in] value parsed value.
 * @return array of contained values. NULL if value is NULL or not an array.
 */
json_value_t** json_value_as_array(
        size_t* count,
        const json_value_t* value);

/**
 * Get key/value pairs contained in the map. Returned array of key/values must be freed by the
 * caller using memory_internal_free.
 *
 * @param[out] count number of key/values in the map.
 * @param[in] value parsed value.
 * @return array of contained key/value pairs. NULL if the value is NULL or not a map.
 */
json_key_value_t* json_value_as_map(
        size_t* count,
        const json_value_t* value);

/**
 * Find a map entry with a given key.
 *
 * @param[in] key map key.
 * @param[in] key_values an array of map values.
 * @param[in] count number of key value pairs.
 * @return key/value entry with the specified key, or NULL if such value does not exist.
 */
const json_key_value_t* json_key_value_find(
        const char* key,
        const json_key_value_t* key_values,
        size_t count);

/**
 * Get integer value.
 *
 * @param[in] value parsed value.
 * @return contained integer value. 0 if the value is NULL or not an integer.
 */
int64_t json_value_as_integer(const json_value_t* value);

/**
 * Get string value. Returns the pointer to an internal null terminated character array.
 *
 * @param[out] size set to length of the string not including the null terminator if not NULL.
 * @param[in] value parsed value.
 * @return contained string value. NULL if the value is NULL or not a string.
 */
const char* json_value_as_string(size_t* size, const json_value_t* value);

/**
 * Get string representation of the number value. Returns the pointer to an internal null
 * terminated character array.
 *
 * @param[in] value parsed value.
 * @return contained number value. NULL if the value is NULL or not a number.
 */
const char* json_value_as_number(const json_value_t* value);

/**
 * Decodes a base64 encoded string in place.
 * @param [out] the place where the decoded string will be written.
 * @param[in/out] out_length the length of the out buffer and will return the number of bytes written.
 * @param[in] in the buffer containing the encoded string.
 * @param[in] in_length the length of the encoded string.
 * @param[in] url_decode use base64url decoding.
 * @return true if the decode was successful.
 */
bool b64_decode(
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length,
        bool url_decode);

/**
 * Converts a string from upper case to lower case.
 * @param str the string to convert.
 * @param length the length of the string.
 */
void string_to_lowercase(
        uint8_t* str,
        size_t length);

#ifdef __cplusplus
}
#endif

#endif // JSON_H
