/**
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
 * @file pad.h
 *
 * This file contains the functions and structures implementing PKCS7 padding.
 */

#ifndef PAD_H
#define PAD_H

#ifdef __cplusplus

#include <cstdbool>
#include <cstdint>

extern "C" {
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#define PADDED_SIZE(size) AES_BLOCK_SIZE*(((size) / AES_BLOCK_SIZE) + 1)

/**
 * Check pkcs7 padding of a block of data.
 *
 * @param[out] pad_value pad value.
 * @param[in] block AES block.
 * @return status of pad check. true if padding is valid, false if it is not.
 */
bool pad_check_pkcs7(
        uint8_t* pad_value,
        const void* block);

/**
 * Apply pkcs7 padding to a block of data.
 *
 * @param[out] out AES block to pad.
 * @param[in] pad_value pad value.
 * @return status of the operation.
 */
bool pad_apply_pkcs7(
        void* out,
        uint8_t pad_value);

#ifdef __cplusplus
}
#endif

#endif // PAD_H
