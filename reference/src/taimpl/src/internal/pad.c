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

#include "pad.h" // NOLINT
#include "common.h"
#include "log.h"

bool pad_check_pkcs7(
        uint8_t* pad_value,
        const void* block) {

    if (pad_value == NULL) {
        ERROR("NULL pad_value");
        return false;
    }

    if (block == NULL) {
        ERROR("NULL block");
        return false;
    }

    const uint8_t* ptr = (const uint8_t*) block;
    *pad_value = ptr[15];

    if (*pad_value < 1 || *pad_value > AES_BLOCK_SIZE) {
        ERROR("Invalid pad value encountered");
        return false;
    }

    for (size_t i = (AES_BLOCK_SIZE - *pad_value); i < AES_BLOCK_SIZE; ++i) {
        if (ptr[i] != *pad_value) {
            ERROR("Missing pad value");
            return false;
        }
    }

    return true;
}

bool pad_apply_pkcs7(
        void* out,
        uint8_t pad_value) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (pad_value < 1 || pad_value > AES_BLOCK_SIZE) {
        ERROR("Invalid pad value");
        return false;
    }

    uint8_t* ptr = (uint8_t*) out;

    for (size_t i = (AES_BLOCK_SIZE - pad_value); i < AES_BLOCK_SIZE; ++i) {
        ptr[i] = pad_value;
    }

    return true;
}
