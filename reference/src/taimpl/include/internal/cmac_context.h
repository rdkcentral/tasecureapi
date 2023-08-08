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
 * @file cmac_context.h
 *
 * This file contains the functions and structures implementing CMAC context.
 */

#ifndef CMAC_CONTEXT_H
#define CMAC_CONTEXT_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

typedef struct cmac_context_s cmac_context_t;

/**
 * Create CMAC context.
 *
 * @param[in] stored_key key.
 * @return created context.
 */
cmac_context_t* cmac_context_create(const stored_key_t* stored_key);

/**
 * Compute an CMAC over the input data.
 *
 * @param[in] context context.
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @return status of the operation.
 */
sa_status cmac_context_update(
        cmac_context_t* context,
        const void* in,
        size_t in_length);

/**
 * Compute an CMAC over the key.
 *
 * @param[in] context context.
 * @param[in] stored_key the stored key in the mac.
 * @return status of the operation.
 */
sa_status cmac_context_update_key(
        cmac_context_t* context,
        stored_key_t* stored_key);

/**
 * Compute the 16 byte CMAC value.
 *
 * @param[out] mac computed CMAC value.
 * @param[in] context context.
 * @return status of the operation.
 */
sa_status cmac_context_compute(
        void* mac,
        cmac_context_t* context);

/**
 * Check if the cmac context status is done.
 *
 * @param[in] context context.
 * @return true, if the context status is done.
 */
bool cmac_context_done(cmac_context_t* context);

/**
 * Release the CMAC context
 *
 * @param[in] context context.
 */
void cmac_context_free(cmac_context_t* context);

/**
 * Compute the 16 byte CMAC value over inputs.
 *
 * @param[out] mac computed CMAC value.
 * @param[in] in1 first input buffer.
 * @param[in] in1_length first input buffer length.
 * @param[in] in2 second input buffer.
 * @param[in] in2_length second input buffer length.
 * @param[in] in3 third input buffer.
 * @param[in] in3_length third input buffer length.
 * @param[in] stored_key key.
 * @return status of the operation.
 */
sa_status cmac(
        void* mac,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length,
        const stored_key_t* stored_key);

#ifdef __cplusplus
}
#endif

#endif // CMAC_CONTEXT_H
