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
 * @file hmac_context.h
 *
 * This file contains the functions and structures implementing HMAC context.
 */

#ifndef HMAC_CONTEXT_H
#define HMAC_CONTEXT_H

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

typedef struct hmac_context_s hmac_context_t;

/**
 * Create the HMAC context.
 *
 * @param[in] digest_algorithm digest algorithm.
 * @param[in] stored_key key.
 * @return created context.
 */
hmac_context_t* hmac_context_create(
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key);

/**
 * Obtain HMAC context digest algorithm.
 *
 * @param[in] context context.
 * @return digest algorithm. -1 of the context is NULL.
 */
sa_digest_algorithm hmac_context_get_digest(const hmac_context_t* context);

/**
 * Compute an HMAC over the input data.
 *
 * @param[in] context context.
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @return status of the operation.
 */
sa_status hmac_context_update(
        hmac_context_t* context,
        const void* in,
        size_t in_length);

/**
 * Compute an HMAC over the key.
 *
 * @param[in] context context.
 * @param[in] stored_key the stored key in the mac.
 * @return status of the operation.
 */
sa_status hmac_context_update_key(
        hmac_context_t* context,
        stored_key_t* stored_key);

/**
 * Compute the HMAC value.
 *
 * @param[out] mac mac value.
 * @param[in,out] mac_length mac value length. Set to number of bytes written on exit.
 * @param[in] context context.
 * @return status of the operation.
 */
sa_status hmac_context_compute(
        void* mac,
        size_t* mac_length,
        hmac_context_t* context);

/**
 * Check if the hmac context status is done.
 *
 * @param[in] context context.
 * @return true, if the context status is done.
 */
bool hmac_context_done(hmac_context_t* context);

/**
 * Release the HMAC context.
 *
 * @param[in] context context.
 */
void hmac_context_free(hmac_context_t* context);

/**
 * Compute the HMAC SHA value over inputs.
 *
 * @param[out] mac mac value.
 * @param[in,out] mac_length mac value length. Set to number of bytes written on exit.
 * @param[in] digest_algorithm digest algorithm.
 * @param[in] in1 first input data.
 * @param[in] in1_length first input data length.
 * @param[in] in2 second input data.
 * @param[in] in2_length second input data length.
 * @param[in] in3 third input data.
 * @param[in] in3_length third input data length.
 * @param[in] stored_key key.
 * @return status of the operation.
 */
sa_status hmac(
        void* mac,
        size_t* mac_length,
        sa_digest_algorithm digest_algorithm,
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

#endif // HMAC_CONTEXT_H
