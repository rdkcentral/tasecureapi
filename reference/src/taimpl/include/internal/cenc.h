/*
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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
 * @file cenc.h
 *
 * This file contains the functions implementing common encryption.
 */

#ifndef CENC_H
#define CENC_H

#include "client_store.h"
#include "sa_cenc.h"

#define CENC_OVERFLOW 0

/**
 * Returns the required length of a buffer for the sample.
 *
 * @param[in] subsample_lengths the lengths of the subsample components.
 * @param[in] subsample_count the number of subsamples.
 * @return the required length of a buffer for the sample. CENC_OVERFLOW if an integer overflow occurs.
 */
size_t cenc_get_required_length(
        sa_subsample_length* subsample_lengths,
        size_t subsample_count);

/**
 * Decrypts a sample using the common encryption algorithm specified in ISO/IEC 23001-7 Common encryption in ISO base
 * media file format files specification.
 *
 * @param[in/out] sample the structure containing the parameters of the sample.
 * @param[in] client the client store.
 * @param[in] cipher_store the cipher stored.
 * @param[in] caller_uuid the UUID of the caller.
 * @return the status of the operation.
 */
sa_status cenc_process_sample(
        sa_sample* sample,
        client_t* client,
        cipher_store_t* cipher_store,
        const sa_uuid* caller_uuid);

#endif // CENC_H
