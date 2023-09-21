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

#ifndef TA_SA_CENC_H
#define TA_SA_CENC_H

#include "sa_cenc.h"
#include "ta_sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Process an array of sample data chunks with the cipher context according to ISO/IEC 23001-7
 * Common encryption in ISO base media file format files specification.
 *
 * @param[in] samples the array of sample data chunks.
 * @param[in] samples_length the size of the samples array.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - iv, samples, subsample_lengths, out, or in is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + in.context.svp/clear.length + in.context.svp/clear.offset is not equal to the length of all of the
 *     bytes_of_clear_data and bytes_of_protected_data for all of the samples
 *   + Writing past the end of a clear or SVP buffer detected.
 *   + Context has already processed last chunk of data.
 * + SA_STATUS_INVALID_SVP_MEMORY - SVP buffer is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_process_common_encryption(
        size_t samples_length,
        sa_sample* samples,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // TA_SA_CENC_H
