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

#ifndef SA_CENC_H
#define SA_CENC_H

#include "sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Identifies the size of a subsample and the number of clear and encrypted bytes in the subsample.
 * See ISO/IEC 23001-7 Common encryption in ISO base media file format files specification for the
 * definition of these fields.
 */
typedef struct {
    /**
     * The number of bytes of clear data in this Subsample.
     */
    size_t bytes_of_clear_data;

    /**
     * The number of bytes of protected data in this Subsample.
     */
    size_t bytes_of_protected_data;
} sa_subsample_length;

/**
 * Identifies the number of subsamples in a sample and the encryption pattern used in the protected
 * data blocks. See ISO/IEC 23001-7 Common encryption in ISO base media file format files
 * specification for the definition of these fields.
 */
typedef struct {
    /**
     * The IV to use for the sample. CBCS mode resets the IV at every subsample. All other modes
     * use the IV starting at the beginning of the sample.
     */
    void* iv;

    /**
     * The length of the IV.
     */
    size_t iv_length;

    /**
     * Identifies the number of blocks that are encrypted in the protected data section. In CENS
     * mode and CBCS mode the protected data is only partially encrypted. This field is non-zero and
     * identifies the number of 16 byte blocks that are encrypted. The following field identifies
     * the number of 16 bytes block that are skipped. This pattern repeats until the entire
     * protected block is used. Any remaining block less than 16 bytes is unencrypted. Setting this
     * field to 0 indicates CENC or CBC1 mode and that the entire protected data section is
     * encrypted. See ISO/IEC 23001-7 section 10.
     */
    size_t crypt_byte_block;

    /**
     * Identifies the number of blocks that are skipped in a protected data section. In CENC and
     * CBC1 mode, the entire protected data section is encrypted and this field must be set to 0.
     * In CENS and CBCS mode, audio tracks can be fully encrypted, so this field should be set to
     * 0 for those cases. See ISO/IEC 23001-7 section 10.
     */
    size_t skip_byte_block;

    /**
     * The number of subsamples in the sample.
     */
    size_t subsample_count;

    /**
     * An array of subsample data.
     */
    sa_subsample_length* subsample_lengths;

    /**
     * The cipher context to use that identifies the algorithm, mode, key, and buffer type.
     */
    sa_crypto_cipher_context context;

    /**
     * Identifies the decrypted output destination.
     */
    sa_buffer* out;

    /**
     * The encrypted input data.
     */
    sa_buffer* in;
} sa_sample;

/**
 * Process an array of sample data chunks with the cipher context according to ISO/IEC 23001-7
 * Common encryption in ISO base media file format files specification.
 *
 * @param[in] samples the array of sample data chunks.
 * @param[in] samples_length the size of the samples array.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - samples, iv, subsample_lengths, out, or in is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + in.context.svp/clear.length + in.context.svp/clear.offset is not equal to the length of all of the
 *     bytes_of_clear_data and bytes_of_protected_data for all of the samples
 *   + Writing past the end of a clear or SVP buffer detected.
 *   + Context has already processed last chunk of data.
 * + SA_STATUS_BAD_SVP_BUFFER - SVP buffer is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_process_common_encryption(
        size_t samples_length,
        sa_sample* samples);

#ifdef __cplusplus
}
#endif

#endif /* SA_CENC_H */
