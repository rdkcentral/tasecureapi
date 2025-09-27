/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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

#include "client.h"
#include "log.h"
#include "sa.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_process_common_encryption(
        size_t samples_length,
        sa_sample* samples) {

    if (samples == NULL) {
        ERROR("NULL samples");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (samples_length < 1) {
        ERROR("samples_length < 1");
        return SA_STATUS_INVALID_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_process_common_encryption_s* process_common_encryption = NULL;
    sa_subsample_length_s* subsample_length_s = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    void* param3 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_process_common_encryption_s, process_common_encryption);
        for (size_t i = 0; i < samples_length; i++) {
            if (samples[i].iv == NULL) {
                ERROR("NULL iv");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (samples[i].iv_length != AES_BLOCK_SIZE) {
                ERROR("iv is invalid size");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            if (samples[i].subsample_lengths == NULL) {
                ERROR("NULL subsample_lengths");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (samples[i].out == NULL) {
                ERROR("NULL out");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (samples[i].in == NULL) {
                ERROR("NULL in");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            process_common_encryption->api_version = API_VERSION;
            memcpy(process_common_encryption->iv, samples[i].iv, samples[i].iv_length);
            process_common_encryption->crypt_byte_block = samples[i].crypt_byte_block;
            process_common_encryption->skip_byte_block = samples[i].skip_byte_block;
            process_common_encryption->subsample_count = samples[i].subsample_count;
            process_common_encryption->context = samples[i].context;
            process_common_encryption->out_buffer_type = samples[i].out->buffer_type;
            process_common_encryption->in_buffer_type = samples[i].in->buffer_type;

            size_t param1_size = samples[i].subsample_count * sizeof(sa_subsample_length_s);
            subsample_length_s = malloc(param1_size);
            if (subsample_length_s == NULL) {
                ERROR("malloc failed");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            for (size_t j = 0; j < samples[i].subsample_count; j++) {
                subsample_length_s[j].bytes_of_clear_data = samples[i].subsample_lengths[j].bytes_of_clear_data;
                subsample_length_s[j].bytes_of_protected_data = samples[i].subsample_lengths[j].bytes_of_protected_data;
            }

            CREATE_PARAM(param1, samples[i].subsample_lengths, param1_size);
            uint32_t param1_type = TA_PARAM_IN;
            size_t param2_size;
            uint32_t param2_type;
            if (samples[i].out->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                if (samples[i].out->context.clear.buffer == NULL) {
                    ERROR("NULL samples[i].out.context.clear.buffer");
                    status = SA_STATUS_NULL_PARAMETER;
                    break;
                }

                if (samples[i].out->context.clear.offset > samples[i].out->context.clear.length) {
                    ERROR("Integer overflow");
                    status = SA_STATUS_INVALID_PARAMETER;
                    break;
                }

                process_common_encryption->out_offset = 0;
                param2_size = samples[i].out->context.clear.length - samples[i].out->context.clear.offset;

                param2_type = TA_PARAM_OUT;
                CREATE_OUT_PARAM(param2,
                        ((uint8_t*) samples[i].out->context.clear.buffer) + samples[i].out->context.clear.offset,
                        param2_size);
            }
#ifndef DISABLE_SVP
	    else {
                process_common_encryption->out_offset = samples[i].out->context.svp.offset;
                param2_size = sizeof(sa_svp_buffer);
                param2_type = TA_PARAM_IN;
                CREATE_PARAM(param2, &samples[i].out->context.svp.buffer, param2_size);
            }
#endif // DISABLE_SVP

            size_t param3_size;
            uint32_t param3_type = TA_PARAM_IN;
            if (samples[i].in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                if (samples[i].in->context.clear.buffer == NULL) {
                    ERROR("NULL samples[i].in.context.clear.buffer");
                    status = SA_STATUS_NULL_PARAMETER;
                    break;
                }

                if (samples[i].in->context.clear.offset > samples[i].in->context.clear.length) {
                    ERROR("Integer overflow");
                    status = SA_STATUS_INVALID_PARAMETER;
                    break;
                }

                process_common_encryption->in_offset = 0;
                param3_size = samples[i].in->context.clear.length - samples[i].in->context.clear.offset;
                CREATE_PARAM(param3,
                        ((uint8_t*) samples[i].in->context.clear.buffer) + samples[i].in->context.clear.offset,
                        param3_size);
            }
#ifndef DISABLE_SVP 
	    else {
                process_common_encryption->in_offset = samples[i].in->context.svp.offset;
                param3_size = sizeof(sa_svp_buffer);
                CREATE_PARAM(param3, &samples[i].in->context.svp.buffer, param3_size);
            }
#endif

            // clang-format off
            uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, param3_type};
            ta_param params[NUM_TA_PARAMS] = {{process_common_encryption, sizeof(sa_process_common_encryption_s)},
                                           {param1, param1_size},
                                           {param2, param2_size},
                                           {param3, param3_size}};
            // clang-format on
            status = ta_invoke_command(session, SA_PROCESS_COMMON_ENCRYPTION, param_types, params);
            if (status != SA_STATUS_OK) {
                ERROR("ta_invoke_command failed: %d", status);
                break;
            }

            if (samples[i].out->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                COPY_OUT_PARAM(((uint8_t*) samples[i].out->context.clear.buffer) + samples[i].out->context.clear.offset,
                        param2, process_common_encryption->out_offset);
                samples[i].out->context.clear.offset += process_common_encryption->out_offset;
            }
#ifndef DISABLE_SVP
	    else if (samples[i].out->buffer_type == SA_BUFFER_TYPE_SVP) {
                samples[i].out->context.svp.offset = process_common_encryption->out_offset;
	    }
#endif // DISABLE_SVP

            if (samples[i].in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                samples[i].in->context.clear.offset += process_common_encryption->in_offset;
	    }
#ifndef DISABLE_SVP
            else if (samples[i].in->buffer_type == SA_BUFFER_TYPE_SVP) {
                samples[i].in->context.svp.offset = process_common_encryption->in_offset;
            }
#endif // DISABLE_SVP
            if (subsample_length_s != NULL)
                free(subsample_length_s);

            subsample_length_s = NULL;
            RELEASE_PARAM(param1);
            param1 = NULL;
            RELEASE_PARAM(param2);
            param2 = NULL;
            RELEASE_PARAM(param3);
            param3 = NULL;
        }
    } while (false);

    if (subsample_length_s != NULL)
        free(subsample_length_s);

    RELEASE_COMMAND(process_common_encryption);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    RELEASE_PARAM(param3);
    return status;
}
