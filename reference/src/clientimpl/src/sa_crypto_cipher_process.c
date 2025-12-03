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

sa_status sa_crypto_cipher_process(
        sa_buffer* out,
        sa_crypto_cipher_context context,
        sa_buffer* in,
        size_t* bytes_to_process) {

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (bytes_to_process == NULL) {
        ERROR("NULL bytes_to_process");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_crypto_cipher_process_s* cipher_process = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_cipher_process_s, cipher_process);
        cipher_process->api_version = API_VERSION;
        cipher_process->context = context;
        cipher_process->bytes_to_process = *bytes_to_process;
        cipher_process->out_buffer_type = (out != NULL) ? out->buffer_type : SA_BUFFER_TYPE_CLEAR;
        cipher_process->in_buffer_type = in->buffer_type;

        size_t param1_size;
        uint32_t param1_type;
        if (out != NULL) {
            if (out->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                if (out->context.clear.buffer == NULL) {
                    ERROR("NULL out.context.clear.buffer");
                    status = SA_STATUS_NULL_PARAMETER;
                    break;
                }

                if (out->context.clear.offset > out->context.clear.length) {
                    ERROR("Integer overflow");
                    status = SA_STATUS_INVALID_PARAMETER;
                    break;
                }

                cipher_process->out_offset = 0;
                param1_size = out->context.clear.length - out->context.clear.offset;
                param1_type = TA_PARAM_OUT;
                CREATE_OUT_PARAM(param1, ((uint8_t*) out->context.clear.buffer) + out->context.clear.offset,
                        param1_size);
            }
        } else {
            cipher_process->out_offset = 0;
            param1 = NULL;
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }

        size_t param2_size = 0;
        uint32_t param2_type = TA_PARAM_IN;
        if (in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
            if (in->context.clear.buffer == NULL) {
                ERROR("NULL in.context.clear.buffer");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (in->context.clear.offset > in->context.clear.length) {
                ERROR("Integer overflow");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            cipher_process->in_offset = 0;
            param2_size = in->context.clear.length - in->context.clear.offset;
            CREATE_PARAM(param2, ((uint8_t*) in->context.clear.buffer) + in->context.clear.offset, param2_size);
        }

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{cipher_process, sizeof(sa_crypto_cipher_process_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_CIPHER_PROCESS, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        if (out != NULL) {
            if (out->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                COPY_OUT_PARAM(((uint8_t*) out->context.clear.buffer) + out->context.clear.offset, param1,
                        cipher_process->out_offset);
                out->context.clear.offset += cipher_process->out_offset;
            }
        }

        if (in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
            in->context.clear.offset += cipher_process->in_offset;
	}

        *bytes_to_process = cipher_process->bytes_to_process;
    } while (false);

    RELEASE_COMMAND(cipher_process);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
