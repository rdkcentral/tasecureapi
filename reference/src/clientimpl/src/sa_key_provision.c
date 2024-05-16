/*
 * Copyright 2020-2024 Comcast Cable Communications Management, LLC
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
#include "ta_client.h"
#include "sa_key_provision_impl.h"
#include "sa.h"
#include <stdbool.h>

sa_status sa_key_provision_ta (
   sa_key_type_ta ta_key_type,
   const void* in,
   size_t in_length,
   void* parameters) {

   sa_status status = SA_STATUS_OK;
   if (SA_STATUS_OK != 
      (status = sa_key_provision_preprocessing(ta_key_type, in, in_length, parameters))) {
      return status; 
   }

   void* session = client_session();
   if (NULL == session) {
       ERROR("client_session failed");
       return SA_STATUS_INTERNAL_ERROR;
   }
   sa_key_provision_ta_s* key_provision_ta = NULL;
   void* param1 = NULL;
   void* param2 = NULL;
   void* param3 = NULL;
   do {
        CREATE_COMMAND(sa_key_provision_ta_s, key_provision_ta);
        key_provision_ta->api_version = API_VERSION;
        key_provision_ta->key = INVALID_HANDLE;
        key_provision_ta->key_format = SA_KEY_FORMAT_PROVISION_TA;
        key_provision_ta->curve = 0;

        size_t param1_size;
        uint32_t param1_type;
        if (NULL != in) {
            CREATE_PARAM(param1, (void*)in,in_length);
            param1_size = in_length;
            param1_type = TA_PARAM_IN;
        } else {
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }
        size_t param2_size;
        uint32_t param2_type;

        if (NULL != parameters) {
            param2_size = ((size_t) ((uint8_t*) parameters)[0] << 8) + (size_t) ((uint8_t*) parameters)[1];
            CREATE_PARAM(param2, parameters, param2_size);
            param2_type = TA_PARAM_IN;
        } else {
            param2 = NULL;
            param2_size = 0;
            param2_type = TA_PARAM_NULL;
        }
        size_t param3_size = sizeof(ta_key_type);
        CREATE_PARAM(param3, (void*)&ta_key_type, param3_size);
        uint32_t param3_type = TA_PARAM_IN;

        
        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, param3_type};
        ta_param params[NUM_TA_PARAMS] = {{key_provision_ta, sizeof(sa_key_provision_ta_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {param3, param3_size}};
        INFO("param0: 0x%x, param0_size: %d", key_provision_ta, sizeof(sa_key_provision_ta_s));
        INFO("param1: 0x%x, param1_size: %d", param1, param1_size);
        INFO("param2: 0x%x, param2_size: %d", param2,param2_size);
        INFO("ta_key_type:%d, param3: %d, param3_size: %d",ta_key_type,*((int*)param3),param3_size);
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_PROVISION_TA, param_types, params);

        if (SA_STATUS_OK != status) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
        INFO("key:%d", key_provision_ta->key);
    } while (false);

    // ATTENTION: If you dont release the key, you will get resource leaked.
    if (INVALID_HANDLE != key_provision_ta->key) {
        sa_key_release(key_provision_ta->key);
    }
    RELEASE_COMMAND(key_provision_ta);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    RELEASE_PARAM(param3);

    return status;   
}
