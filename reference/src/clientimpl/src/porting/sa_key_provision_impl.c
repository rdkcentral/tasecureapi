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
#include "sa.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_key_provision_preprocessing(
   const sa_key_type_ta ta_key_type,
   const void* in,
   const size_t in_length,
   void* parameters) {

   sa_status status = SA_STATUS_OK;
   if (NULL == in         ||
       NULL == parameters ||
       0 == in_length) {
      ERROR("null input or input size is 0 or null parameters");
      return SA_STATUS_NULL_PARAMETER;
   }
   INFO("in_length: %d", in_length);
   switch(ta_key_type) {
      case WIDEVINE_OEM_PROVISIONING:
         if (NULL == ((WidevineOemProvisioning*)in)->oemDevicePrivateKey      ||
             0 == ((WidevineOemProvisioning*)in)->oemDevicePrivateKeyLength   ||
             NULL == ((WidevineOemProvisioning*)in)->oemDeviceCertificate     ||
             0 == ((WidevineOemProvisioning*)in)->oemDeviceCertificateLength) {
             ERROR("null private key/cert or size is  0");
             return SA_STATUS_NULL_PARAMETER;
         }
         break;

      case PLAYREADY_MODEL_PROVISIONING:
         if (NULL == ((PlayReadyProvisioning*)in)->privateKey             ||
             0 == ((PlayReadyProvisioning*)in)->privateKeyLength          ||
             NULL == ((PlayReadyProvisioning*)in)->modelCertificate       ||
             0 == ((PlayReadyProvisioning*)in)->modelCertificateLength)   {
             ERROR("null private key / cert or input size is  0");
             return SA_STATUS_NULL_PARAMETER;
         }
         break;

      case NETFLIX_PROVISIONING:
         if (NULL == ((NetflixProvisioning*)in)->hmacKey         ||
             0 == ((NetflixProvisioning*)in)->hmacKeyLength      ||
             NULL == ((NetflixProvisioning*)in)->wrappingKey     ||
             0 == ((NetflixProvisioning*)in)->wrappingKeyLength  ||
             NULL == ((NetflixProvisioning*)in)->esnContainer    ||
             0 == ((NetflixProvisioning*)in)->esnContainerLength) {
             ERROR("null input or input size is  0");
             return SA_STATUS_NULL_PARAMETER;
         }
         break;

      case APPLE_MFI_PROVISIONING:
      case APPLE_FAIRPLAY_PROVISIONING:
         /* TODO SoC Vendor:Implement per guidance from Apple. */
         return SA_STATUS_OPERATION_NOT_SUPPORTED;
      default:
         ERROR("Unknown provisioning type");
         return SA_STATUS_INVALID_PARAMETER;
    }

    return status;
}
