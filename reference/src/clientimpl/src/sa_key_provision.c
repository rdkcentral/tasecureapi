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

#include "sa.h"
#include "sa_rights.h"
#include "log.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

sa_key *create_uninitialized_sa_key() {
   sa_key *handle = (sa_key*)calloc(sizeof(sa_key), 1);
   if (NULL == handle) {
      ERROR("Fail to allcate memory");
      return NULL;
   }
   *handle = INVALID_HANDLE;
   return handle;
}

sa_status release_sa_key(sa_key *key) {
   sa_status status = SA_STATUS_OK;

   if (NULL != key) {
      if (INVALID_HANDLE != *key) {
         status = sa_key_release(*key);
         if (SA_STATUS_OK != status) {
            ERROR("Fail to release key, status:%d", status);
         }
      }
      free(key);
      key = NULL;
   }
   return status;
}

sa_status sa_key_provision_ta (
        sa_key_type_ta ta_key_type,
        const void* in,
        size_t in_length,
        void* parameters) {

   sa_status status = SA_STATUS_OK;
   WidevineOemProvisioning    *wvProvision = NULL;
   PlayReadyProvisioning      *prProvision = NULL;
   NetflixProvisioning        *nflxProvision = NULL;
   AppleMfiProvisioning       *aaplMfiProvisioning = NULL;
   AppleFairPlayProvisioning  *aaplFPProvisioning = NULL;

   if (NULL == in ||
      0 == in_length) {
      ERROR("null input or input size is 0");
      return SA_STATUS_NULL_PARAMETER;
   }

   switch(ta_key_type) {
      case WIDEVINE_OEM_PROVISIONING:
         {
            DEBUG(" case WIDEVINE_OEM_PROVISIONING");
            if (NULL == ((WidevineOemProvisioning*)in)->oemDevicePrivateKey     ||
               0 == ((WidevineOemProvisioning*)in)->oemDevicePrivateKeyLength   ||
               NULL == ((WidevineOemProvisioning*)in)->oemDeviceCertificate     ||
               0 == ((WidevineOemProvisioning*)in)->oemDeviceCertificateLength) {
               ERROR("null private key/cert or size is  0");
               return SA_STATUS_NULL_PARAMETER;
            }

            wvProvision = calloc(sizeof(WidevineOemProvisioning), 1);
            if (NULL == wvProvision) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }

            /*deep copy*/
            wvProvision->oemDevicePrivateKeyLength =
               ((WidevineOemProvisioning*)in)->oemDevicePrivateKeyLength;
            wvProvision->oemDeviceCertificateLength =
               ((WidevineOemProvisioning*)in)->oemDeviceCertificateLength;

            wvProvision->oemDevicePrivateKey =
               (void*)calloc(wvProvision->oemDevicePrivateKeyLength, 1);
            if (NULL == wvProvision->oemDevicePrivateKey) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(wvProvision->oemDevicePrivateKey,
                   ((WidevineOemProvisioning*)in)->oemDevicePrivateKey,
                   wvProvision->oemDevicePrivateKeyLength);

            /*TODO SoC Vendor:here just provide an examlpe to pass certif ication data,
             how to use certif ication data is all up to SOC vendors.
            */
            wvProvision->oemDeviceCertificate =
               (void*)calloc(wvProvision->oemDeviceCertificateLength, 1);
            if (NULL == wvProvision->oemDeviceCertificate) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(wvProvision->oemDeviceCertificate,
                   ((WidevineOemProvisioning*)in)->oemDeviceCertificate,
                   wvProvision->oemDeviceCertificateLength);

            INFO("wvProvision:%x",wvProvision);
            INFO("keyLen : %d", wvProvision->oemDevicePrivateKeyLength);
            INFO("certLen : %d", wvProvision->oemDeviceCertificateLength);

            if (0 == (memcmp(wvProvision->oemDevicePrivateKey, "SIGN", 4))) {
               wvProvision->oemDevicePrivateKey += 8;
               wvProvision->oemDevicePrivateKeyLength -=8;
            } else {
              INFO("NO SIGN in the header");
            }

            sa_key *rsa_key = create_uninitialized_sa_key();
            assert(NULL != rsa_key);
            INFO("using SA_KEY_FORMAT_SOC");
            status = sa_key_import(rsa_key, SA_KEY_FORMAT_SOC,
                        wvProvision->oemDevicePrivateKey,
                        wvProvision->oemDevicePrivateKeyLength,NULL);

            if (NULL != wvProvision->oemDevicePrivateKey) {
               free(wvProvision->oemDevicePrivateKey);
               wvProvision->oemDevicePrivateKey = NULL;
            }
            if (NULL != wvProvision->oemDeviceCertificate) {
               free(wvProvision->oemDeviceCertificate);
               wvProvision->oemDeviceCertificate = NULL;
            }
            if (NULL != wvProvision) {
               free(wvProvision);
               wvProvision = NULL;
            }
            release_sa_key(rsa_key);

            if (SA_STATUS_OK != status) {
               ERROR("Faild to import widevine oem private key");
            }
            return status;
         }
         break;
      case PLAYREADY_MODEL_PROVISIONING:
         {
            DEBUG(" case PLAYREADY_MODEL_PROVISIONING");
            if (NULL == ((PlayReadyProvisioning*)in)->privateKey            ||
               0 == ((PlayReadyProvisioning*)in)->privateKeyLength          ||
               NULL == ((PlayReadyProvisioning*)in)->modelCertificate       ||
               0 == ((PlayReadyProvisioning*)in)->modelCertificateLength)   {
               ERROR("null private key / cert or input size is  0");
               return SA_STATUS_NULL_PARAMETER;
            }

            prProvision = calloc(sizeof(PlayReadyProvisioning), 1);
            if (NULL == prProvision) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }

            /*deep copy*/
            prProvision->privateKeyLength =
               ((PlayReadyProvisioning*)in)->privateKeyLength;
            prProvision->modelCertificateLength =
               ((PlayReadyProvisioning*)in)->modelCertificateLength;

            prProvision->privateKey =
               (uint8_t*)calloc(prProvision->privateKeyLength, 1);
            if (NULL == prProvision->privateKey) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(prProvision->privateKey, ((PlayReadyProvisioning*)in)->privateKey,
                   prProvision->privateKeyLength);

            /*TODO SoC Vendor:here just provide an examlpe to pass certif ication data
              and model type,how to use them is all up to SOC vendors.
            */
            prProvision->modelCertificate =
               (void*)calloc(prProvision->modelCertificateLength, 1);
            if (NULL == prProvision->modelCertificate) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(prProvision->modelCertificate,
                   ((PlayReadyProvisioning*)in)->modelCertificate,
                   prProvision->modelCertificateLength);

            INFO("prProvision:%x",prProvision);
            INFO("keyLen : %d", prProvision->privateKeyLength);
            INFO("CertLen : %d", prProvision->modelCertificateLength);
            INFO("Model type : %s",
                  (prProvision->modelType == PLAYREADY_MODEL_2K)? "model 2000" :
                  ((prProvision->modelType == PLAYREADY_MODEL_3K)? "model 3000":
                   "No such model type"));

            sa_key *rsa_key = create_uninitialized_sa_key();
            assert(NULL != rsa_key);
            status = sa_key_import(rsa_key, SA_KEY_FORMAT_SOC,
                                  prProvision->privateKey,prProvision->privateKeyLength, NULL);

            if (NULL != prProvision->privateKey) {
               free(prProvision->privateKey);
               prProvision->privateKey = NULL;
            }
            if (NULL != prProvision->modelCertificate) {
               free(prProvision->modelCertificate);
               prProvision->modelCertificate = NULL;
            }
            if (NULL != prProvision) {
               free(prProvision);
               prProvision = NULL;
            }
            release_sa_key(rsa_key);

            if (SA_STATUS_OK != status) {
               ERROR("Faild to import playready private key");
            }
            return status;
         }
         break;
      case NETFLIX_PROVISIONING:
         {
            DEBUG("case NETFLIX_PROVISIONING");
            if (NULL == ((NetflixProvisioning*)in)->hmacKey        ||
               0 == ((NetflixProvisioning*)in)->hmacKeyLength      ||
               NULL == ((NetflixProvisioning*)in)->wrappingKey     ||
               0 == ((NetflixProvisioning*)in)->wrappingKeyLength  ||
               NULL == ((NetflixProvisioning*)in)->esnContainer    ||
               0 == ((NetflixProvisioning*)in)->esnContainerLength) {
               ERROR("null input or input size is  0");
               return SA_STATUS_NULL_PARAMETER;
            }

            nflxProvision = calloc(sizeof(NetflixProvisioning), 1);
            if (NULL == nflxProvision) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }

            /*deep copy*/
            nflxProvision->hmacKeyLength =
               ((NetflixProvisioning*)in)->hmacKeyLength;
            nflxProvision->wrappingKeyLength =
               ((NetflixProvisioning*)in)->wrappingKeyLength;
            nflxProvision->esnContainerLength =
               ((NetflixProvisioning*)in)->esnContainerLength;

            nflxProvision->hmacKey =
               (void*)calloc(nflxProvision->hmacKeyLength, 1);

            if (NULL == nflxProvision->hmacKey) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(nflxProvision->hmacKey, ((NetflixProvisioning*)in)->hmacKey,
                   nflxProvision->hmacKeyLength);

            nflxProvision->wrappingKey =
               (void*)calloc(nflxProvision->wrappingKeyLength, 1);
            if (NULL == nflxProvision->wrappingKey) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(nflxProvision->wrappingKey,
                   ((NetflixProvisioning*)in)->wrappingKey,
                   nflxProvision->wrappingKeyLength);

            /*TODO SoC Vendor:here just provide an examlpe to pass ESN data,
             how to use it is all up toSOC vendors.
            */
            nflxProvision->esnContainer =
               (void*)calloc(nflxProvision->esnContainerLength, 1);
            if (NULL == nflxProvision->esnContainer) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(nflxProvision->esnContainer,
                   ((NetflixProvisioning*)in)->esnContainer,
                   nflxProvision->esnContainerLength);

            INFO("nflxProvision:%x",nflxProvision);
            INFO("hmacLen : %d", nflxProvision->hmacKeyLength);
            INFO("wrappingLen : %d", nflxProvision->wrappingKeyLength);
            INFO("ESNLen : %d", nflxProvision->esnContainerLength);

            sa_key *sa_hmac_key = create_uninitialized_sa_key();
            assert(NULL != sa_hmac_key);
            sa_status status_hmac = sa_key_import(sa_hmac_key, SA_KEY_FORMAT_SOC,
                                  nflxProvision->hmacKey,nflxProvision->hmacKeyLength,
                                  NULL);

            sa_key *sa_wrapping_key = create_uninitialized_sa_key();
            assert(NULL != sa_wrapping_key);

            sa_status status_wrapping = sa_key_import(sa_wrapping_key, SA_KEY_FORMAT_SOC,
                                  nflxProvision->wrappingKey,nflxProvision->wrappingKeyLength,
                                  NULL);

            if (NULL != nflxProvision->hmacKey) {
               free(nflxProvision->hmacKey);
               nflxProvision->hmacKey = NULL;
            }
            if (NULL != nflxProvision->wrappingKey) {
               free(nflxProvision->wrappingKey);
               nflxProvision->wrappingKey = NULL;
            }
            if (NULL != nflxProvision->esnContainer) {
               free(nflxProvision->esnContainer);
               nflxProvision->esnContainer = NULL;
            }
            if (NULL != nflxProvision) {
               free(nflxProvision);
               nflxProvision = NULL;
            }
            release_sa_key(sa_hmac_key);
            release_sa_key(sa_wrapping_key);

            if (SA_STATUS_OK != status_hmac) {
               ERROR("Faild to import netflix hmac key");
               return status_hmac;
            }
            if (SA_STATUS_OK != status_wrapping) {
               ERROR("Faild to import netflix wrapping key");
            }
            return status_wrapping;
         }
         break;
      case APPLE_MFI_PROVISIONING:
         {
            DEBUG(" case APPLE_MFI_PROVISIONING");
            if (NULL == ((AppleMfiProvisioning*)in)->mfiBaseKey           ||
               0 == ((AppleMfiProvisioning*)in)->mfiBaseKeyLength         ||
               NULL == ((AppleMfiProvisioning*)in)->mfiProvisioningObject ||
               0 == ((AppleMfiProvisioning*)in)->mfiProvisioningObjectLength) {
               ERROR("null private key/object or size is  0");
               return SA_STATUS_NULL_PARAMETER;
            }

            aaplMfiProvisioning = calloc(sizeof(AppleMfiProvisioning), 1);
            if (NULL == aaplMfiProvisioning) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }

            /*deep copy*/
            aaplMfiProvisioning->mfiBaseKeyLength =
               ((AppleMfiProvisioning*)in)->mfiBaseKeyLength;
            aaplMfiProvisioning->mfiProvisioningObjectLength =
               ((AppleMfiProvisioning*)in)->mfiProvisioningObjectLength;

            /*TODO SoC Vendor:here just provide an examlpe to pass-through MFI base key
              and provisioning obecjt,
              how to use these data is all up to SOC vendors.
            */
            aaplMfiProvisioning->mfiBaseKey =
               (void*)calloc(aaplMfiProvisioning->mfiBaseKeyLength, 1);
            if (NULL == aaplMfiProvisioning->mfiBaseKey) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(aaplMfiProvisioning->mfiBaseKey,
                   ((AppleMfiProvisioning*)in)->mfiBaseKey,
                   aaplMfiProvisioning->mfiBaseKeyLength);

            aaplMfiProvisioning->mfiProvisioningObject =
               (void*)calloc(aaplMfiProvisioning->mfiProvisioningObjectLength, 1);
            if (NULL == aaplMfiProvisioning->mfiProvisioningObject) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(aaplMfiProvisioning->mfiProvisioningObject,
                   ((AppleMfiProvisioning*)in)->mfiProvisioningObject,
                   aaplMfiProvisioning->mfiProvisioningObjectLength);

            INFO("aaplMfiProvisioning:%x",aaplMfiProvisioning);
            INFO("base key length : %d", aaplMfiProvisioning->mfiBaseKeyLength);
            INFO("provisioning object length : %d",
                  aaplMfiProvisioning->mfiProvisioningObjectLength);


            if (NULL != aaplMfiProvisioning->mfiBaseKey) {
               free(aaplMfiProvisioning->mfiBaseKey);
               aaplMfiProvisioning->mfiBaseKey = NULL;
            }
            if (NULL != aaplMfiProvisioning->mfiProvisioningObject) {
               free(aaplMfiProvisioning->mfiProvisioningObject);
               aaplMfiProvisioning->mfiProvisioningObject = NULL;
            }
            if (NULL != aaplMfiProvisioning) {
               free(aaplMfiProvisioning);
               aaplMfiProvisioning = NULL;
            }
         }
         break;
      case APPLE_FAIRPLAY_PROVISIONING:
         {
            DEBUG(" case APPLE_FAIRPLAY_PROVISIONING");
            if (NULL == ((AppleFairPlayProvisioning*)in)->fairPlaySecret  ||
               0 == ((AppleFairPlayProvisioning*)in)->fairPlaySecretLength) {
               ERROR("null private key or size is  0");
               return SA_STATUS_NULL_PARAMETER;
            }

            aaplFPProvisioning = calloc(sizeof(AppleFairPlayProvisioning), 1);
            if (NULL == aaplFPProvisioning) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }

            /*deep copy*/
            aaplFPProvisioning->fairPlaySecretLength =
               ((AppleFairPlayProvisioning*)in)->fairPlaySecretLength;

            /*TODO SoC Vendor:here just provide an examlpe to pass-through fairplay secret key
              how to use these data is all up to SOC vendors.
            */
            aaplFPProvisioning->fairPlaySecret =
               (void*)calloc(aaplFPProvisioning->fairPlaySecretLength, 1);
            if (NULL == aaplFPProvisioning->fairPlaySecret) {
               ERROR("calloc failed");
               return SA_STATUS_INTERNAL_ERROR;
            }
            memcpy(aaplFPProvisioning->fairPlaySecret,
                   ((AppleFairPlayProvisioning*)in)->fairPlaySecret,
                   aaplFPProvisioning->fairPlaySecretLength);

            INFO("aaplFPProvisioning:%x",aaplFPProvisioning);
            INFO("secret key length : %d", aaplFPProvisioning->fairPlaySecretLength);

            if (NULL != aaplFPProvisioning->fairPlaySecret) {
               free(aaplFPProvisioning->fairPlaySecret);
               aaplFPProvisioning->fairPlaySecret = NULL;
            }
            if (NULL != aaplFPProvisioning) {
               free(aaplFPProvisioning);
               aaplFPProvisioning = NULL;
            }
         }
         break;
      default:
         ERROR("unknown key provisioning type");
         break;
  }


  return status;
}

