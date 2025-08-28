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

#include "client_store.h"
#include "common.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "porting/memory.h"
#include "rights.h"
#include "soc_key_container.h"
#include "ta_sa.h"


sa_status ta_sa_key_provision_widevine(
    const void* in,
    const void* parameters,
    client_t* client,
    const sa_uuid* caller_uuid) {

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }
      
    sa_status status = SA_STATUS_OK;
    stored_key_t* stored_key = NULL;

    /* TODO SoC Vendor:
     * Parse the FKPS key container.
     * Authenticate the SoC key container.
     * Obtain the clear provisioning key(s).
     * Check that the entitled TAs allowed to use the key match the TA which the keys are being provided to.
     * Provide/write the provisioning key(s) to the corresponding TA.
     */
    const void* encryptKey = ((WidevineOemProvisioning*)in)->oemDevicePrivateKey;
    const size_t encryptKeyLen  = ((WidevineOemProvisioning*)in)->oemDevicePrivateKeyLength;
	      
    do {
        /* The code provided here is only for demo purposes and does not provide a complete
         * provisioning implementation.
         * This code just provides an example to get an stored key,
         * it contains decrypted key which is stored_key->key,stored_key->key_length,
         * and other attributes.
         */
         status = soc_kc_unwrap(&stored_key, encryptKey, encryptKeyLen, (void*)parameters);
         if (status != SA_STATUS_OK) {
             ERROR("soc_kc_unwrap failed");
             break;
         }
    } while(false);
    stored_key_free(stored_key);

    /* TODO SoC Vendor:here just provide an example to get certificate data,
     * how to use it is all up to SOC vendor.
     */
    {
        void *oemDeviceCertificate =
             ((WidevineOemProvisioning*)in)->oemDeviceCertificate;
        size_t oemDeviceCertificateLength =
             ((WidevineOemProvisioning*)in)->oemDeviceCertificateLength;
        INFO("oemDeviceCertificate:0x%x, oemDeviceCertificateLength:%d",
             oemDeviceCertificate, oemDeviceCertificateLength);
    }

    return status;
}

sa_status ta_sa_key_provision_playready(
    const void* in,
    const void* parameters,
    client_t* client,
    const sa_uuid* caller_uuid) {

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_OK;
    stored_key_t* stored_key = NULL;

    /* TODO SoC Vendor:
     * Parse the FKPS key container.
     * Authenticate the SoC key container.
     * Obtain the clear provisioning key(s).
     * Check that the entitled TAs allowed to use the key match the TA which the keys are being provided to.
     * Provide/write the provisioning key(s) to the corresponding TA.
     */
    const void *encryptKey = ((PlayReadyProvisioning*)in)->privateKey;
    const size_t encryptKeyLen  = ((PlayReadyProvisioning*)in)->privateKeyLength;

    do {
        /* The code provided here is only for demo purposes and does not provide a complete
         * provisioning implementation.
         * This code just provides an example to get an stored key,
         * it contains decrypted key which is stored_key->key,stored_key->key_length,
         * and other attributes.
         */
         status = soc_kc_unwrap(&stored_key, encryptKey, encryptKeyLen, (void*)parameters);
         if (status != SA_STATUS_OK) {
             ERROR("soc_kc_unwrap failed");
             break;
         }
    } while(false);
    stored_key_free(stored_key);

    /* TODO SoC Vendor:here just provide an example to get certificate data
     * and model type. How to use them is all up to SOC vendor.
     */
    {
        void *modelCertificate =
             ((PlayReadyProvisioning*)in)->modelCertificate;
        size_t modelCertificateLength =
             ((PlayReadyProvisioning*)in)->modelCertificateLength;
        INFO("modelCertificate:0x%x, modelCertificateLength:%d",
             modelCertificate, modelCertificateLength);
        INFO("Model type : %s",
             (((PlayReadyProvisioning*)in)->modelType == PLAYREADY_MODEL_2K)?
             "model 2000" :
             ((((PlayReadyProvisioning*)in)->modelType == PLAYREADY_MODEL_3K)?
             "model 3000":
             "No such model type"));
    }
    
    return status;      
}

sa_status ta_sa_key_provision_netflix(
    const void* in,
    const void* parameters,
    client_t* client,
    const sa_uuid* caller_uuid) {
    
    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }
 
    sa_status status = SA_STATUS_OK;
    stored_key_t* stored_key = NULL;

    /* TODO SoC Vendor:
     * Parse the FKPS key container.
     * Authenticate the SoC key container.
     * Obtain the clear provisioning key(s).
     * Check that the entitled TAs allowed to use the key match the TA which the keys are being provided to.
     * Provide/write the provisioning key(s) to the corresponding TA.
     */
    const void   *encryptionKey = ((NetflixProvisioning*)in)->encryptionKey;
    const size_t encryptionKeyLen = ((NetflixProvisioning*)in)->encryptionKeyLength;
    const void*  hmac = ((NetflixProvisioning*)in)->hmacKey;
    const size_t hmacLen = ((NetflixProvisioning*)in)->hmacKeyLength;
    const void*  wrappingKey = ((NetflixProvisioning*)in)->wrappingKey;
    const size_t wrappingKeyLen = ((NetflixProvisioning*)in)->wrappingKeyLength;
    INFO("encryptionKey:0x%x, encryptionKeyLen:%d",
          encryptionKey, encryptionKeyLen);
    INFO("hmac:0x%x, hmacLen:%d",
          hmac, hmacLen);
    INFO("wrappingKey:0x%x, wrappingKeyLen:%d",
          wrappingKey, wrappingKeyLen);

    do {
        /* The code provided here is only for demo purposes and does not provide a complete
         * provisioning implementation.
         * This code just provides an example to get an stored key,
         * it contains decrypted key which is stored_key->key,stored_key->key_length,
         * and other attributes.
         */
         status = soc_kc_unwrap(&stored_key, encryptionKey, encryptionKeyLen, (void*)parameters);
         if (status != SA_STATUS_OK) {
             ERROR("soc_kc_unwrap failed");
             break;
         }
    } while(false);
    stored_key_free(stored_key);

    /* TODO SoC Vendor:here just provide an example to pass ESN data,
     * how to use it is all up to SOC vendor.
     */
    {
        void *esn = ((NetflixProvisioning*)in)->esnContainer;
        size_t esnLength = ((NetflixProvisioning*)in)->esnContainerLength;
        INFO("esn:0x%x, esnLength:%d", esn, esnLength);
    }
    
    return status;      
}

sa_status ta_sa_key_provision(
    sa_key_type_ta ta_key_type,
    const void* in,
    const size_t in_length,
    const void* parameters,
    ta_client client_slot,
    const sa_uuid* caller_uuid) {

    if (in == NULL || in_length == 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length <= 0) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_OK;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
	 	
    do {
       status = client_store_acquire(&client, client_store, client_slot, caller_uuid); 
       if (status != SA_STATUS_OK) {
           ERROR("client_store_acquire failed");
           break;
       }

       switch(ta_key_type) {
           case WIDEVINE_OEM_PROVISIONING:
                status = ta_sa_key_provision_widevine(in, parameters, client, caller_uuid);
                break;
           case PLAYREADY_MODEL_PROVISIONING:
                status = ta_sa_key_provision_playready(in, parameters, client, caller_uuid);
                break;
           case NETFLIX_PROVISIONING:
                status = ta_sa_key_provision_netflix(in, parameters, client, caller_uuid);
                break;
           default:
                ERROR("unknown key provisioning type");
                break;
	}
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
