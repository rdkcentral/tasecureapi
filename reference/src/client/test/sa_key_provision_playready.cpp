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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_key.h"
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

#define CERTIFICATION_LENGTH 4096

//Note: turn on this if you want to read data from files
//#define FILE_BASED_FETCH_KEY

#ifdef FILE_BASED_FETCH_KEY
static PlayReadyProvisioning* createPlayreadyblob(FILE *file_private_key,
   FILE *file_oem_cert);
static bool readPlayreadyData(PlayReadyProvisioning **prProvision);
#endif //FILE_BASED_FETCH_KEY

namespace {
    TEST_P(SaKeyProvisionPlayreadyTest, nominal) {
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        auto key_length = std::get<0>(GetParam());
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        //create a rsa key container
        std::string rsa_key_type_string = std::get<1>(GetParam());;

        std::string rsa_key_container;
        sa_status status = create_key_container(
             rsa_key_type_string, //key type string
             rsa_key_type, //key type
             clear_rsa_key,
             rsa_key_container);

        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = (void*)rsa_key_container.data();
        prProvision->privateKeyLength = rsa_key_container.size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision,
           sizeof(PlayReadyProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionPlayreadyTest, simpleCheck) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        //create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";
        std::string rsa_key_container;
        sa_status status = create_key_container(
             rsa_key_type_string, //key type string
             rsa_key_type, //key type
             clear_rsa_key,
             rsa_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = (void*)rsa_key_container.data();
        prProvision->privateKeyLength = rsa_key_container.size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision,
          sizeof(PlayReadyProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionPlayreadyTest, failsNullProvision) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        //create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";

        std::string rsa_key_container;
        sa_status status = create_key_container(
             rsa_key_type_string, //key type string
             rsa_key_type, //key type
             clear_rsa_key,
             rsa_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = (void*)rsa_key_container.data();
        prProvision->privateKeyLength = rsa_key_container.size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, nullptr,
           sizeof(PlayReadyProvisioning), nullptr);

        if (nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
    TEST_F(SaKeyProvisionPlayreadyTest, failsZeroInLength) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        //create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";

        std::string rsa_key_container;
        sa_status status = create_key_container(
             rsa_key_type_string, //key type string
             rsa_key_type, //key type
             clear_rsa_key,
             rsa_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = (void*)rsa_key_container.data();
        prProvision->privateKeyLength = rsa_key_container.size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING,
           prProvision, 0, nullptr);
        if (nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
#ifdef FILE_BASED_FETCH_KEY
   //There are two file playready_private_key.key and playready_cert.bin under
   //tasecureapi/reference/src/client/,
   //these files are playready private key and certification. you can do
   //"export  playready_privatekey=
   //~/PATH/tasecureapi/reference/src/client/playready_private_key.key",
   //"export  playready_cert=~/PATH/tasecureapi/reference/src/client/playready_cert.bin",
   //the following test fromFileBased will pick up them and test
   //Or
   //you just simply copy these two files and put under /opt/drm/

 TEST_F(SaKeyProvisionPlayreadyTest, fromFileBased) {
     PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
     ASSERT_NE(nullptr, prProvision);
     ASSERT_TRUE(readPlayreadyData(&prProvision));

      sa_status status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING,
      prProvision, sizeof(prProvision), nullptr);
      ASSERT_EQ(status, SA_STATUS_OK);

      if (nullptr != prProvision->privateKey){
         free(prProvision->privateKey);
         prProvision->privateKey = nullptr;
      }
      if (nullptr != prProvision->modelCertificate){
         free(prProvision->modelCertificate);
         prProvision->modelCertificate = nullptr;
      }
    }
#endif //FILE_BASED_FETCH_KEY
} // namespace

#ifdef FILE_BASED_FETCH_KEY
#include <sys/stat.h>
#include <string.h>

#define playready_privatekey "/opt/drm/playready_private_key.key"
#define playready_cert       "/opt/drm/playready_cert.bin"

static void* readBlob(FILE *fp, size_t *key_size) {
   if (NULL == fp) {
      ERROR("file pointer do not exist");
      return NULL;
   }
   if (0 != fseek(fp,0L,SEEK_END)) {
      ERROR("failed to seek end");
      return NULL;
   }
   *key_size = ftell(fp);
   void *key = calloc(*key_size, 1);
   if (NULL == key) {
       ERROR("calloc failed");
       return NULL;
   }
   if (0 != fseek(fp, 0L,SEEK_SET)) {
     ERROR("Failed to seek to the beginning");
     return NULL;
   }
   size_t keySize = fread(key, 1,*key_size,fp);
   if (keySize != *key_size ||
      keySize  < *key_size) {
      ERROR("%d, %d", keySize, key_size);
      ERROR("this file has problem");
      return NULL;
   }

   return key;
}

static PlayReadyProvisioning* createPlayreadyblob(FILE *file_private_key,
   FILE *file_oem_cert) {
   if (NULL == file_private_key ||
      NULL == file_oem_cert) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t private_key_size = 0;
   void *private_key = readBlob(file_private_key, &private_key_size);
   if (NULL == private_key) {
      ERROR("this file :%s has problem", playready_privatekey);
      return NULL;
   }
   INFO("private_key_size: %d",private_key_size);

   size_t oem_cert_size = 0;
   void *oem_cert = readBlob(file_oem_cert, &oem_cert_size);
   if (NULL == oem_cert) {
      ERROR("this file :%s has problem", playready_privatekey);
      return NULL;
   }
   INFO("oem_cert_size: %d",oem_cert_size);

   PlayReadyProvisioning *prProvision =
       (PlayReadyProvisioning*)calloc(sizeof(PlayReadyProvisioning), 1);
   if (NULL == prProvision) {
      ERROR("calloc failed");
      return NULL;
   }

   prProvision->privateKey = private_key;
   prProvision->privateKeyLength = private_key_size;
   prProvision->modelCertificate = oem_cert;
   prProvision->modelCertificateLength = oem_cert_size;

   INFO("keyLen : %d", prProvision->privateKeyLength);
   INFO("certLen : %d", prProvision->modelCertificateLength);

   return prProvision;
}

static bool readPlayreadyData(PlayReadyProvisioning **prProvision) {
   FILE* file_private_key = NULL;
   FILE* file_oem_cert = NULL;
   const char* file_private_key_name = getenv("playready_privatekey");
   const char* file_cert_name = getenv("playready_cert");

   INFO("file_private_key_name:%s", file_private_key_name);
   INFO("file_cert_name:%s", file_cert_name);
   if (file_private_key_name == NULL) {
      file_private_key_name = playready_privatekey;
      if (0 != access(file_private_key_name, F_OK)) {
         ERROR("File does not exist: %s",file_private_key_name);
         return false;
      }
   }

   if (file_cert_name == NULL) {
      file_cert_name = playready_cert;
      if (0 != access(file_cert_name, F_OK)) {
          ERROR("File does not exist: %s",file_cert_name);
          return false;
      }
   }

   file_private_key = fopen(file_private_key_name, "rbe");
   if (NULL == file_private_key) {
       ERROR("file :%s does not exist", file_private_key_name);
       return false;
   }

   file_oem_cert = fopen(file_cert_name, "rbe");
   if (NULL == file_oem_cert) {
       ERROR("file :%s does not exist", file_cert_name);
       return false;
   }

   *prProvision = createPlayreadyblob(file_private_key, file_oem_cert);

   if (file_private_key)
      fclose(file_private_key);
   if (file_oem_cert)
      fclose(file_oem_cert);

   if (NULL == *prProvision) {
       ERROR("failed to get prProvision data");
       return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
