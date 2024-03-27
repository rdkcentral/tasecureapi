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

//Note: turn on this if you want to read data from files
//#define FILE_BASED_FETCH_KEY
#ifdef FILE_BASED_FETCH_KEY
static AppleMfiProvisioning* createAppleMfiblob(FILE *file_base_key,
   FILE *file_provisioning_object);
static bool readAppleMfiData(AppleMfiProvisioning **appleMfiProvision);
#endif //FILE_BASED_FETCH_KEY

namespace {
    TEST_P(SaKeyProvisionAppleMfiTest, nominal) {
        auto key_length = std::get<0>(GetParam());
        std::string key_string_type = std::get<1>(GetParam());
        std::vector<uint8_t> clear_base_key = random(key_length);

        //create a base key container
        auto base_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string base_key_type_string = key_string_type;

        std::string base_key_container;
        sa_status status = create_key_container(
             base_key_type_string, //key type string
             base_key_type, //key type
             clear_base_key,
             base_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("base_key_container length : %d", base_key_container.size());

        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = (void*)base_key_container.data();
        appleMfiProvision->mfiBaseKeyLength = base_key_container.size();

        //create a provision object container
        auto pb_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string pb_key_type_string = key_string_type;
        std::vector<uint8_t> clear_provision_object = random(key_length);
        std::string pb_key_container;
        status = create_key_container(
             pb_key_type_string, //key type string
             pb_key_type, //key type
             clear_provision_object,
             pb_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("pb_key_container length : %d", pb_key_container.size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = (void*)pb_key_container.data();
        appleMfiProvision->mfiProvisioningObjectLength = pb_key_container.size();

        status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           sizeof(AppleMfiProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleMfiTest, simpleCheck) {
        auto key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_base_key = random(key_length);

        //create a base key container
        auto base_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string base_key_type_string = "AES-128";
        std::string base_key_container;
        sa_status status = create_key_container(
             base_key_type_string, //key type string
             base_key_type, //key type
             clear_base_key,
             base_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("base_key_container length : %d", base_key_container.size());
        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = (void*)base_key_container.data();
        appleMfiProvision->mfiBaseKeyLength = base_key_container.size();


        //create a provisioning object container
        auto pb_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string pb_key_type_string = "AES-128";
        std::vector<uint8_t> clear_provision_object = random(key_length);
        std::string pb_key_container;
        status = create_key_container(
             pb_key_type_string, //key type string
             pb_key_type, //key type
             clear_provision_object,
             pb_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("pb_key_container length : %d", pb_key_container.size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = (void*)pb_key_container.data();
        appleMfiProvision->mfiProvisioningObjectLength = pb_key_container.size();

        status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           sizeof(AppleMfiProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleMfiTest, failsZeroInLength) {
        auto key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_base_key = random(key_length);

        //create a base key container
        auto base_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string base_key_type_string = "AES-128";
        std::string base_key_container;
        sa_status status = create_key_container(
             base_key_type_string, //key type string
             base_key_type, //key type
             clear_base_key,
             base_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("base_key_container length : %d", base_key_container.size());
        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = (void*)base_key_container.data();
        appleMfiProvision->mfiBaseKeyLength = base_key_container.size();


        //create a provisioning object container
        auto pb_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string pb_key_type_string = "AES-128";
        std::vector<uint8_t> clear_provision_object = random(key_length);
        std::string pb_key_container;
        status = create_key_container(
             pb_key_type_string, //key type string
             pb_key_type, //key type
             clear_provision_object,
             pb_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("pb_key_container length : %d", pb_key_container.size());
        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = (void*)pb_key_container.data();
        appleMfiProvision->mfiProvisioningObjectLength = pb_key_container.size();

        status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           0, nullptr);

        if (nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
    TEST_F(SaKeyProvisionAppleMfiTest, failNullProvision) {
        auto key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_base_key = random(key_length);

        //create a base key container
        auto base_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string base_key_type_string = "AES-128";
        std::string base_key_container;
        sa_status status = create_key_container(
             base_key_type_string, //key type string
             base_key_type, //key type
             clear_base_key,
             base_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("base_key_container length : %d", base_key_container.size());
        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = (void*)base_key_container.data();
        appleMfiProvision->mfiBaseKeyLength = base_key_container.size();


        //create a provisioning object container
        std::vector<uint8_t> clear_provision_object = random(key_length);
        auto pb_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string pb_key_type_string = "AES-128";
        std::string pb_key_container;
        status = create_key_container(
             pb_key_type_string, //key type string
             pb_key_type, //key type
             clear_provision_object,
             pb_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("pb_key_container length : %d", pb_key_container.size());
        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = (void*)pb_key_container.data();
        appleMfiProvision->mfiProvisioningObjectLength = pb_key_container.size();

        status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, nullptr,
           sizeof(AppleMfiProvisioning), nullptr);

        if (nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
#ifdef FILE_BASED_FETCH_KEY
    //There are two file apple_mfi_base_key.key and apple_mfi_provisioning_object.bin under
    //tasecureapi/reference/src/client/,
    //these files are base key and provisioning object. you can do
    //"export  apple_mfi_base_key=~/PATH/tasecureapi/reference/src/client/apple_mfi_base_key.key",
    //"export  apple_mfi_provisioning_object=
    //~/PATH/tasecureapi/reference/src/client/apple_mfi_provisioning_object.bin",
    //the following test checkAppleMfiPrivateKeyFromFileBased will pick up them and test
    //Or
    //you just simply copy these two files and put under /opt/drm/
 TEST_F(SaKeyProvisionAppleMfiTest, fromFileBased) {
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        ASSERT_TRUE(readAppleMfiData(&appleMfiProvision));

        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, 
           appleMfiProvision, sizeof(appleMfiProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != appleMfiProvision->mfiBaseKey){
           free(appleMfiProvision->mfiBaseKey);
           appleMfiProvision->mfiBaseKey = nullptr;
        }
        if (nullptr != appleMfiProvision->mfiProvisioningObject){
           free(appleMfiProvision->mfiProvisioningObject);
           appleMfiProvision->mfiProvisioningObject = nullptr;
        }
    }
#endif //FILE_BASED_FETCH_KEY
} // namespace

#ifdef FILE_BASED_FETCH_KEY
#include <sys/stat.h>
#include <string.h>

#define apple_mfi_base_key              "/opt/drm/apple_mfi_base_key.key"
#define apple_mfi_provisioning_object   "/opt/drm/apple_mfi_provisioning_object.bin"

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

static AppleMfiProvisioning* createAppleMfiblob(FILE *file_base_key,
   FILE *file_provisioning_object) {
   if (NULL == file_base_key ||
      NULL == file_provisioning_object) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t base_key_size = 0;
   void *base_key = readBlob(file_base_key, &base_key_size);
   if (NULL == base_key) {
      ERROR("this file :%s has problem", apple_mfi_base_key);
      return NULL;
   }
   INFO("base_key_size: %d", base_key_size);

   size_t provisioning_object_size = 0;
   void *provisioning_object = readBlob(file_provisioning_object, &provisioning_object_size);
   if (NULL == provisioning_object) {
      ERROR("this file :%s has problem", apple_mfi_provisioning_object);
      return NULL;
   }
   INFO("provisioning_object_size: %d", provisioning_object_size);

   AppleMfiProvisioning *appleMfiProvision =
       (AppleMfiProvisioning*)calloc(sizeof(AppleMfiProvisioning), 1);
   if (NULL == appleMfiProvision) {
      ERROR("calloc failed");
      return NULL;
   }
  
   appleMfiProvision->mfiBaseKey = base_key;
   appleMfiProvision->mfiBaseKeyLength = base_key_size;
   appleMfiProvision->mfiProvisioningObject = provisioning_object;
   appleMfiProvision->mfiProvisioningObjectLength = provisioning_object_size;

   INFO("keyLen : %d", appleMfiProvision->mfiBaseKeyLength);
   INFO("certLen : %d", appleMfiProvision->mfiProvisioningObjectLength);

   return appleMfiProvision;
}

static bool readAppleMfiData(AppleMfiProvisioning **appleMfiProvision) {
   FILE* file_base_key = NULL;
   FILE* file_provisioning_object = NULL;
   const char* file_base_key_name = getenv("apple_mfi_base_key");
   const char* file_provisioning_object_name = 
      getenv("apple_mfi_provisioning_object");

   INFO("file_base_key_name:%s", file_base_key_name);
   INFO("file_provisioning_object:%s", file_provisioning_object);
   if (file_base_key_name == NULL) {
      file_base_key_name = apple_mfi_base_key;
      if (0 != access(file_base_key_name, F_OK)) {
         ERROR("File does not exist: %s",file_base_key_name);
         return false;
      }
   }

   if (file_provisioning_object_name == NULL) {
      file_provisioning_object_name = apple_mfi_provisioning_object;
      if (0 != access(file_provisioning_object_name, F_OK)) {
         ERROR("File does not exist: %s",file_provisioning_object_name);
         return false;
      }
   }

   file_base_key = fopen(file_base_key_name, "rbe");
   if (NULL == file_base_key) {
       ERROR("file :%s does not exist", file_base_key_name);
       return false;
   }

   file_provisioning_object = fopen(file_provisioning_object_name, "rbe");
   if (NULL == file_provisioning_object) {
       ERROR("file :%s does not exist", file_provisioning_object_name);
       return false;
   }

   *appleMfiProvision = createAppleMfiblob(file_base_key, file_provisioning_object);

   if (file_base_key)
      fclose(file_base_key);
   if (file_provisioning_object)
      fclose(file_provisioning_object);

   if (NULL == *appleMfiProvision) {
      ERROR("failed to get appleMfiProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
