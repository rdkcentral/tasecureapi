/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

/*Note: turn on this if you want to read data from files*/
#define FILE_BASED_FETCH_KEY

#ifdef FILE_BASED_FETCH_KEY
static AppleMfiProvisioning* createAppleMfiblob(FILE *file_base_key,
   FILE *file_provisioning_object);
static bool readAppleMfiData(AppleMfiProvisioning **appleMfiProvision);
#endif //FILE_BASED_FETCH_KEY
namespace {
   static std::shared_ptr<std::vector<uint8_t>> export_key(
        std::vector<uint8_t>& mixin,
        sa_key key);
}

namespace {
    TEST_P(SaKeyProvisionAppleMfiTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto base_key_length = std::get<1>(GetParam());
        auto provisioning_object_length = std::get<1>(GetParam());

        std::vector<uint8_t> clear_base_key;
        sa_elliptic_curve curve;
        auto imported_base_key = create_sa_key(key_type, base_key_length,clear_base_key,curve);
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported base key
        std::vector<uint8_t> mixin = {};
        auto exported_base_key = export_key(mixin, *imported_base_key);
        ASSERT_NE(nullptr, exported_base_key);
        INFO("export_base_key length : %d", exported_base_key->size());

        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = exported_base_key->data();
        appleMfiProvision->mfiBaseKeyLength = exported_base_key->size();

        std::vector<uint8_t> clear_provision_object;
        auto imported_provision_object = create_sa_key(key_type, provisioning_object_length,
             clear_provision_object,curve);
        ASSERT_NE(nullptr, imported_provision_object);
        if(UNSUPPORTED_KEY == *imported_provision_object) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported provision object 
        //std::vector<uint8_t> mixin = {};
        auto exported_provision_object = export_key(mixin, *imported_provision_object);
        ASSERT_NE(nullptr, exported_provision_object);
        INFO("exported_provision_object length : %d", exported_provision_object->size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = exported_provision_object->data();
        appleMfiProvision->mfiProvisioningObjectLength = exported_provision_object->size();

        sa_status status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           sizeof(AppleMfiProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
    }

    TEST_P(SaKeyProvisionAppleMfiTest, nominalWithMixin) {
        auto key_type = std::get<0>(GetParam());
        auto base_key_length = std::get<1>(GetParam());
        auto provisioning_object_length = std::get<1>(GetParam());

        std::vector<uint8_t> clear_base_key;
        sa_elliptic_curve curve;
        auto imported_base_key = create_sa_key(key_type, base_key_length,clear_base_key,curve);
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported base key
        std::vector<uint8_t> mixin = random(AES_BLOCK_SIZE); 
        auto exported_base_key = export_key(mixin, *imported_base_key);
        ASSERT_NE(nullptr, exported_base_key);
        INFO("export_base_key length : %d", exported_base_key->size());

        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = exported_base_key->data();
        appleMfiProvision->mfiBaseKeyLength = exported_base_key->size();

        std::vector<uint8_t> clear_provision_object;
        auto imported_provision_object = create_sa_key(key_type, provisioning_object_length,
             clear_provision_object,curve);
        ASSERT_NE(nullptr, imported_provision_object);
        if(UNSUPPORTED_KEY == *imported_provision_object) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported provision object 
        auto exported_provision_object = export_key(mixin, *imported_provision_object);
        ASSERT_NE(nullptr, exported_provision_object);
        INFO("exported_provision_object length : %d", exported_provision_object->size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = exported_provision_object->data();
        appleMfiProvision->mfiProvisioningObjectLength = exported_provision_object->size();

        sa_status status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           sizeof(AppleMfiProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleMfiTest, simpleCheck) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_base_key(SYM_128_KEY_SIZE);
        auto imported_base_key = create_sa_key_symmetric(&rights, clear_base_key); 
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported base key
        std::vector<uint8_t> mixin = {};
        auto exported_base_key = export_key(mixin, *imported_base_key);
        ASSERT_NE(nullptr, exported_base_key);
        INFO("export_base_key length : %d", exported_base_key->size());

        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = exported_base_key->data();
        appleMfiProvision->mfiBaseKeyLength = exported_base_key->size();

        std::vector<uint8_t> clear_provision_object(SYM_128_KEY_SIZE);
        auto imported_provision_object = create_sa_key_symmetric(&rights, 
             clear_provision_object);
        ASSERT_NE(nullptr, imported_provision_object);
        if(UNSUPPORTED_KEY == *imported_provision_object) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported provision object 
        //std::vector<uint8_t> mixin = {};
        auto exported_provision_object = export_key(mixin, *imported_provision_object);
        ASSERT_NE(nullptr, exported_provision_object);
        INFO("exported_provision_object length : %d", exported_provision_object->size());
        //write_to_storage(exported_provision_object->data(),exported_provision_object->size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = exported_provision_object->data();
        appleMfiProvision->mfiProvisioningObjectLength = exported_provision_object->size();

        sa_status status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           sizeof(AppleMfiProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleMfiTest, failsZeroInLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_base_key(SYM_128_KEY_SIZE);
        auto imported_base_key = create_sa_key_symmetric(&rights, clear_base_key); 
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported base key
        std::vector<uint8_t> mixin = {};
        auto exported_base_key = export_key(mixin, *imported_base_key);
        ASSERT_NE(nullptr, exported_base_key);
        INFO("export_base_key length : %d", exported_base_key->size());

        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = exported_base_key->data();
        appleMfiProvision->mfiBaseKeyLength = exported_base_key->size();

        std::vector<uint8_t> clear_provision_object(SYM_128_KEY_SIZE);
        auto imported_provision_object = create_sa_key_symmetric(&rights, 
             clear_provision_object);
        ASSERT_NE(nullptr, imported_provision_object);
        if(UNSUPPORTED_KEY == *imported_provision_object) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported provision object 
        //std::vector<uint8_t> mixin = {};
        auto exported_provision_object = export_key(mixin, *imported_provision_object);
        ASSERT_NE(nullptr, exported_provision_object);
        INFO("exported_provision_object length : %d", exported_provision_object->size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = exported_provision_object->data();
        appleMfiProvision->mfiProvisioningObjectLength = exported_provision_object->size();

        sa_status status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, appleMfiProvision,
           0, nullptr);

        if(nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
    TEST_F(SaKeyProvisionAppleMfiTest, failsNoCacheableFlag) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE);

        std::vector<uint8_t> clear_base_key(SYM_128_KEY_SIZE);
        auto imported_base_key = create_sa_key_symmetric(&rights, clear_base_key); 
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported base key
        size_t out_length = 0;
        INFO("out_length : %d", out_length);
        sa_status status = sa_key_export(nullptr, &out_length,nullptr,0,*imported_base_key);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
    TEST_F(SaKeyProvisionAppleMfiTest, failNullProvision) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_base_key(SYM_128_KEY_SIZE);
        auto imported_base_key = create_sa_key_symmetric(&rights, clear_base_key); 
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported base key
        std::vector<uint8_t> mixin = {};
        auto exported_base_key = export_key(mixin, *imported_base_key);
        ASSERT_NE(nullptr, exported_base_key);
        INFO("export_base_key length : %d", exported_base_key->size());
        //write_to_storage(exported_base_key->data(),exported_base_key->size());

        //Note: here just provide an examlpe to create base key and passed
        //into sa_key_provision_ta, how to use base key is all up to
        //SOC vendors.
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        appleMfiProvision->mfiBaseKey = exported_base_key->data();
        appleMfiProvision->mfiBaseKeyLength = exported_base_key->size();

        std::vector<uint8_t> clear_provision_object(SYM_128_KEY_SIZE);
        auto imported_provision_object = create_sa_key_symmetric(&rights, 
             clear_provision_object);
        ASSERT_NE(nullptr, imported_provision_object);
        if(UNSUPPORTED_KEY == *imported_provision_object) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported provision object 
        //std::vector<uint8_t> mixin = {};
        auto exported_provision_object = export_key(mixin, *imported_provision_object);
        ASSERT_NE(nullptr, exported_provision_object);
        INFO("exported_provision_object length : %d", exported_provision_object->size());
        //write_to_storage(exported_provision_object->data(),exported_provision_object->size());

        //Note: here just provide an examlpe to create provision object and passed
        //into sa_key_provision_ta, how to use provision object data is all up to
        //SOC vendors.
        appleMfiProvision->mfiProvisioningObject = exported_provision_object->data();
        appleMfiProvision->mfiProvisioningObjectLength = exported_provision_object->size();

        sa_status status = sa_key_provision_ta(APPLE_MFI_PROVISIONING, nullptr,
           sizeof(AppleMfiProvisioning), nullptr);
        ASSERT_NE(status, SA_STATUS_OK);

        if(nullptr != appleMfiProvision) {
           delete appleMfiProvision;
           appleMfiProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleMfiTest, failsInvalidMixinLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_base_key(SYM_128_KEY_SIZE);
        auto imported_base_key = create_sa_key_symmetric(&rights, clear_base_key); 
        ASSERT_NE(nullptr, imported_base_key);
        if(UNSUPPORTED_KEY == *imported_base_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }
        auto mixin = random(17);
        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        sa_status status = sa_key_export(out.data(), &out_length, mixin.data(),
           mixin.size(),*imported_base_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER); 
    }

#ifdef FILE_BASED_FETCH_KEY
 /*there are two file 0391000003910001.key and 0691000006910001.bin under
   tasecureapi/reference/src/client/,
   these files are base key and provisioning object. you can do
   "export  apple_mfi_base_key=~/PATH/tasecureapi/reference/src/client/0391000003910001.key",
   "export  apple_mfi_provisioning_object=~/PATH/tasecureapi/reference/src/client/0691000006910001.bin",
   the following test checkAppleMfiPrivateKeyFromFileBased will pick up them and test
  Or
   you just simply copy these two files and put under /opt/drm/
  */
 TEST_F(SaKeyProvisionAppleMfiTest, fromFileBased) {
        AppleMfiProvisioning *appleMfiProvision = new AppleMfiProvisioning;
        ASSERT_NE(nullptr, appleMfiProvision);
        ASSERT_TRUE(readAppleMfiData(&appleMfiProvision));

        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, 
           appleMfiProvision, sizeof(appleMfiProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleMfiProvision->mfiBaseKey){
           free(appleMfiProvision->mfiBaseKey);
           appleMfiProvision->mfiBaseKey = nullptr;
        }
        if(nullptr != appleMfiProvision->mfiProvisioningObject){
           free(appleMfiProvision->mfiProvisioningObject);
           appleMfiProvision->mfiProvisioningObject = nullptr;
        }
    }
#endif //FILE_BASED_FETCH_KEY
    static std::shared_ptr<std::vector<uint8_t>> export_key(
        std::vector<uint8_t>& mixin,
        sa_key key) {
        size_t required_length = 0;

        if (SA_STATUS_OK !=
            sa_key_export(nullptr, &required_length,
            mixin.empty() ? nullptr : mixin.data(), mixin.size(), key)) {
            return nullptr;
        }

        std::shared_ptr<std::vector<uint8_t>> result(new std::vector<uint8_t>(required_length));
        if (SA_STATUS_OK !=
            sa_key_export(result->data(), &required_length,
            mixin.empty() ? nullptr : mixin.data(), mixin.size(),key)) {
            return nullptr;
        }

        return result;
    }
} // namespace

#ifdef FILE_BASED_FETCH_KEY
#include <sys/stat.h>
#include <string.h>

#define apple_mfi_base_key              "/opt/drm/0391000003910001.key"
#define apple_mfi_provisioning_object   "/opt/drm/0691000006910001.bin"

static void* readBlob(FILE *fp, size_t *key_size) {
   if(NULL == fp) {
      ERROR("file pointer do not exist");
      return NULL;
   }
   if(0 != fseek(fp,0L,SEEK_END)) {
      ERROR("failed to seek end");
      return NULL;
   }
   *key_size = ftell(fp);
   void *key = calloc(*key_size, 1);
   if (NULL == key) {
       ERROR("OOM");
       return NULL;
   }
   if(0 != fseek(fp, 0L,SEEK_SET)) {
     ERROR("Failed to seek to the beginning");
     return NULL;
   }
   size_t keySize = fread(key, 1,*key_size,fp);
   if(keySize != *key_size ||
      keySize  < *key_size) {
      ERROR("%d, %d", keySize, key_size);
      ERROR("this file has problem");
      return NULL;
   }

   return key;
}

static AppleMfiProvisioning* createAppleMfiblob(FILE *file_base_key, FILE *file_provisioning_object) {
   if(NULL == file_base_key ||
      NULL == file_provisioning_object) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t base_key_size = 0;
   void *base_key = readBlob(file_base_key, &base_key_size);
   if(NULL == base_key) {
      ERROR("this file :%s has problem", apple_mfi_base_key);
      return NULL;
   }
   INFO("base_key_size: %d", base_key_size);

   size_t provisioning_object_size = 0;
   void *provisioning_object = readBlob(file_provisioning_object, &provisioning_object_size);
   if(NULL == provisioning_object) {
      ERROR("this file :%s has problem", apple_mfi_provisioning_object);
      return NULL;
   }
   INFO("provisioning_object_size: %d", provisioning_object_size);

   AppleMfiProvisioning *appleMfiProvision =
       (AppleMfiProvisioning*)calloc(sizeof(AppleMfiProvisioning), 1);
   if(NULL == appleMfiProvision) {
      ERROR("OOM");
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
   const char* file_base_key_name = getenv("aaple_mfi_base_key");
   const char* file_provisioning_object_name = 
      getenv("apple_mfi_provisioning_object");

   INFO("file_base_key_name:%s", file_base_key_name);
   INFO("file_provisioning_object:%s", file_provisioning_object);
   if (file_base_key_name == NULL) {
        file_base_key_name = apple_mfi_base_key;
        if(0 != access(file_base_key_name, F_OK)) {
           ERROR("File does not exist: %s",file_base_key_name);
           return false;
        }
   }

   if (file_provisioning_object_name == NULL) {
        file_provisioning_object_name = apple_mfi_provisioning_object;
        if(0 != access(file_provisioning_object_name, F_OK)) {
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

   if(file_base_key)
      fclose(file_base_key);
   if(file_provisioning_object)
      fclose(file_provisioning_object);

   if(NULL == *appleMfiProvision) {
      ERROR("failed to get appleMfiProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
