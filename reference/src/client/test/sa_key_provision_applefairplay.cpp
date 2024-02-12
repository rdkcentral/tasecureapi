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
static AppleFairPlayProvisioning* createAppleFairplayblob(FILE *file_fairplay_secret);
static bool readAppleFairplayData(AppleFairPlayProvisioning **appleFPProvision);
#endif //FILE_BASED_FETCH_KEY
namespace {
   static std::shared_ptr<std::vector<uint8_t>> export_key(
        std::vector<uint8_t>& mixin,
        sa_key key);
}

namespace {
    TEST_P(SaKeyProvisionAppleFairplayTest, nominal) {
        auto secret_key_type = std::get<0>(GetParam());
        auto secret_key_length = std::get<1>(GetParam());

        std::vector<uint8_t> clear_secret_key;
        sa_elliptic_curve curve;
        auto imported_secret_key = create_sa_key(secret_key_type, secret_key_length,
           clear_secret_key,curve);
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        std::vector<uint8_t> mixin = {};
        auto exported_secret_key = export_key(mixin, *imported_secret_key);
        ASSERT_NE(nullptr, exported_secret_key);
        INFO("export_secret_key length : %d", exported_secret_key->size());

        AppleFairPlayProvisioning *appleFPProvision = new AppleFairPlayProvisioning;
        ASSERT_NE(nullptr, appleFPProvision);
        //Note: here just provide an examlpe to create a secret key and passed
        //into sa_key_provision_ta, how to use it is all up to SOC vendors.
        appleFPProvision->fairPlaySecret = exported_secret_key->data();
        appleFPProvision->fairPlaySecretLength = exported_secret_key->size();

        sa_status status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, 
           appleFPProvision, sizeof(AppleFairPlayProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleFPProvision) {
           delete appleFPProvision;
           appleFPProvision = nullptr;
        }
    }

    TEST_P(SaKeyProvisionAppleFairplayTest, nominalWithMixin) {
        auto secret_key_type = std::get<0>(GetParam());
        auto secret_key_length = std::get<1>(GetParam());

        std::vector<uint8_t> clear_secret_key;
        sa_elliptic_curve curve;
        auto imported_secret_key = create_sa_key(secret_key_type, secret_key_length,
           clear_secret_key,curve);
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        std::vector<uint8_t> mixin = random(AES_BLOCK_SIZE);
        auto exported_secret_key = export_key(mixin, *imported_secret_key);
        ASSERT_NE(nullptr, exported_secret_key);
        INFO("export_secret_key length : %d", exported_secret_key->size());

        AppleFairPlayProvisioning *appleFPProvision = new AppleFairPlayProvisioning;
        ASSERT_NE(nullptr, appleFPProvision);
        //Note: here just provide an examlpe to create a secret key and passed
        //into sa_key_provision_ta, how to use it is all up to SOC vendors.
        appleFPProvision->fairPlaySecret = exported_secret_key->data();
        appleFPProvision->fairPlaySecretLength = exported_secret_key->size();

        sa_status status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, 
           appleFPProvision, sizeof(AppleFairPlayProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleFPProvision) {
           delete appleFPProvision;
           appleFPProvision = nullptr;
        }
    }

    
    TEST_F(SaKeyProvisionAppleFairplayTest, simpleCheck) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_secret_key(SYM_128_KEY_SIZE);;
        auto imported_secret_key = create_sa_key_symmetric(&rights, clear_secret_key); 
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        std::vector<uint8_t> mixin = {};
        auto exported_secret_key = export_key(mixin, *imported_secret_key);
        ASSERT_NE(nullptr, exported_secret_key);
        INFO("export_secret_key length : %d", exported_secret_key->size());

        AppleFairPlayProvisioning *appleFPProvision = new AppleFairPlayProvisioning;
        ASSERT_NE(nullptr, appleFPProvision);
        //Note: here just provide an examlpe to create a secret key and passed
        //into sa_key_provision_ta, how to use it is all up to SOC vendors.
        appleFPProvision->fairPlaySecret = exported_secret_key->data();
        appleFPProvision->fairPlaySecretLength = exported_secret_key->size();

        sa_status status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, appleFPProvision, 
          sizeof(AppleFairPlayProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleFPProvision) {
           delete appleFPProvision;
           appleFPProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleFairplayTest, failsZeroInLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_secret_key(SYM_128_KEY_SIZE);;
        auto imported_secret_key = create_sa_key_symmetric(&rights, clear_secret_key); 
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        std::vector<uint8_t> mixin = {};
        auto exported_secret_key = export_key(mixin, *imported_secret_key);
        ASSERT_NE(nullptr, exported_secret_key);
        INFO("export_key length : %d", exported_secret_key->size());

        AppleFairPlayProvisioning *appleFPProvision = new AppleFairPlayProvisioning;
        ASSERT_NE(nullptr, appleFPProvision);
        appleFPProvision->fairPlaySecret = exported_secret_key->data();
        appleFPProvision->fairPlaySecretLength = exported_secret_key->size();

        sa_status status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, appleFPProvision, 0, nullptr);
        if(nullptr != appleFPProvision) {
           delete appleFPProvision;
           appleFPProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
    TEST_F(SaKeyProvisionAppleFairplayTest, failsNoCacheableFlag) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE);

        std::vector<uint8_t> clear_secret_key(SYM_128_KEY_SIZE);;
        auto imported_secret_key = create_sa_key_symmetric(&rights, clear_secret_key); 
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        size_t out_length = 0;
        INFO("out_length : %d", out_length);
        sa_status status = sa_key_export(nullptr, &out_length,nullptr,0,*imported_secret_key);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyProvisionAppleMfiTest, failNullProvision) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_secret_key(SYM_128_KEY_SIZE);;
        auto imported_secret_key = create_sa_key_symmetric(&rights, clear_secret_key); 
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        std::vector<uint8_t> mixin = {};
        auto exported_secret_key = export_key(mixin, *imported_secret_key);
        ASSERT_NE(nullptr, exported_secret_key);
        INFO("export_secret_key length : %d", exported_secret_key->size());

        AppleFairPlayProvisioning *appleFPProvision = new AppleFairPlayProvisioning;
        ASSERT_NE(nullptr, appleFPProvision);
        //Note: here just provide an examlpe to create a secret key and passed
        //into sa_key_provision_ta, how to use it is all up to SOC vendors.
        appleFPProvision->fairPlaySecret = exported_secret_key->data();
        appleFPProvision->fairPlaySecretLength = exported_secret_key->size();

        sa_status status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, nullptr, 
           sizeof(AppleFairPlayProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleFPProvision) {
           delete appleFPProvision;
           appleFPProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionAppleFairplayTest, failsInvalidMixinLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> clear_secret_key(SYM_128_KEY_SIZE);;
        auto imported_secret_key = create_sa_key_symmetric(&rights, clear_secret_key); 
        ASSERT_NE(nullptr, imported_secret_key);
        if(UNSUPPORTED_KEY == *imported_secret_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported secret key
        auto mixin = random(17);
        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        sa_status status = sa_key_export(out.data(), &out_length, mixin.data(),
           mixin.size(),*imported_secret_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    } 

#ifdef FILE_BASED_FETCH_KEY
 /*there is a file  0691000006910002.bin under tasecureapi/reference/src/client/,
   this file is a fairplay secret key. you can do
   "export  apple_fairplay_secret_key=~/PATH/tasecureapi/reference/src/client/0691000006910002.bin",
   the following test fromFileBased will pick up them and test
  Or
   you just simply copy these two files and put under /opt/drm/
  */
 TEST_F(SaKeyProvisionAppleFairplayTest, fromFileBased) {
        AppleFairPlayProvisioning *appleFPProvision = new AppleFairPlayProvisioning;
        ASSERT_NE(nullptr, appleFPProvision);
        ASSERT_TRUE(readAppleFairplayData(&appleFPProvision));

        sa_status status = sa_key_provision_ta(APPLE_FAIRPLAY_PROVISIONING, 
          appleFPProvision, sizeof(appleFPProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != appleFPProvision->fairPlaySecret){
           free(appleFPProvision->fairPlaySecret);
           appleFPProvision->fairPlaySecret = nullptr;
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

#define apple_fairplay_secret "/opt/drm/0691000006910002.bin"

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

static AppleFairPlayProvisioning* createAppleFairplayblob(FILE *file_fairplay_secret) {
   if(NULL == file_fairplay_secret) {
      ERROR("file pointer do not exist");
      return NULL;
   }
   
   size_t secret_key_size = 0;
   void *secret_key = readBlob(file_fairplay_secret, &secret_key_size);
   if(NULL == secret_key) {
      ERROR("this file :%s has problem", apple_fairplay_secret);
      return NULL;
   }
   INFO("secret_key_size: %d", secret_key_size);

   AppleFairPlayProvisioning *appleFPProvision =
       (AppleFairPlayProvisioning*)calloc(sizeof(AppleFairPlayProvisioning), 1);
   if(NULL == appleFPProvision) {
      ERROR("OOM");
      return NULL;
   }

   appleFPProvision->fairPlaySecret = secret_key;
   appleFPProvision->fairPlaySecretLength = secret_key_size;
   INFO("keyLen : %d", appleFPProvision->fairPlaySecretLength);

   return appleFPProvision;
}

static bool readAppleFairplayData(AppleFairPlayProvisioning **appleFPProvision) {
   FILE* file_fairplay_secret = NULL;
   const char* file_fairplay_secret_name = getenv("apple_fairplay_secret");

   INFO("file_fairplay_secret_name:%s", file_fairplay_secret_name);
   if (file_fairplay_secret_name == NULL) {
        file_fairplay_secret_name = apple_fairplay_secret;
        if(0 != access(file_fairplay_secret_name, F_OK)) {
           ERROR("File does not exist: %s",file_fairplay_secret_name);
           return false;
        }
   }

   file_fairplay_secret = fopen(file_fairplay_secret_name, "rbe");
   if (NULL == file_fairplay_secret) {
       ERROR("file :%s does not exist", file_fairplay_secret_name);
       return false;
   }

   *appleFPProvision = createAppleFairplayblob(file_fairplay_secret);

   if(file_fairplay_secret)
      fclose(file_fairplay_secret);

   if(NULL == *appleFPProvision) {
      ERROR("failed to get appleFPProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
