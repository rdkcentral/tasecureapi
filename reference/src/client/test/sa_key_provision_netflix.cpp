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
#include "digest_util.h"
#include "sa.h"
#include "sa_key.h"
#include "sa_key_import_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

/*Note: turn on this if you want to read data from files*/
#define FILE_BASED_FETCH_KEY

#ifdef FILE_BASED_FETCH_KEY
static NetflixProvisioning* createNetflixblob(FILE *file_hmac_key,
   FILE *file_wrapping_key, FILE*file_estn);
static bool readNetflixData(NetflixProvisioning **nflxProvision);
#endif //FILE_BASED_FETCH_KEY
namespace {
   static std::shared_ptr<std::vector<uint8_t>> export_key(
        std::vector<uint8_t>& mixin,
        sa_key key);
}

namespace {
    TEST_P(SaKeyProvisionNetflixTest, nominal) {
        auto encryption_key_length = std::get<0>(GetParam());
        auto hmac_key_length = std::get<1>(GetParam());

        auto  clear_encryption_key = random(encryption_key_length);
        auto  clear_hmac_key = random(hmac_key_length);
        std::vector<uint8_t>  clear_wrapping_key(encryption_key_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        //create an exported hmac key
        auto imported_hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        std::vector<uint8_t> mixin = {};
        auto exported_hmac_key = export_key(mixin, *imported_hmac_key);
        ASSERT_NE(nullptr, exported_hmac_key);
        INFO("export_hmac_key length : %d", exported_hmac_key->size());
       
        //create an exported wrapping key
        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key, clear_hmac_key));
        //ASSERT_TRUE(key_check_sym(*key, clear_wrapping_key));
        auto imported_wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        auto exported_wrapping_key = export_key(mixin, *imported_wrapping_key);
        ASSERT_NE(nullptr, exported_wrapping_key);
        INFO("export_wrapping_key length : %d", exported_wrapping_key->size());
        //write_to_storage(exported_wrapping_key->data(), exported_wrapping_key->size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        nflxProvision->hmacKey = exported_hmac_key->data();
        nflxProvision->hmacKeyLength = exported_hmac_key->size();

        nflxProvision->wrappingKey = exported_wrapping_key->data();
        nflxProvision->wrappingKeyLength = exported_wrapping_key->size();

        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision, 
           sizeof(NetflixProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
    }

    TEST_F(SaKeyProvisionNetflixTest, simpleCheck) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        std::vector<uint8_t> clear_wrapping_key(SYM_128_KEY_SIZE);

        //create an exported hmac key
        auto imported_hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        std::vector<uint8_t> mixin = {};
        auto exported_hmac_key = export_key(mixin, *imported_hmac_key);
        ASSERT_NE(nullptr, exported_hmac_key);
        INFO("export_hmac_key length : %d", exported_hmac_key->size());
        //write_to_storage(exported_hmac_key->data(),exported_hmac_key->size());

        //create an exported wrapping key
        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key, clear_hmac_key));
        //ASSERT_TRUE(key_check_sym(*key, clear_wrapping_key));
        sa_rights_set_allow_all(&rights);
        auto imported_wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        auto exported_wrapping_key = export_key(mixin, *imported_wrapping_key);
        ASSERT_NE(nullptr, exported_wrapping_key);
        INFO("export_wrapping_key length : %d", exported_wrapping_key->size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        nflxProvision->hmacKey = exported_hmac_key->data();
        nflxProvision->hmacKeyLength = exported_hmac_key->size();

        nflxProvision->wrappingKey = exported_wrapping_key->data();
        nflxProvision->wrappingKeyLength = exported_wrapping_key->size();

        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;
        //write_to_storage(nflxProvision->esnContainer, SYM_256_KEY_SIZE);

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision, 
           sizeof(NetflixProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionNetflixTest, failsZeroInLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        std::vector<uint8_t> clear_wrapping_key(SYM_128_KEY_SIZE);

        //create an exported hmac key
        auto imported_hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        std::vector<uint8_t> mixin = {};
        auto exported_hmac_key = export_key(mixin, *imported_hmac_key);
        ASSERT_NE(nullptr, exported_hmac_key);
        INFO("export_hmac_key length : %d", exported_hmac_key->size());

        //create an exported wrapping key
        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key, clear_hmac_key));
        //ASSERT_TRUE(key_check_sym(*key, clear_wrapping_key));
        sa_rights_set_allow_all(&rights);
        auto imported_wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        auto exported_wrapping_key = export_key(mixin, *imported_wrapping_key);
        ASSERT_NE(nullptr, exported_wrapping_key);
        INFO("export_wrapping_key length : %d", exported_wrapping_key->size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        nflxProvision->hmacKey = exported_hmac_key->data();
        nflxProvision->hmacKeyLength = exported_hmac_key->size();

        nflxProvision->wrappingKey = exported_wrapping_key->data();
        nflxProvision->wrappingKeyLength = exported_wrapping_key->size();

        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision, 
           0, nullptr);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }

    TEST_F(SaKeyProvisionNetflixTest, failsNullProvision) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        std::vector<uint8_t> clear_wrapping_key(SYM_128_KEY_SIZE);

        //create an exported hmac key
        auto imported_hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        std::vector<uint8_t> mixin = {};
        auto exported_hmac_key = export_key(mixin, *imported_hmac_key);
        ASSERT_NE(nullptr, exported_hmac_key);
        INFO("export_hmac_key length : %d", exported_hmac_key->size());

        //create an exported wrapping key
        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key, clear_hmac_key));
        //ASSERT_TRUE(key_check_sym(*key, clear_wrapping_key));
        sa_rights_set_allow_all(&rights);
        auto imported_wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        auto exported_wrapping_key = export_key(mixin, *imported_wrapping_key);
        ASSERT_NE(nullptr, exported_wrapping_key);
        INFO("export_wrapping_key length : %d", exported_wrapping_key->size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        nflxProvision->hmacKey = exported_hmac_key->data();
        nflxProvision->hmacKeyLength = exported_hmac_key->size();

        nflxProvision->wrappingKey = exported_wrapping_key->data();
        nflxProvision->wrappingKeyLength = exported_wrapping_key->size();

        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING, nullptr, 
           sizeof(NetflixProvisioning), nullptr);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
    TEST_F(SaKeyProvisionNetflixTest, failsNoCacheableFlag) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        std::vector<uint8_t> clear_wrapping_key(SYM_128_KEY_SIZE);

        //create an exported hmac key
        auto imported_hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(nullptr, imported_hmac_key);
        if(UNSUPPORTED_KEY == *imported_hmac_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }
       
        size_t out_length = 0;
        sa_status status = sa_key_export(nullptr, &out_length,nullptr,0,*imported_hmac_key);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);

    }
    TEST_F(SaKeyProvisionNetflixTest, failsInvalidMixinLength) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        std::vector<uint8_t> clear_wrapping_key(SYM_128_KEY_SIZE);

        //create an exported hmac key
        auto imported_hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(nullptr, imported_hmac_key);
        if(UNSUPPORTED_KEY == *imported_hmac_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }
       
        auto mixin = random(17);
        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        sa_status status = sa_key_export(out.data(), &out_length, mixin.data(),
           mixin.size(),*imported_hmac_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

#ifdef FILE_BASED_FETCH_KEY
 /*there are two file 0371000003710002.key,0371000003710003.key and 0671000006710001.bin 
   undertasecureapi/reference/src/client/,
   these files are netflix hmac and wrapping key and estn number. you can do
   "export  netflix_hmac_key=~/PATH/tasecureapi/reference/src/client/0371000003710002.key",
   "export  netflix_wrapping_key=~/PATH/tasecureapi/reference/src/client/0371000003710003.key",
   "export  netflix_estn=~/PATH/tasecureapi/reference/src/client/0671000006710001.bin",
   the following test fromFileBased will pick up them and test
  Or
   you just simply copy these two files and put under /opt/drm/
  */
 TEST_F(SaKeyProvisionNetflixTest, fromFileBased) {
        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        ASSERT_TRUE(readNetflixData(&nflxProvision));

        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, 
          nflxProvision, sizeof(nflxProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != nflxProvision->hmacKey){
           free(nflxProvision->hmacKey);
           nflxProvision->hmacKey = nullptr;
        }
        if(nullptr != nflxProvision->wrappingKey){
           free(nflxProvision->wrappingKey);
           nflxProvision->wrappingKey = nullptr;
        }
        if(nullptr != nflxProvision->esnContainer){
           free(nflxProvision->esnContainer);
           nflxProvision->esnContainer = nullptr;
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

#define netflix_privatekey         "/opt/drm/0671000006710002.bin"
#define netflix_estn               "/opt/drm/0671000006710001.bin"
#define netflix_hmac_key           "/opt/drm/0371000003710002.key"
#define netflix_wrapping_key       "/opt/drm/0371000003710003.key"

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
static NetflixProvisioning* createNetflixblob(
       FILE *file_hmac_key, 
       FILE *file_wrapping_key,
       FILE *file_estn) {
   if(NULL == file_hmac_key     ||
      NULL == file_wrapping_key ||
      NULL == file_estn) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t hmac_key_size = 0;
   void *hmac_key = readBlob(file_hmac_key, &hmac_key_size);
   if(NULL == hmac_key) {
      ERROR("this file :%s has problem", netflix_hmac_key);
      return NULL;
   }
   INFO("hmac_key_size: %d", hmac_key_size); 

   size_t wrapping_key_size = 0;
   void *wrapping_key = readBlob(file_wrapping_key, &wrapping_key_size);
   if(NULL == wrapping_key) {
      ERROR("this file :%s has problem", netflix_wrapping_key);
      return NULL;
   }
   INFO("wrapping_key_size: %d", wrapping_key_size);
 
   size_t estn_size = 0;
   void *estn = readBlob(file_estn, &estn_size);
   if(NULL == estn) {
      ERROR("this file :%s has problem", netflix_estn);
      return NULL;
   }
   INFO("estn_size: %d", estn_size);

   NetflixProvisioning *nflxProvision =
       (NetflixProvisioning*)calloc(sizeof(NetflixProvisioning), 1);
   if(NULL == nflxProvision) {
      ERROR("OOM");
      return NULL;
   }

   nflxProvision->hmacKey = hmac_key;
   nflxProvision->hmacKeyLength = hmac_key_size;
   nflxProvision->wrappingKey = wrapping_key;
   nflxProvision->wrappingKeyLength = wrapping_key_size;
   nflxProvision->esnContainer = estn;
   nflxProvision->esnContainerLength = estn_size;

   INFO("keyLen : %d", nflxProvision->hmacKeyLength);
   INFO("wrappingLen : %d", nflxProvision->wrappingKeyLength);
   INFO("estnLen : %d", nflxProvision->esnContainerLength);

   return nflxProvision;
}

static bool readNetflixData(NetflixProvisioning **nflxProvision) {
   FILE* file_hmac_key = NULL;
   FILE* file_wrapping_key = NULL;
   FILE* file_estn = NULL;
   const char* file_hmac_key_name = getenv("netflix_hmac_key");
   const char* file_wrapping_key_name = getenv("netflix_wrapping_key");
   const char* file_estn_name = getenv("netflix_estn");

   INFO("file_hmac_key_name:%s", file_hmac_key_name);
   INFO("file_wrapping_key_name:%s", file_wrapping_key_name);
   INFO("file_estn_name:%s", file_estn_name);
   if (file_hmac_key_name == NULL) {
        file_hmac_key_name = netflix_hmac_key;
        if(0 != access(file_hmac_key_name, F_OK)) {
           ERROR("File does not exist: %s",file_hmac_key_name);
           return false;
        }
   }
   if (file_wrapping_key_name == NULL) {
        file_wrapping_key_name = netflix_wrapping_key;
        if(0 != access(file_wrapping_key_name, F_OK)) {
           ERROR("File does not exist: %s",file_wrapping_key_name);
           return false;
        }
   }
   if (file_estn_name == NULL) {
        file_estn_name = netflix_estn;
        if(0 != access(file_estn_name, F_OK)) {
           ERROR("File does not exist: %s",file_estn_name);
           return false;
        }
   }

   file_hmac_key = fopen(file_hmac_key_name, "rbe");
   if (NULL == file_hmac_key) {
       ERROR("file :%s does not exist", file_hmac_key_name);
       return false;
   }
   file_wrapping_key = fopen(file_wrapping_key_name, "rbe");
   if (NULL == file_wrapping_key) {
       ERROR("file :%s does not exist", file_wrapping_key_name);
       return false;
   }
   file_estn = fopen(file_estn_name, "rbe");
   if (NULL == file_estn) {
       ERROR("file :%s does not exist", file_estn_name);
       return false;
   }

   *nflxProvision = createNetflixblob(file_hmac_key,
                                       file_wrapping_key,
                                       file_estn);

   if(file_hmac_key)
      fclose(file_hmac_key);
   if(file_wrapping_key)
      fclose(file_wrapping_key);
   if(file_estn)
      fclose(file_estn);

   if(NULL == *nflxProvision) {
      ERROR("failed to get nflxProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
