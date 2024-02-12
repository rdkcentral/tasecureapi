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
#include "digest_util.h"
#include "sa.h"
#include "sa_key.h"
#include "sa_key_import_common.h"
#include "gtest/gtest.h"
#include <unordered_map>
using namespace client_test_helpers;

//Note: turn on this if you want to read data from files
//#define FILE_BASED_FETCH_KEY
#ifdef FILE_BASED_FETCH_KEY
static NetflixProvisioning* createNetflixblob(FILE *file_hmac_key,
   FILE *file_wrapping_key, FILE*file_estn);
static bool readNetflixData(NetflixProvisioning **nflxProvision);
#endif //FILE_BASED_FETCH_KEY

namespace {
    TEST_P(SaKeyProvisionNetflixTest, nominal) {
        auto encryption_key_length = std::get<0>(GetParam());
        std::string hmac_key_type_string = std::get<1>(GetParam());

        std::vector<uint8_t> clear_encryption_key = random(encryption_key_length);
        std::vector<uint8_t> clear_hmac_key = random(encryption_key_length);

        //create a hmac key container
        std::string hmac_key_container;
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        sa_status status = create_key_container(
             hmac_key_type_string, //key type string
             hmac_key_type, //key type
             clear_hmac_key,
             hmac_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        //create a wrapping key container
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::vector<uint8_t> key_id = random(encryption_key_length);
        std::unordered_map<std::string, std::string> type_map = {
           {"HMAC-128", "AES-128"},
           {"HMAC-256", "AES-256"}
        };
        //You can use other algorithm to wrap key, here just provide
        //a very simple way to wrap AES key.
        for (int i = 0; i < (int)encryption_key_length; i++) {
            clear_encryption_key[i] ^= key_id[i];
        }
        status = create_key_container(
             type_map[hmac_key_type_string], //key type string
             wrapping_key_type, //key type
             clear_encryption_key,
             wrapping_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           sizeof(NetflixProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
    }

    TEST_F(SaKeyProvisionNetflixTest, simpleCheck) {
        auto key_length = SYM_256_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(AES_BLOCK_SIZE);
        std::vector<uint8_t> clear_hmac_key = random(key_length);
        std::vector<uint8_t> clear_wrapping_key(key_length);

        //create a hmac key container
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string hmac_key_type_string = "HMAC-256";

        std::string hmac_key_container;
        sa_status status = create_key_container(
             hmac_key_type_string, //key type string
             hmac_key_type, //key type
             clear_hmac_key,
             hmac_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        //create a wrapping key container
        std::string wrapping_key_container;
        std::string wrapping_key_type_string = "AES-128";
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::vector<uint8_t> key_id = random(AES_BLOCK_SIZE);
        //You can use other algorithm to wrap key, here just provide
        //a very simple way wrap AES key.
        for (auto i = 0; i < AES_BLOCK_SIZE; i++) {
            clear_encryption_key[i] ^= key_id[i];
        }
        status = create_key_container(
             wrapping_key_type_string, //key type string
             wrapping_key_type, //key type
             clear_encryption_key,
             wrapping_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           sizeof(NetflixProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
    }
    TEST_F(SaKeyProvisionNetflixTest, failsZeroInLength) {
        auto key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(key_length);
        std::vector<uint8_t> clear_hmac_key = random(key_length);

        //create a hmac key container
        std::string hmac_key_container;
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string hmac_key_type_string = "HMAC-128";
        sa_status status = create_key_container(
             hmac_key_type_string, //key type string
             hmac_key_type, //key type
             clear_hmac_key,
             hmac_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        //create a wrapping key container
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string wrapping_key_type_string = "AES-128";
        std::vector<uint8_t> key_id = random(AES_BLOCK_SIZE);
        //You can use other algorithm to wrap key, here just provide
        //a very simple way wrap AES key.
        for (auto i = 0; i < AES_BLOCK_SIZE; i++) {
            clear_encryption_key[i] ^= key_id[i];
        }
        status = create_key_container(
             wrapping_key_type_string, //key type string
             wrapping_key_type, //key type
             clear_encryption_key,
             wrapping_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           0, nullptr);

        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }

    TEST_F(SaKeyProvisionNetflixTest, failsNullProvision) {
        auto key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(key_length);
        std::vector<uint8_t> clear_hmac_key = random(key_length);
        std::vector<uint8_t> clear_wrapping_key(key_length);

        //create a hmac key container
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string hmac_key_type_string = "HMAC-256";

        std::string hmac_key_container;
        sa_status status = create_key_container(
             hmac_key_type_string, //key type string
             hmac_key_type, //key type
             clear_hmac_key,
             hmac_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key,
           clear_hmac_key));

        //create a wrapping key container
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string wrapping_key_type_string = "AES-128";
        std::vector<uint8_t> key_id = random(AES_BLOCK_SIZE);
        //You can use other algorithm to wrap key, here just provide
        //a very simple way wrap AES key.
        for (auto i = 0; i < AES_BLOCK_SIZE; i++) {
            clear_encryption_key[i] ^= key_id[i];
        }
        status = create_key_container(
             wrapping_key_type_string, //key type string
             wrapping_key_type, //key type
             clear_encryption_key,
             wrapping_key_container);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nullptr,
           sizeof(NetflixProvisioning), nullptr);
        ASSERT_NE(status, SA_STATUS_OK);

        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
    }
#ifdef FILE_BASED_FETCH_KEY
    //There are two file netflix_hmac_key.key,netflix_wrapping_key.key and netflix_estn.bin 
    //undertasecureapi/reference/src/client/,
    //these files are netflix hmac and wrapping key and estn number. you can do
    //"export  netflix_hmac_key=~/PATH/tasecureapi/reference/src/client/netflix_hmac_key.key",
    //"export  netflix_wrapping_key=~/PATH/tasecureapi/reference/src/client/netflix_wrapping_key.key",
    //"export  netflix_estn=~/PATH/tasecureapi/reference/src/client/netflix_estn.bin",
    //the following test fromFileBased will pick up them and test
    //Or
    //you just simply copy these two files and put under /opt/drm/
 TEST_F(SaKeyProvisionNetflixTest, fromFileBased) {
        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        ASSERT_TRUE(readNetflixData(&nflxProvision));

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING,
          nflxProvision, sizeof(nflxProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != nflxProvision->hmacKey){
           free(nflxProvision->hmacKey);
           nflxProvision->hmacKey = nullptr;
        }
        if (nullptr != nflxProvision->wrappingKey){
           free(nflxProvision->wrappingKey);
           nflxProvision->wrappingKey = nullptr;
        }
        if (nullptr != nflxProvision->esnContainer){
           free(nflxProvision->esnContainer);
           nflxProvision->esnContainer = nullptr;
        }
    }
#endif //FILE_BASED_FETCH_KEY
} // namespace

#ifdef FILE_BASED_FETCH_KEY
#include <sys/stat.h>
#include <string.h>

#define netflix_estn               "/opt/drm/netflix_estn.bin"
#define netflix_hmac_key           "/opt/drm/netflix_hmac_key.key"
#define netflix_wrapping_key       "/opt/drm/netflix_wrapping_key.key"

static void* readBlob(FILE *fp, size_t *key_length) {
   if (NULL == fp) {
      ERROR("file pointer do not exist");
      return NULL;
   }
   if (0 != fseek(fp,0L,SEEK_END)) {
      ERROR("failed to seek end");
      return NULL;
   }
   *key_length = ftell(fp);
   void *key = calloc(*key_length, 1);
   if (NULL == key) {
       ERROR("OOM");
       return NULL;
   }
   if (0 != fseek(fp, 0L,SEEK_SET)) {
      ERROR("Failed to seek to the beginning");
      return NULL;
   }
   size_t keySize = fread(key, 1,*key_length,fp);
   if (keySize != *key_length ||
      keySize  < *key_length) {
      ERROR("%d, %d", keySize, key_length);
      ERROR("this file has problem");
      return NULL;
   }
   
   return key;
}
static NetflixProvisioning* createNetflixblob(
       FILE *file_hmac_key, 
       FILE *file_wrapping_key,
       FILE *file_estn) {
   if (NULL == file_hmac_key     ||
      NULL == file_wrapping_key ||
      NULL == file_estn) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t hmac_key_length = 0;
   void *hmac_key = readBlob(file_hmac_key, &hmac_key_length);
   if (NULL == hmac_key) {
      ERROR("this file :%s has problem", netflix_hmac_key);
      return NULL;
   }
   INFO("hmac_key_length: %d", hmac_key_length);

   size_t wrapping_key_length = 0;
   void *wrapping_key = readBlob(file_wrapping_key, &wrapping_key_length);
   if (NULL == wrapping_key) {
      ERROR("this file :%s has problem", netflix_wrapping_key);
      return NULL;
   }
   INFO("wrapping_key_length: %d", wrapping_key_length);
 
   size_t estn_size = 0;
   void *estn = readBlob(file_estn, &estn_size);
   if (NULL == estn) {
      ERROR("this file :%s has problem", netflix_estn);
      return NULL;
   }
   INFO("estn_size: %d", estn_size);

   NetflixProvisioning *nflxProvision =
       (NetflixProvisioning*)calloc(sizeof(NetflixProvisioning), 1);
   if (NULL == nflxProvision) {
      ERROR("OOM");
      return NULL;
   }

   nflxProvision->hmacKey = hmac_key;
   nflxProvision->hmacKeyLength = hmac_key_length;
   nflxProvision->wrappingKey = wrapping_key;
   nflxProvision->wrappingKeyLength = wrapping_key_length;
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
      if (0 != access(file_hmac_key_name, F_OK)) {
         ERROR("File does not exist: %s",file_hmac_key_name);
         return false;
      }
   }
   if (file_wrapping_key_name == NULL) {
      file_wrapping_key_name = netflix_wrapping_key;
      if (0 != access(file_wrapping_key_name, F_OK)) {
         ERROR("File does not exist: %s",file_wrapping_key_name);
         return false;
      }
   }
   if (file_estn_name == NULL) {
      file_estn_name = netflix_estn;
      if (0 != access(file_estn_name, F_OK)) {
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

   if (file_hmac_key)
      fclose(file_hmac_key);
   if (file_wrapping_key)
      fclose(file_wrapping_key);
   if (file_estn)
      fclose(file_estn);

   if (NULL == *nflxProvision) {
      ERROR("failed to get nflxProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
