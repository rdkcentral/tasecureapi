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

#ifdef FILE_BASED_FETCH_KEY
#define netflix_esn                "/keys/fake_netflix_esn.bin"
#define netflix_hmac_key           "/keys/fake_netflix_hmac_key.key"
#define netflix_wrapping_key       "/keys/fake_netflix_wrapping_key.key"
#define netflix_encryption_key     "/keys/fake_netflix_encryption_key.key"
static NetflixProvisioning*  createNetflixBlob(FILE *file_encryption_key,
   FILE *file_hmac_key, FILE *file_wrapping_key, FILE*file_esn);
static bool readNetflixData(NetflixProvisioning **nflxProvision);
#endif // FILE_BASED_FETCH_KEY

namespace {
    TEST_P(SaKeyProvisionNetflixTest, nominal) {
        uint8_t wrapping_key_length = SYM_128_KEY_SIZE;
        uint8_t encryption_key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(encryption_key_length);
        std::vector<uint8_t> clear_wrapping_key = random(wrapping_key_length);
        uint16_t hmac_key_length = std::get<0>(GetParam());
        std::vector<uint8_t> clear_hmac_key = random(hmac_key_length);

        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);

	// Create an encryption key container
        std::string encryption_key_type_string = "AES-128";
        std::string encryption_key_container;
        auto encryption_key_type = SA_KEY_TYPE_SYMMETRIC;
        sa_status status =  create_key_container(
             encryption_key_type_string, // key type string
             encryption_key_type, // key type
             clear_encryption_key,
             encryption_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("encryption_key_container length : %d", encryption_key_container.size());

        // Create a hmac key container
        std::string hmac_key_type_string = std::get<1>(GetParam());
        std::string hmac_key_container;
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        ASSERT_NE(nullptr, parameters);
        status =  create_key_container(
             hmac_key_type_string, // key type string
             hmac_key_type, // key type
             clear_hmac_key,
             hmac_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        // Create a wrapping key container
        std::string wrapping_key_type_string = "AES-128";
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        status =  create_key_container(
             wrapping_key_type_string, // key type string
             wrapping_key_type, // key type
             clear_wrapping_key,
             wrapping_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        // Note: Here is an example of creating a test provisioning object and passing
        // it into sa_key_provision_ta. Format of keys and certs may vary depending on how
	// each platform has these data encoded and delivered.
        nflxProvision->encryptionKey = (void*)encryption_key_container.data();
        nflxProvision->encryptionKeyLength = encryption_key_container.size();
        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("encryption length : %d", nflxProvision->encryptionKeyLength);
        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           sizeof(NetflixProvisioning), parameters);

        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
	if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_OK);
    }
	
    TEST_F(SaKeyProvisionNetflixTest, invalidParameters) {
        auto hmac_key_length = SYM_256_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_hmac_key = random(hmac_key_length);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_128_KEY_SIZE);

        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);

        // Create an encryption key container
        std::string encryption_key_type_string = "AES-128";
        std::string encryption_key_container;
        auto encryption_key_type = SA_KEY_TYPE_SYMMETRIC;
        sa_status status =  create_key_container(
             encryption_key_type_string, // key type string
             encryption_key_type, // key type
             clear_encryption_key,
             encryption_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("encryption_key_container length : %d", encryption_key_container.size());

        // Create a hmac key container
        std::string hmac_key_type_string = "HMAC-256";
        std::string hmac_key_container;
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        ASSERT_NE(nullptr, parameters);
        status =  create_key_container(
             hmac_key_type_string, // key type string
             hmac_key_type, // key type
             clear_hmac_key,
             hmac_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        // Create a wrapping key container
        std::string wrapping_key_type_string = "AES-128";
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        status =  create_key_container(
             wrapping_key_type_string, // key type string
             wrapping_key_type, // key type
             clear_wrapping_key,
             wrapping_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        // Note: Here is an example of creating a test provisioning object, and passing
        // it into sa_key_provision_ta. Format of keys and certs may vary depending on how
	// each platform has these data encoded and delivered.
        nflxProvision->encryptionKey = (void*)encryption_key_container.data();
        nflxProvision->encryptionKeyLength = encryption_key_container.size();
        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("encryption length : %d", nflxProvision->encryptionKeyLength);
        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);
	parameters->version = 0;
        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           sizeof(NetflixProvisioning), parameters);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
	if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
	
	
    TEST_F(SaKeyProvisionNetflixTest, invalidKeyFormat) {
        auto hmac_key_length = SYM_128_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_hmac_key = random(hmac_key_length);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_128_KEY_SIZE);

        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);

        // Create an encryption key container
        std::string encryption_key_type_string = "AES-128";
        auto encryption_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string encryption_key_container;
        sa_status status =  create_key_container(
             encryption_key_type_string, // key type string
             encryption_key_type, // key type
             clear_encryption_key,
             encryption_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("encryption_key_container length : %d", encryption_key_container.size());

        // Create a hmac key container
        std::string hmac_key_type_string = "HMAC-256";
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string hmac_key_container;
        ASSERT_NE(nullptr, parameters);
        status =  create_key_container(
             hmac_key_type_string, // key type string
             hmac_key_type, // key type
             clear_hmac_key,
             hmac_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        // Create a wrapping key container
        std::string wrapping_key_type_string = "AES-128";
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        status =  create_key_container(
             wrapping_key_type_string, // key type string
             wrapping_key_type, // key type
             clear_wrapping_key,
             wrapping_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        // Note: Here is an example of creating a test provisioning object, and passing
        // it into sa_key_provision_ta. Format of keys and certs may vary depending on how
	// each platform has these data encoded and delivered.
        nflxProvision->encryptionKey = (void*)encryption_key_container.data();
        nflxProvision->encryptionKeyLength = encryption_key_container.size() >> 1;
        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size() >> 1;
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size() >> 1;
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("encryption length : %d", nflxProvision->encryptionKeyLength);
        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           sizeof(NetflixProvisioning), parameters);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
	if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }
	
    TEST_F(SaKeyProvisionNetflixTest, failsZeroInLength) {
        auto hmac_key_length = SYM_256_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_hmac_key = random(hmac_key_length);

        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);

        // Create an encryption key container
        std::string encryption_key_type_string = "AES-128";
        std::string encryption_key_container;
        auto encryption_key_type = SA_KEY_TYPE_SYMMETRIC;
        sa_status status =  create_key_container(
             encryption_key_type_string, // key type string
             encryption_key_type, // key type
             clear_encryption_key,
             encryption_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("encryption_key_container length : %d", encryption_key_container.size());

        // Create a hmac key container
        std::string hmac_key_type_string = "HMAC-256";
        std::string hmac_key_container;
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        status =  create_key_container(
             hmac_key_type_string, // key type string
             hmac_key_type, // key type
             clear_hmac_key,
             hmac_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        // Create a wrapping key container
        std::string wrapping_key_type_string = "AES-128";
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        status =  create_key_container(
             wrapping_key_type_string, // key type string
             wrapping_key_type, // key type
             clear_wrapping_key,
             wrapping_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        // Note: Here is an example of creating a test provisioning object, and passing
        // it into sa_key_provision_ta. Format of keys and certs may vary depending on how
	// each platform has these data encoded and delivered.
        nflxProvision->encryptionKey = (void*)encryption_key_container.data();
        nflxProvision->encryptionKeyLength = encryption_key_container.size();
        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("encryption length : %d", nflxProvision->encryptionKeyLength);
        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision,
           0, parameters);

        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
        if (nullptr != parameters) {
            delete parameters;
            parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyProvisionNetflixTest, failsNullProvision) {
        auto hmac_key_length = SYM_256_KEY_SIZE;
        std::vector<uint8_t> clear_encryption_key = random(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_hmac_key = random(hmac_key_length);
        std::vector<uint8_t> clear_wrapping_key = random(SYM_128_KEY_SIZE);

        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);

        // Create an encryption key container
        std::string encryption_key_type_string = "AES-128";
        auto encryption_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string encryption_key_container;
        sa_status status =  create_key_container(
             encryption_key_type_string, // key type string
             encryption_key_type, // key type
             clear_encryption_key,
             encryption_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("encryption_key_container length : %d", encryption_key_container.size());

        // Create a hmac key container
        std::string hmac_key_type_string = "HMAC-256";
        auto hmac_key_type = SA_KEY_TYPE_SYMMETRIC;
        std::string hmac_key_container;
        status =  create_key_container(
             hmac_key_type_string, // key type string
             hmac_key_type, // key type
             clear_hmac_key,
             hmac_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("hmac_key_container length : %d", hmac_key_container.size());

        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key,
           clear_hmac_key));

        // Create a wrapping key container
        std::string wrapping_key_type_string = "AES-128";
        std::string wrapping_key_container;
        auto wrapping_key_type = SA_KEY_TYPE_SYMMETRIC;
        status =  create_key_container(
             wrapping_key_type_string, // key type string
             wrapping_key_type, // key type
             clear_encryption_key,
             wrapping_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("wrapping_key_container length : %d", wrapping_key_container.size());

        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);

        // Note: Here is an example of creating a test provisioning object, and passing
        // it into sa_key_provision_ta. Format of keys and certs may vary depending on how
	// each platform has these data encoded and delivered.
        nflxProvision->encryptionKey = (void*)encryption_key_container.data();
        nflxProvision->encryptionKeyLength = encryption_key_container.size();
        nflxProvision->hmacKey = (void*)hmac_key_container.data();
        nflxProvision->hmacKeyLength = hmac_key_container.size();
        nflxProvision->wrappingKey = (void*)wrapping_key_container.data();
        nflxProvision->wrappingKeyLength = wrapping_key_container.size();
        nflxProvision->esnContainer = (void*)(random(SYM_256_KEY_SIZE)).data();
        nflxProvision->esnContainerLength = SYM_256_KEY_SIZE;

        INFO("encryption length : %d", nflxProvision->encryptionKeyLength);
        INFO("hmac length : %d", nflxProvision->hmacKeyLength);
        INFO("wrapping length : %d", nflxProvision->wrappingKeyLength);
        INFO("ESN length : %d", nflxProvision->esnContainerLength);

        status = sa_key_provision_ta(NETFLIX_PROVISIONING, nullptr,
           sizeof(NetflixProvisioning), parameters);

        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
	if (nullptr != parameters) {
            delete parameters;
            parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
#ifdef FILE_BASED_FETCH_KEY
    // There are four file fake_netflix_encryption_key.key, fake_netflix_hmac_key.key,
    // fake_netflix_wrapping_key.key and fake_netflix_esn.bin
    // under tasecureapi/reference/test/,
    // these files are netflix encryption key, hmac and wrapping key and esn number. you can do
    // "export  netflix_encryption_key=~/PATH/tasecureapi/reference/test/fake_netflix_encryption_key.key",
    // "export  netflix_hmac_key=~/PATH/tasecureapi/reference/test/fake_netflix_hmac_key.key",
    // "export  netflix_wrapping_key=~/PATH/tasecureapi/reference/test/fake_netflix_wrapping_key.key",
    // "export  netflix_esn=~/PATH/tasecureapi/reference/test/fake_netflix_esn.bin",
    // the following test fromFileBased will pick up them and test
    // Or
    // you just simply put these three files under /keys.
 TEST_F(SaKeyProvisionNetflixTest, fromFileBased) {
        NetflixProvisioning *nflxProvision = new NetflixProvisioning;
        ASSERT_NE(nullptr, nflxProvision);
        ASSERT_TRUE(readNetflixData(&nflxProvision));
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
	createParameters(parameters,SA_SPECIFICATION_MAJOR);

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING,
          nflxProvision, sizeof(nflxProvision), parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != nflxProvision->encryptionKey){
           free(nflxProvision->encryptionKey);
           nflxProvision->encryptionKey = nullptr;
        }
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
        if (nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
        if (nullptr != parameters) {
            delete parameters;
            parameters = nullptr;
        }
    }
#endif //FILE_BASED_FETCH_KEY
} // namespace

#ifdef FILE_BASED_FETCH_KEY
#include <sys/stat.h>
#include <string.h>

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
static NetflixProvisioning*  createNetflixBlob(
       FILE *file_encryption_key,
       FILE *file_hmac_key, 
       FILE *file_wrapping_key,
       FILE *file_esn) {
   if (NULL == file_encryption_key ||
      NULL == file_hmac_key        ||
      NULL == file_wrapping_key    ||
      NULL == file_esn) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t encryption_key_length = 0;
   void *encryption_key = readBlob(file_encryption_key, &encryption_key_length);
   if (NULL == encryption_key) {
      ERROR("this file :%s has problem", netflix_encryption_key);
      return NULL;
   }
   INFO("encryption_key_length: %d", encryption_key_length);

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
 
   size_t esn_size = 0;
   void *esn = readBlob(file_esn, &esn_size);
   if (NULL == esn) {
      ERROR("this file :%s has problem", netflix_esn);
      return NULL;
   }
   INFO("esn_size: %d", esn_size);

   NetflixProvisioning *nflxProvision =
       (NetflixProvisioning*)calloc(1, sizeof(NetflixProvisioning));
   if (NULL == nflxProvision) {
      ERROR("OOM");
      return NULL;
   }

   nflxProvision->encryptionKey = encryption_key;
   nflxProvision->encryptionKeyLength = encryption_key_length;
   nflxProvision->hmacKey = hmac_key;
   nflxProvision->hmacKeyLength = hmac_key_length;
   nflxProvision->wrappingKey = wrapping_key;
   nflxProvision->wrappingKeyLength = wrapping_key_length;
   nflxProvision->esnContainer = esn;
   nflxProvision->esnContainerLength = esn_size;

   INFO("encryption keyLen : %d", nflxProvision->encryptionKeyLength);
   INFO("hmac keyLen : %d", nflxProvision->hmacKeyLength);
   INFO("wrappingLen : %d", nflxProvision->wrappingKeyLength);
   INFO("esnLen : %d", nflxProvision->esnContainerLength);

   return nflxProvision;
}

static bool readNetflixData(NetflixProvisioning **nflxProvision) {
   FILE* file_encryption_key = NULL;
   FILE* file_hmac_key = NULL;
   FILE* file_wrapping_key = NULL;
   FILE* file_esn = NULL;
   const char* file_encryption_key_name = getenv("netflix_encryption_key");
   const char* file_hmac_key_name = getenv("netflix_hmac_key");
   const char* file_wrapping_key_name = getenv("netflix_wrapping_key");
   const char* file_esn_name = getenv("netflix_esn");

   INFO("file_encryption_key_name:%s", file_encryption_key_name);
   INFO("file_hmac_key_name:%s", file_hmac_key_name);
   INFO("file_wrapping_key_name:%s", file_wrapping_key_name);
   INFO("file_esn_name:%s", file_esn_name);
   if (file_encryption_key_name == NULL) {
      file_encryption_key_name = netflix_encryption_key;
      if (0 != access(file_encryption_key_name, F_OK)) {
         ERROR("File does not exist: %s",file_encryption_key_name);
         return false;
      }
   }
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
   if (file_esn_name == NULL) {
      file_esn_name = netflix_esn;
      if (0 != access(file_esn_name, F_OK)) {
         ERROR("File does not exist: %s",file_esn_name);
         return false;
      }
   }

   file_encryption_key = fopen(file_encryption_key_name, "rbe");
   if (NULL == file_encryption_key) {
       ERROR("file :%s does not exist", file_encryption_key_name);
       return false;
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
   file_esn = fopen(file_esn_name, "rbe");
   if (NULL == file_esn) {
      ERROR("file :%s does not exist", file_esn_name);
      return false;
   }

   *nflxProvision = createNetflixBlob(file_encryption_key,
		                      file_hmac_key,
                                      file_wrapping_key,
                                      file_esn);

   if (file_encryption_key)
      fclose(file_encryption_key);
   if (file_hmac_key)
      fclose(file_hmac_key);
   if (file_wrapping_key)
      fclose(file_wrapping_key);
   if (file_esn)
      fclose(file_esn);

   if (NULL == *nflxProvision) {
      ERROR("failed to get nflxProvision data");
      return false;
   } 
   return true;
}
#endif // FILE_BASED_FETCH_KEY
