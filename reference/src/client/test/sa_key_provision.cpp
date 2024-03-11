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

#define CERTIFICATION_LENGTH 4096
/*Note: turn on this if you want to check key validation*/
//#define KEY_VALIDATION_TEST
/*Note: turn on this if you want to read data from files*/
//#define FILE_BASED_FETCH_KEY

#ifdef FILE_BASED_FETCH_KEY
static WidevineOemProvisioning* createWidevineblob(FILE *file_private_key,
   FILE *file_oem_cert);
static bool readWidevineData(WidevineOemProvisioning **wvProvision);
#endif //FILE_BASED_FETCH_KEY
namespace {
   static std::shared_ptr<std::vector<uint8_t>> export_key(
        std::vector<uint8_t>& mixin,
        sa_key key);
}

namespace {
#ifdef KEY_VALIDATION_TEST
    static void *set_mem_data(void *pointer, uint8_t value,
       size_t length) {
       volatile uint8_t *p = (uint8_t*)pointer;
       while (length--){
          *p++ = value;
       }
       return pointer;
    }
#endif //KEY_VALIDATION_TEST

    TEST_F(SaKeyProvisionTest, checkWidevinePrivateKey) {
        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);

        auto clear_key = sample_rsa_1024_pkcs8_e3();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        std::vector<uint8_t> mixin = {};
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        INFO("export_key length : %d", exported_key->size());

        wvProvision->oemDevicePrivateKey = exported_key->data();
        wvProvision->oemDevicePrivateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        wvProvision->oemDeviceCertificate = certificate.data();
        wvProvision->oemDeviceCertificateLength = CERTIFICATION_LENGTH;

        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, wvProvision, sizeof(wvProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
    }

    TEST_F(SaKeyProvisionTest, checkPlayreadyPrivateKey) {
        auto clear_key = sample_rsa_3072_pkcs8();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }
        //create an exported private key
        std::vector<uint8_t> mixin = {};
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        DEBUG("export_key length : %d", exported_key->size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = exported_key->data();
        prProvision->privateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and pass
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        //same logic applies to model type below
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        //provides model type here, it may needed when SOC vendors save
        //unwrapped key inside TA.
        prProvision->modelType = PLAYREADY_MODEL_2K;
        sa_status status =
           sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision, sizeof(prProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
     }

    TEST_F(SaKeyProvisionTest, checkNetflixKeys) {
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

        sa_status status = sa_key_provision_ta(NETFLIX_PROVISIONING, nflxProvision, sizeof(nflxProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != nflxProvision) {
           delete nflxProvision;
           nflxProvision = nullptr;
        }
    }
#ifdef KEY_VALIDATION_TEST
  TEST_F(SaKeyProvisionTest, checkWidevinePrivateKeyValidation) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        
        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        std::vector<uint8_t> mixin = {};
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        INFO("export_key length : %d", exported_key->size());

        auto rsa_key = create_uninitialized_sa_key();
        sa_status  status = sa_key_import(rsa_key.get(), SA_KEY_FORMAT_EXPORTED,
                               exported_key->data(), exported_key->size(),NULL);
        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        set_mem_data(&type_parameters,0,sizeof(sa_type_parameters));
        auto header = key_header(*rsa_key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        //use 128B here since it is using rsa_1024 algo to create a key.
        ASSERT_EQ(128, header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(SA_KEY_TYPE_RSA, header->type);
        ASSERT_TRUE(key_check_rsa(*rsa_key, clear_key));

        // Get the public key.
        size_t out_length = 0;
        status = sa_key_get_public(nullptr, &out_length, *rsa_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);
        status = sa_key_get_public(out.data(), &out_length, *rsa_key);
        ASSERT_EQ(status, SA_STATUS_OK);
        out.resize(out_length);
        INFO("out_length : %d", out_length);

        // extract public using OpenSSL
        auto public_openssl = std::vector<uint8_t>(4096);
        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);
        ASSERT_TRUE(export_public_key(public_openssl, rsa));

        // compare public from OpenSSL and SecApi
        ASSERT_EQ(out, public_openssl);
    }


 TEST_F(SaKeyProvisionTest, checkPlayreadyPrivateKeyValidation) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        std::vector<uint8_t> mixin = {};
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        INFO("export_key length : %d", exported_key->size());

        auto rsa_key = create_uninitialized_sa_key();
        sa_status  status = sa_key_import(rsa_key.get(), SA_KEY_FORMAT_EXPORTED,
                               exported_key->data(), exported_key->size(),NULL);
        ASSERT_EQ(status, SA_STATUS_OK);

        sa_type_parameters type_parameters;
        set_mem_data(&type_parameters, 0, sizeof(sa_type_parameters));
        auto header = key_header(*rsa_key);
        ASSERT_NE(nullptr, header.get());
        ASSERT_TRUE(memcmp(&rights, &header->rights, sizeof(sa_rights)) == 0);
        //use 128B here since it is using rsa_1024 algo to create a key.
        ASSERT_EQ(128, header->size);
        ASSERT_EQ(memcmp(&type_parameters, &header->type_parameters, sizeof(sa_type_parameters)), 0);
        ASSERT_EQ(SA_KEY_TYPE_RSA, header->type);
        ASSERT_TRUE(key_check_rsa(*rsa_key, clear_key));

        // Get the public key.
        size_t out_length = 0;
        status = sa_key_get_public(nullptr, &out_length, *rsa_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto out = std::vector<uint8_t>(out_length);
        status = sa_key_get_public(out.data(), &out_length, *rsa_key);
        ASSERT_EQ(status, SA_STATUS_OK);
        out.resize(out_length);
        INFO("out_length : %d", out_length);

        // extract public using OpenSSL
        auto public_openssl = std::vector<uint8_t>(4096);
        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);
        ASSERT_TRUE(export_public_key(public_openssl, rsa));

        // compare public from OpenSSL and SecApi
        ASSERT_EQ(out, public_openssl);
  }

 TEST_F(SaKeyProvisionTest, checkNetflixKeysValidation) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        //check encryption key validation.
        auto clear_encryption_key = random(SYM_128_KEY_SIZE);
        auto encryption_key = create_sa_key_symmetric(&rights, clear_encryption_key);
        if(UNSUPPORTED_KEY == *encryption_key) {
           GTEST_SKIP() << "key type, size or curve are not supported";
        }
        std::vector<uint8_t> mixin = {};
        auto exported_encryption_key = export_key(mixin, *encryption_key);
        ASSERT_NE(nullptr, exported_encryption_key);
        INFO("export_encryption_key length : %d", exported_encryption_key->size());

        auto sa_encryption_key = create_uninitialized_sa_key();
        ASSERT_NE(sa_encryption_key,nullptr);

        sa_status status_encryption_key = sa_key_import(sa_encryption_key.get(), 
           SA_KEY_FORMAT_EXPORTED, exported_encryption_key->data(), exported_encryption_key->size(),nullptr);
        ASSERT_EQ(status_encryption_key, SA_STATUS_OK);

        auto header_encryption_key = key_header(*sa_encryption_key);
        ASSERT_NE(nullptr, header_encryption_key.get());
        ASSERT_TRUE(memcmp(&rights, &header_encryption_key->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_encryption_key.size(), header_encryption_key->size);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header_encryption_key->type);

        //check hmac key validation.
        auto clear_hmac_key = random(SYM_256_KEY_SIZE);
        sa_rights_set_allow_all(&rights);
        auto hmac_key = create_sa_key_symmetric(&rights, clear_hmac_key);
        ASSERT_NE(nullptr, hmac_key);
        if(UNSUPPORTED_KEY == *hmac_key) {
           GTEST_SKIP() << "key type, size or curve are not supported";
        }
        auto exported_hmac_key = export_key(mixin, *hmac_key);
        ASSERT_NE(nullptr, exported_hmac_key);
        INFO("export_hmac_key length : %d", exported_hmac_key->size());

        auto sa_hmac_key = create_uninitialized_sa_key();
        ASSERT_NE(sa_hmac_key,nullptr);

        sa_status status_hmac_key = sa_key_import(sa_hmac_key.get(),
           SA_KEY_FORMAT_EXPORTED, exported_hmac_key->data(), exported_hmac_key->size(),nullptr);
        ASSERT_EQ(status_hmac_key, SA_STATUS_OK);

        auto header_hmac_key = key_header(*sa_hmac_key);
        ASSERT_NE(nullptr, header_hmac_key.get());
        ASSERT_TRUE(memcmp(&rights, &header_hmac_key->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_hmac_key.size(), header_hmac_key->size);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header_hmac_key->type);

        sa_kdf_parameters_netflix kdf_parameters_netflix = {
           .kenc = *encryption_key,
           .khmac = *hmac_key};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(nullptr, key);
        sa_status status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_NETFLIX, &kdf_parameters_netflix);
        ASSERT_EQ(SA_STATUS_OK, status);
        std::vector<uint8_t> clear_wrapping_key(SYM_128_KEY_SIZE);
        ASSERT_TRUE(netflix_wrapping_key_kdf(clear_wrapping_key, clear_encryption_key, clear_hmac_key));
        ASSERT_TRUE(key_check_sym(*key, clear_wrapping_key));

        //check wrapping key validation.
        sa_rights_set_allow_all(&rights);
        auto wrapping_key = create_sa_key_symmetric(&rights, clear_wrapping_key);
        ASSERT_NE(nullptr, wrapping_key);
        if(UNSUPPORTED_KEY == *wrapping_key) {
           GTEST_SKIP() << "key type, size or curve are not supported";
        }
        auto exported_wrapping_key = export_key(mixin, *wrapping_key);
        ASSERT_NE(nullptr, exported_wrapping_key);
        INFO("export_wrapping_key length : %d", exported_wrapping_key->size());

        auto sa_wrapping_key = create_uninitialized_sa_key();
        ASSERT_NE(sa_wrapping_key,nullptr);

        sa_status status_wrapping_key = sa_key_import(sa_wrapping_key.get(), 
           SA_KEY_FORMAT_EXPORTED, exported_wrapping_key->data(), exported_wrapping_key->size(),nullptr);
        ASSERT_EQ(status_wrapping_key, SA_STATUS_OK);

        auto header_wrapping_key = key_header(*sa_wrapping_key);
        ASSERT_NE(nullptr, header_wrapping_key.get());
        ASSERT_TRUE(memcmp(&rights, &header_wrapping_key->rights, sizeof(sa_rights)) == 0);
        ASSERT_EQ(clear_wrapping_key.size(), header_wrapping_key->size);
        ASSERT_EQ(SA_KEY_TYPE_SYMMETRIC, header_wrapping_key->type);
    }
#endif //KEY_VALIDATION_TEST

#ifdef FILE_BASED_FETCH_KEY
 /*there are two file 0351000003510001.key and 0651000006510001.bin under
   tasecureapi/reference/src/client/,
   these files are widevine oem private key and certification. you can do
   "export  wievine_oem_privatekey=~/PATH/tasecureapi/reference/src/client/0351000003510001.key",
   "export  widevine_oem_cert=~/PATH/tasecureapi/reference/src/client/0651000006510001.bin",
   the following test checkWidevinePrivateKeyFromFileBased will pick up them and test
  Or
   you just simply copy these two files and put under /opt/drm/
  */
 TEST_F(SaKeyProvisionTest, checkWidevinePrivateKeyFromFileBased) {
        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        ASSERT_TRUE(readWidevineData(&wvProvision));

        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, wvProvision, sizeof(wvProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != wvProvision->oemDevicePrivateKey){
           free(wvProvision->oemDevicePrivateKey);
           wvProvision->oemDevicePrivateKey = nullptr;
        }
        if(nullptr != wvProvision->oemDeviceCertificate){
           free(wvProvision->oemDeviceCertificate);
           wvProvision->oemDeviceCertificate = nullptr;
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

#define wievine_oem_privatekey "/opt/drm/0351000003510001.key"
#define widevine_oem_cert      "/opt/drm/0651000006510001.bin"
#define playready2k_privatekey "/opt/drm/0331000003310001.key"
#define playready2k_oem_cert   "/opt/drm/0631000006310001.bin"
#define playready3k_privatekey "/opt/drm/0331000003310003.key"
#define playready3k_oem_cert   "/opt/drm/0631000006310002.bin"
#define netflix_privatekey     "/opt/drm/0671000006710002.bin"
#define netflix_estn           "/opt/drm/0671000006710001.x"
#define netflix_hmac           "/opt/drm/0371000003710002.x"
#define netflix_wrapping       "/opt/drm/0371000003710003.x"

static WidevineOemProvisioning* createWidevineblob(FILE *file_private_key, FILE *file_oem_cert) {
   if(NULL == file_private_key ||
      NULL == file_oem_cert) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   if(0 != fseek(file_private_key,0L,SEEK_END)) {
      ERROR("failed to seek end");
      return NULL;
   }
   size_t private_key_size = ftell(file_private_key);
   void *privateKey = calloc(private_key_size, 1);
   if (NULL == privateKey) {
       ERROR("OOM");
       return NULL;
   }
   if(0 != fseek(file_private_key, 0L,SEEK_SET)) {
     ERROR("Failed to seek to the beginning");
     return NULL;
   }
   size_t keySize = fread(privateKey, 1,private_key_size,file_private_key);
   if(keySize != private_key_size ||
      keySize < private_key_size) {
      ERROR("%d, %d", keySize, private_key_size);
      ERROR("this file:%s has problem", wievine_oem_privatekey);
      return NULL;
   }

   if(0!= fseek(file_oem_cert,0L,SEEK_END)) {
      ERROR("Failed to seek to the end");
      return NULL;
   }
   size_t oem_cert_size = ftell(file_oem_cert);
   void *oemCert = calloc(oem_cert_size, 1);
   if (NULL == oemCert) {
       ERROR("OOM");
       return NULL;
   }
   if(0 != fseek(file_oem_cert, 0L,SEEK_SET)) {
     ERROR("Failed to seek to the beginning");
     return NULL;
   }

   size_t certSize = fread(oemCert, 1, oem_cert_size, file_oem_cert);
   if(certSize != oem_cert_size ||
      certSize < oem_cert_size) {
      ERROR("this file:%s has problem", widevine_oem_cert);
      return NULL;
   }

   WidevineOemProvisioning *wvProvision =
       (WidevineOemProvisioning*)calloc(sizeof(WidevineOemProvisioning), 1);
   if(NULL == wvProvision) {
      ERROR("OOM");
      return NULL;
   }

   wvProvision->oemDevicePrivateKey = privateKey;
   wvProvision->oemDevicePrivateKeyLength = private_key_size;
   wvProvision->oemDeviceCertificate = oemCert;
   wvProvision->oemDeviceCertificateLength = oem_cert_size;

   INFO("keyLen : %d", wvProvision->oemDevicePrivateKeyLength);
   INFO("certLen : %d", wvProvision->oemDeviceCertificateLength);

   return wvProvision;
}

static bool readWidevineData(WidevineOemProvisioning **wvProvision) {
   FILE* file_private_key = NULL;
   FILE* file_oem_cert = NULL;
   const char* file_private_key_name = getenv("wievine_oem_privatekey");
   const char* file_cert_name = getenv("widevine_oem_cert");

   INFO("file_private_key_name:%s", file_private_key_name);
   INFO("file_cert_name:%s", file_cert_name);
   if (file_private_key_name == NULL) {
        file_private_key_name = wievine_oem_privatekey;
        if(0 != access(file_private_key_name, F_OK)) {
           ERROR("File does not exist: %s",file_private_key_name);
           return false;
        }
   }

   if (file_cert_name == NULL) {
        file_cert_name = widevine_oem_cert;
        if(0 != access(file_cert_name, F_OK)) {
           ERROR("File does not exist: %s",file_cert_name);
           return false;
        }
   }

   file_private_key = fopen(file_private_key_name, "rb");
   if (NULL == file_private_key) {
       ERROR("file :%s does not exist", file_private_key_name);
       return false;
   }

   file_oem_cert = fopen(file_cert_name, "rb");
   if (NULL == file_oem_cert) {
       ERROR("file :%s does not exist", file_cert_name);
       return false;
   }

   *wvProvision = createWidevineblob(file_private_key, file_oem_cert);

   if(file_private_key)
      fclose(file_private_key);
   if(file_oem_cert)
      fclose(file_oem_cert);

   if(NULL == *wvProvision) {
      ERROR("failed to get wvProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
