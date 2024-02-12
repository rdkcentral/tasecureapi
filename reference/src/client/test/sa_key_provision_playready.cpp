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
/*Note: turn on this if you want to read data from files*/
#define FILE_BASED_FETCH_KEY

#ifdef FILE_BASED_FETCH_KEY
static PlayReadyProvisioning* createPlayreadyblob(FILE *file_private_key,
   FILE *file_oem_cert);
static bool readPlayreadyData(PlayReadyProvisioning **prProvision);
#endif //FILE_BASED_FETCH_KEY
namespace {
   static std::shared_ptr<std::vector<uint8_t>> export_key(
        std::vector<uint8_t>& mixin,
        sa_key key);
}

namespace {
    TEST_P(SaKeyProvisionPlayreadyTest, nominal) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_key;
        sa_elliptic_curve curve;
        auto imported_key = create_sa_key(key_type, key_length,clear_key,curve);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        std::vector<uint8_t> mixin = {};
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        INFO("export_key length : %d", exported_key->size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);

        prProvision->privateKey = exported_key->data();
        prProvision->privateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        sa_status status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision, 
           sizeof(PlayReadyProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
    }

TEST_P(SaKeyProvisionPlayreadyTest, nominalWithMixin) {
        auto key_type = std::get<0>(GetParam());
        auto key_length = std::get<1>(GetParam());

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        std::vector<uint8_t> clear_key;
        sa_elliptic_curve curve;
        auto imported_key = create_sa_key(key_type, key_length,clear_key,curve);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        std::vector<uint8_t> mixin = random(AES_BLOCK_SIZE);
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        INFO("export_key length : %d", exported_key->size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = exported_key->data();
        prProvision->privateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        sa_status status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision,
           sizeof(PlayReadyProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
    }

    TEST_F(SaKeyProvisionPlayreadyTest, simpleCheck) {
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

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = exported_key->data();
        prProvision->privateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        sa_status status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision, 
          sizeof(PlayReadyProvisioning), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
    }
     TEST_F(SaKeyProvisionPlayreadyTest, wrongProvisionType) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        std::vector<uint8_t> mixin = random(AES_BLOCK_SIZE);
        auto exported_key = export_key(mixin, *imported_key);
        ASSERT_NE(nullptr, exported_key);
        INFO("export_key length : %d", exported_key->size());

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = exported_key->data();
        prProvision->privateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, prProvision,
           sizeof(PlayReadyProvisioning), nullptr);

        if(nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }

    TEST_F(SaKeyProvisionPlayreadyTest, failsNoCacheableFlag) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_CACHEABLE);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        size_t out_length = 0;
        sa_status status = sa_key_export(nullptr, &out_length,nullptr,0,*imported_key);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
    TEST_F(SaKeyProvisionPlayreadyTest, failsInvalidMixinLength) {
        auto clear_key = sample_rsa_1024_pkcs8_e3();
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto imported_key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(nullptr, imported_key);
        if(UNSUPPORTED_KEY == *imported_key) {
           GTEST_SKIP() << "key type, key size, or curve not supported";
        }

        //create an exported oem device private key
        auto mixin = random(17);
        auto out = std::vector<uint8_t>(4096);
        size_t out_length = out.size();
        sa_status status = sa_key_export(out.data(), &out_length, mixin.data(),
          mixin.size(),*imported_key);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
 
    TEST_F(SaKeyProvisionPlayreadyTest, failsZeroInLength) {
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

        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        prProvision->privateKey = exported_key->data();
        prProvision->privateKeyLength = exported_key->size();

        //Note: here just provide an examlpe to create certification data and passed
        //into sa_key_provision_ta, how to use certification data is all up to
        //SOC vendors.
        auto certificate = random(CERTIFICATION_LENGTH);
        prProvision->modelCertificate = certificate.data();
        prProvision->modelCertificateLength = CERTIFICATION_LENGTH;

        sa_status status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, prProvision, 0, nullptr);
        if(nullptr != prProvision) {
           delete prProvision;
           prProvision = nullptr;
        }
        ASSERT_NE(status, SA_STATUS_OK);
    }
#ifdef FILE_BASED_FETCH_KEY
 /*there are two file 0331000003310001.key and 0631000006310001.bin under
   tasecureapi/reference/src/client/,
   these files are playready2K private key and certification. you can do
   "export  playready_privatekey=~/PATH/tasecureapi/reference/src/client/0331000003310001.key",
   "export  playready_cert=~/PATH/tasecureapi/reference/src/client/0631000006310001.bin",
   the following test fromFileBased will pick up them and test
  Or
   you just simply copy these two files and put under /opt/drm/
  */
 TEST_F(SaKeyProvisionPlayreadyTest, fromFileBased) {
        PlayReadyProvisioning *prProvision = new PlayReadyProvisioning;
        ASSERT_NE(nullptr, prProvision);
        ASSERT_TRUE(readPlayreadyData(&prProvision));

        sa_status status = sa_key_provision_ta(PLAYREADY_MODEL_PROVISIONING, 
           prProvision, sizeof(prProvision), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        if(nullptr != prProvision->privateKey){
           free(prProvision->privateKey);
           prProvision->privateKey = nullptr;
        }
        if(nullptr != prProvision->modelCertificate){
           free(prProvision->modelCertificate);
           prProvision->modelCertificate = nullptr;
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

#define playready2k_privatekey "/opt/drm/0331000003310001.key"
#define playready2k_cert       "/opt/drm/0631000006310001.bin"
#define playready3k_privatekey "/opt/drm/0331000003310003.key"
#define playready3k_cert       "/opt/drm/0631000006310002.bin"

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

static PlayReadyProvisioning* createPlayreadyblob(FILE *file_private_key, FILE *file_oem_cert) {
   if(NULL == file_private_key ||
      NULL == file_oem_cert) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t private_key_size = 0;
   void *private_key = readBlob(file_private_key, &private_key_size);
   if(NULL == private_key) {
      ERROR("this file :%s has problem", playready2k_privatekey);
      return NULL;
   }
   INFO("private_key_size: %d",private_key_size);

   size_t oem_cert_size = 0;
   void *oem_cert = readBlob(file_oem_cert, &oem_cert_size);
   if(NULL == oem_cert) {
      ERROR("this file :%s has problem", playready2k_privatekey);
      return NULL;
   }
   INFO("oem_cert_size: %d",oem_cert_size);

   PlayReadyProvisioning *prProvision =
       (PlayReadyProvisioning*)calloc(sizeof(PlayReadyProvisioning), 1);
   if(NULL == prProvision) {
      ERROR("OOM");
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
   const char* file_private_key_name = getenv("playready2k_privatekey");
   const char* file_cert_name = getenv("playready2k_cert");

   INFO("file_private_key_name:%s", file_private_key_name);
   INFO("file_cert_name:%s", file_cert_name);
   if (file_private_key_name == NULL) {
        file_private_key_name = playready2k_privatekey;
        if(0 != access(file_private_key_name, F_OK)) {
           ERROR("File does not exist: %s",file_private_key_name);
           return false;
        }
   }

   if (file_cert_name == NULL) {
        file_cert_name = playready2k_cert;
        if(0 != access(file_cert_name, F_OK)) {
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

   if(file_private_key)
      fclose(file_private_key);
   if(file_oem_cert)
      fclose(file_oem_cert);

   if(NULL == *prProvision) {
      ERROR("failed to get prProvision data");
      return false;
   } 
   return true;
}
#endif //FILE_BASED_FETCH_KEY
