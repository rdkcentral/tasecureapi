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

#define CERTIFICATE_LENGTH 4096

#ifdef FILE_BASED_FETCH_KEY
#define widevine_oem_privatekey "/keys/widevine_oem_private.key"
#define widevine_oem_cert       "/keys/widevine_oem_cert.bin"
static WidevineOemProvisioning* createWidevineBlob(FILE *file_private_key,
   FILE *file_oem_cert);
static bool readWidevineData(WidevineOemProvisioning **wvProvision);
#endif // FILE_BASED_FETCH_KEY

namespace {
    TEST_P(SaKeyProvisionWidevineTest, nominal) {
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        auto key_length = std::get<0>(GetParam());
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        // Create a rsa key container
        std::string rsa_key_type_string = std::get<1>(GetParam());;
        std::string rsa_key_container;
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
        sa_status status = create_key_container(
             rsa_key_type_string, // key type string
             rsa_key_type, // key type
             clear_rsa_key,
             rsa_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);

        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());
        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        wvProvision->oemDevicePrivateKey = (void*)rsa_key_container.data();
        wvProvision->oemDevicePrivateKeyLength = rsa_key_container.size();

        // Note: Here is an example of creating a test certificate, and passing it into
	// sa_key_provision_ta. Format of keys and certs may vary depending on how 
	// each platform has these data encoded and delivered.
        auto certificate = random(CERTIFICATE_LENGTH);
        wvProvision->oemDeviceCertificate = certificate.data();
        wvProvision->oemDeviceCertificateLength = CERTIFICATE_LENGTH;

        status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, wvProvision,
           sizeof(WidevineOemProvisioning), parameters);

        if (nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
        if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_OK);
    }

    TEST_F(SaKeyProvisionWidevineTest, invalidParameters) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        // Create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";
        std::string rsa_key_container;
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
        sa_status status = create_key_container(
             rsa_key_type_string, // key type string
             rsa_key_type, // key type
             clear_rsa_key,
             rsa_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);

        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        wvProvision->oemDevicePrivateKey = (void*)rsa_key_container.data();
        wvProvision->oemDevicePrivateKeyLength = rsa_key_container.size();

        // Note: Here is an example of creating a test certificate, and passing it into
	// sa_key_provision_ta. Format of keys and certs may vary depending on how 
	// each platform has these data encoded and delivered.
        auto certificate = random(CERTIFICATE_LENGTH);
        wvProvision->oemDeviceCertificate = certificate.data();
        wvProvision->oemDeviceCertificateLength = CERTIFICATE_LENGTH;

        parameters->version = 1;
        status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING,
            wvProvision, sizeof(WidevineOemProvisioning), parameters);

        if (nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
        if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyProvisionWidevineTest, invalidKeyFormat) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        // Create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";
        std::string rsa_key_container;
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
        sa_status status = create_key_container(
             rsa_key_type_string, // key type string
             rsa_key_type, // key type
             clear_rsa_key,
             rsa_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);

        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        wvProvision->oemDevicePrivateKey = (void*)rsa_key_container.data();
        wvProvision->oemDevicePrivateKeyLength = rsa_key_container.size()>>1;

        // Note: Here is an example of creating a test certificate, and passing it into
	// sa_key_provision_ta. Format of keys and certs may vary depending on how 
	// each platform has these data encoded and delivered.
        auto certificate = random(CERTIFICATE_LENGTH);
        wvProvision->oemDeviceCertificate = certificate.data();
        wvProvision->oemDeviceCertificateLength = CERTIFICATE_LENGTH;

        status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING,
            wvProvision, sizeof(WidevineOemProvisioning), parameters);

        if (nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
        if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_INVALID_KEY_FORMAT);
    }

    TEST_F(SaKeyProvisionWidevineTest, wrongProvisionType) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        // Create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";
        std::string rsa_key_container;
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
        sa_status status = create_key_container(
             rsa_key_type_string, // key type string
             rsa_key_type, // key type
             clear_rsa_key,
             rsa_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);

        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        wvProvision->oemDevicePrivateKey = (void*)rsa_key_container.data();
        wvProvision->oemDevicePrivateKeyLength = rsa_key_container.size();

        // Note: Here is an example of creating a test certificate, and passing it into
	// sa_key_provision_ta. Format of keys and certs may vary depending on how 
	// each platform has these data encoded and delivered.
        auto certificate = random(CERTIFICATE_LENGTH);
        wvProvision->oemDeviceCertificate = certificate.data();
        wvProvision->oemDeviceCertificateLength = CERTIFICATE_LENGTH;

        status = sa_key_provision_ta((sa_key_type_ta)(WIDEVINE_OEM_PROVISIONING+6),
	   wvProvision,sizeof(WidevineOemProvisioning), parameters);

        if (nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
        if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaKeyProvisionWidevineTest, FailsZeroInLength) {
        auto key_length = RSA_2048_BYTE_LENGTH;
        std::vector<uint8_t> clear_rsa_key = get_rsa_private_key(key_length);

        // Create a rsa key container
        auto rsa_key_type = SA_KEY_TYPE_RSA;
        std::string rsa_key_type_string = "RSA-2048";
        std::string rsa_key_container;
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
        sa_status status = create_key_container(
             rsa_key_type_string, // key type string
             rsa_key_type, // key type
             clear_rsa_key,
             rsa_key_container,
             SA_SPECIFICATION_MAJOR,
             parameters);
        ASSERT_EQ(SA_STATUS_OK, status);
        INFO("rsa_key_container length : %d", rsa_key_container.size());

        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        wvProvision->oemDevicePrivateKey = (void*)rsa_key_container.data();
        wvProvision->oemDevicePrivateKeyLength = rsa_key_container.size();

        // Note: Here is an example of creating a test certificate, and passing it into
	// sa_key_provision_ta. Format of keys and certs may vary depending on how 
	// each platform has these data encoded and delivered.
        auto certificate = random(CERTIFICATE_LENGTH);
        wvProvision->oemDeviceCertificate = certificate.data();
        wvProvision->oemDeviceCertificateLength = CERTIFICATE_LENGTH;

        status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, wvProvision, 0, parameters);
        if (nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
        if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
        ERROR("status : %d", status);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
#ifdef FILE_BASED_FETCH_KEY
    // There are two file widevine_oem_private.key and widevine_oem_cert.bin under
    // tasecureapi/reference/test/,
    // these files are widevine oem private key and certification. you can do
    // "export  widevine_oem_privatekey=
    // ~/PATH/tasecureapi/reference/test/widevine_oem_private.key",
    // "export  widevine_oem_cert=~/PATH/tasecureapi/reference/test/widevine_oem_cert.bin",
    // the following test fromFileBased will pick up them and test
    // Or
    // you just simply put these two files under /keys.
 TEST_F(SaKeyProvisionWidevineTest, fromFileBased) {
        WidevineOemProvisioning *wvProvision = new WidevineOemProvisioning;
        ASSERT_NE(nullptr, wvProvision);
        ASSERT_TRUE(readWidevineData(&wvProvision));
        sa_import_parameters_soc *parameters = new sa_import_parameters_soc;
        ASSERT_NE(nullptr, parameters);
		
	createParameters(parameters,SA_SPECIFICATION_MAJOR);
        sa_status status = sa_key_provision_ta(WIDEVINE_OEM_PROVISIONING, wvProvision,
           sizeof(wvProvision), parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        if (nullptr != wvProvision->oemDevicePrivateKey){
           free(wvProvision->oemDevicePrivateKey);
           wvProvision->oemDevicePrivateKey = nullptr;
        }
        if (nullptr != wvProvision->oemDeviceCertificate){
           free(wvProvision->oemDeviceCertificate);
           wvProvision->oemDeviceCertificate = nullptr;
        }
        if (nullptr != parameters) {
           delete parameters;
           parameters = nullptr;
        }
	if (nullptr != wvProvision) {
           delete wvProvision;
           wvProvision = nullptr;
        }
    }
#endif // FILE_BASED_FETCH_KEY
} // namespace

#ifdef FILE_BASED_FETCH_KEY
#include <sys/stat.h>
#include <string.h>

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

static WidevineOemProvisioning* createWidevineBlob(FILE *file_private_key,
   FILE *file_oem_cert) {
   if (NULL == file_private_key ||
      NULL == file_oem_cert) {
      ERROR("file pointer do not exist");
      return NULL;
   }

   size_t private_key_size = 0;
   void *private_key = readBlob(file_private_key, &private_key_size);
   if (NULL == private_key) {
      ERROR("this file :%s has problem", widevine_oem_privatekey);
      return NULL;
   }
   INFO("private_key_size: %d", private_key_size);

   size_t oem_cert_size = 0;
   void *oem_cert = readBlob(file_private_key, &oem_cert_size);
   if (NULL == oem_cert) {
      ERROR("this file :%s has problem", widevine_oem_cert);
      return NULL;
   }
   INFO("oem_cert_size: %d", oem_cert_size);

   WidevineOemProvisioning *wvProvision =
       (WidevineOemProvisioning*)calloc(sizeof(WidevineOemProvisioning), 1);
   if (NULL == wvProvision) {
      ERROR("calloc failed");
      return NULL;
   }

   wvProvision->oemDevicePrivateKey = private_key;
   wvProvision->oemDevicePrivateKeyLength = private_key_size;
   wvProvision->oemDeviceCertificate = oem_cert;
   wvProvision->oemDeviceCertificateLength = oem_cert_size;

   INFO("keyLen : %d", wvProvision->oemDevicePrivateKeyLength);
   INFO("certLen : %d", wvProvision->oemDeviceCertificateLength);

   return wvProvision;
}

static bool readWidevineData(WidevineOemProvisioning **wvProvision) {
   FILE* file_private_key = NULL;
   FILE* file_oem_cert = NULL;
   const char* file_private_key_name = getenv("widevine_oem_privatekey");
   const char* file_cert_name = getenv("widevine_oem_cert");

   INFO("file_private_key_name:%s", file_private_key_name);
   INFO("file_cert_name:%s", file_cert_name);
   if (file_private_key_name == NULL) {
      file_private_key_name = widevine_oem_privatekey;
      if (0 != access(file_private_key_name, F_OK)) {
          ERROR("File does not exist: %s",file_private_key_name);
          return false;
      }
   }

   if (file_cert_name == NULL) {
      file_cert_name = widevine_oem_cert;
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
   *wvProvision = createWidevineBlob(file_private_key, file_oem_cert);

   if (file_private_key)
      fclose(file_private_key);
   if (file_oem_cert)
      fclose(file_oem_cert);

   if (NULL == *wvProvision) {
      ERROR("failed to get wvProvision data");
      return false;
   } 
   return true;
}
#endif // FILE_BASED_FETCH_KEY
