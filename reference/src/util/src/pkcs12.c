/*
 * Copyright 2022-2025 Comcast Cable Communications Management, LLC
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

#include "common.h"
#include "log.h"
#include "root_keystore.h"
#include <openssl/pkcs12.h>
#include <stdbool.h>
#include <stdio.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <memory.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000
#include <stdint.h>
#endif
#endif

static int find_asn1_item_length(const uint8_t* data, int* offset) {
    int length = 0;
    if ((data[*offset] & 0x80) == 0x80) {
        int length_bytes = data[*offset] & 0x7f;
        for (int i = length_bytes; i > 0; i--) {
            length = (length << 8) + data[++(*offset)];
        }
    } else {
        length = data[*offset];
    }

    (*offset)++;
    return length;
}

static int parse_pkcs12_safe_bag(
        PKCS12_SAFEBAG* pkcs12_safebag,
        const char* password,
        void* key,
        size_t* key_length,
        char* name,
        size_t* name_length) {

    if (key == NULL) {
        ERROR("NULL key");
        return 0;
    }

    if (key_length == NULL) {
        ERROR("NULL key_length");
        return 0;
    }

    if (name == NULL) {
        ERROR("NULL name");
        return 0;
    }

    if (name_length == NULL) {
        ERROR("NULL name_length");
        return 0;
    }

    int result = 0;
    uint8_t* bag_name = NULL;
    size_t bag_name_length;
    ASN1_OCTET_STRING* octet_string = NULL;
    uint8_t* secret_bag_data = NULL;
    X509_SIG* x509_sig = NULL;
    PKCS8_PRIV_KEY_INFO* priv_key_info = NULL;
    do {

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        const ASN1_TYPE* attrib = PKCS12_SAFEBAG_get0_attr(pkcs12_safebag, NID_friendlyName);
#else
        const ASN1_TYPE* attrib = PKCS12_get_attr_gen(pkcs12_safebag->attrib, NID_friendlyName);
#endif
        if (attrib == NULL) {
            ERROR("name too short");
            return 0;
        }

        bag_name_length = ASN1_STRING_to_UTF8(&bag_name, attrib->value.bmpstring);
        if (bag_name != NULL && bag_name_length > 0 && bag_name_length <= *name_length) {
            memcpy(name, bag_name, bag_name_length);
            *name_length = bag_name_length;
        } else {
            *name_length = 0;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        int bag_nid = PKCS12_SAFEBAG_get_nid(pkcs12_safebag);
#else
        int bag_nid = OBJ_obj2nid(pkcs12_safebag->type);
#endif
        if (bag_nid == NID_secretBag) {
            // OpenSSL doesn't support SecretBags and the APIs to find the SecretBag data are only available in OpenSSL
            // 3.0. So convert the SecretBag into DER encoded bytes and find the start of the data by scanning.
            int length = i2d_PKCS12_SAFEBAG(pkcs12_safebag, &secret_bag_data);
            if (length <= 0) {
                ERROR("NULL der_x509_sig");
                break;
            }

            // Find two A0 tags.
            int offset = 0;
            for (int i = 0; i < 2; i++) {
                for (uint8_t tag = secret_bag_data[offset]; tag != (V_ASN1_CONTEXT_SPECIFIC | V_ASN1_CONSTRUCTED);
                        tag = secret_bag_data[offset]) {
                    offset++;
                    int asn1_item_length = find_asn1_item_length(secret_bag_data, &offset);
                    tag &= 0x1f;
                    if (tag != V_ASN1_SEQUENCE)
                        offset += asn1_item_length;
                }

                offset++;
                find_asn1_item_length(secret_bag_data, &offset);
            }

            // Now read the octet string header.
            if (secret_bag_data[offset] != V_ASN1_OCTET_STRING) {
                ERROR("Malformed secret bag");
                break;
            }

            offset++;
            int secret_data_length = find_asn1_item_length(secret_bag_data, &offset);

            const unsigned char* p_data = secret_bag_data + offset;
            octet_string = ASN1_OCTET_STRING_new();
            ASN1_OCTET_STRING_set(octet_string, p_data, secret_data_length);
            x509_sig = ASN1_item_unpack(octet_string, ASN1_ITEM_rptr(X509_SIG));
            priv_key_info = PKCS8_decrypt(x509_sig, password, -1);
            if (priv_key_info == NULL) {
                ERROR("NULL priv_key_info");
                break;
            }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
            const ASN1_OBJECT* asn1_object = NULL;
            const X509_ALGOR* x509_algor = NULL;
#else
            ASN1_OBJECT* asn1_object = NULL;
            X509_ALGOR* x509_algor = NULL;
#endif
            const uint8_t* secret_key = NULL;
            int secret_key_length = 0;
            if (PKCS8_pkey_get0(&asn1_object, &secret_key, &secret_key_length, &x509_algor, priv_key_info) != 1) {
                ERROR("PKCS8_pkey_get0 failed");
                break;
            }

            memcpy(key, secret_key, secret_key_length);
            *key_length = secret_key_length;
        } else {
            ERROR("Found keyBag");
            break;
        }

        result = 1;
    } while (false);

    OPENSSL_free(bag_name);
    ASN1_OCTET_STRING_free(octet_string);
    OPENSSL_free(secret_bag_data);
    X509_SIG_free(x509_sig);
    PKCS8_PRIV_KEY_INFO_free(priv_key_info);

    return result;
}

bool load_pkcs12_secret_key(
        void* key,
        size_t* key_length,
        char* name,
        size_t* name_length) {

    const char* password = getenv("ROOT_KEYSTORE_PASSWORD");
    if (password == NULL)
        password = DEFAULT_ROOT_KEYSTORE_PASSWORD;

    size_t in_name_length = *name_length;
    bool requested_common_root = strncmp(name, COMMON_ROOT_NAME, in_name_length) == 0;
    bool status = false;
    FILE* file = NULL;
    PKCS12* pkcs12 = NULL;
    STACK_OF(PKCS7)* auth_safes = NULL;
    do {
        const char* filename = getenv("ROOT_KEYSTORE");
        if (filename != NULL) {
            file = fopen(filename, "re");
            if (file == NULL) {
                ERROR("NULL file");
                break;
            }

            pkcs12 = d2i_PKCS12_fp(file, NULL);
            if (pkcs12 == NULL) {
                ERROR("NULL pkcs12");
                break;
            }
        } else {
            const uint8_t *keystore = default_root_keystore;
            pkcs12 = d2i_PKCS12(NULL, &keystore, sizeof default_root_keystore);
            if (pkcs12 == NULL) {
                ERROR("NULL pkcs12");
                break;
            }
        }

        if (PKCS12_verify_mac(pkcs12, password, -1) != 1) {
            ERROR("PKCS12_verify_mac failed");
            break;
        }

        auth_safes = PKCS12_unpack_authsafes(pkcs12);
        if (auth_safes == NULL) {
            ERROR("PKCS12_unpack_authsafes failed");
            break;
        }

        bool pkcs12_parse_failed = false;
        STACK_OF(PKCS12_SAFEBAG)* pkcs12_safebags = NULL;
        for (int i = 0; !pkcs12_parse_failed && i < sk_PKCS7_num(auth_safes); i++) {
            PKCS7* pkcs7 = sk_PKCS7_value(auth_safes, i);
            int bag_nid = OBJ_obj2nid(pkcs7->type);

            if (bag_nid == NID_pkcs7_data)
                pkcs12_safebags = PKCS12_unpack_p7data(pkcs7);
            else if (bag_nid == NID_pkcs7_encrypted)
                pkcs12_safebags = PKCS12_unpack_p7encdata(pkcs7, password, -1);
            else {
                ERROR("unknown bag_nid");
                pkcs12_parse_failed = true;
            }

            for (int j = 0; !pkcs12_parse_failed && j < sk_PKCS12_SAFEBAG_num(pkcs12_safebags); j++) {
                PKCS12_SAFEBAG* pkcs12_safebag = sk_PKCS12_SAFEBAG_value(pkcs12_safebags, j);
                if (parse_pkcs12_safe_bag(pkcs12_safebag, password, key, key_length, name, name_length) != 1) {
                    pkcs12_parse_failed = true;
                    ERROR("parse_pkcs12_safe_bag failed");
                }

                bool is_common_root = strncmp(COMMON_ROOT_NAME, name, strlen(COMMON_ROOT_NAME)) == 0;
                if (is_common_root == requested_common_root) {
                    status = true;
                    break;
                }
            }

            sk_PKCS12_SAFEBAG_pop_free(pkcs12_safebags, PKCS12_SAFEBAG_free);
        }
    } while (false);

    PKCS12_free(pkcs12);
    sk_PKCS7_pop_free(auth_safes, PKCS7_free);
    if (file != NULL)
        fclose(file);

    return status;
}
