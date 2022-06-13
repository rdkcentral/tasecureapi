/**
* Copyright 2022 Comcast Cable Communications Management, LLC
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

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000

#include "sa_engine_internal.h"
#include "sa_log.h"
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <memory.h>
#endif

static int pkey_asn1_nids[] = {EVP_PKEY_SYM};
static int pkey_asn1_nids_num = (sizeof(pkey_asn1_nids) / sizeof(pkey_asn1_nids[0]));
static EVP_PKEY_ASN1_METHOD* sym_pkey_asn1_method = NULL;

static int pkey_asn1_size(const EVP_PKEY* evp_pkey) {
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    pkey_data* data = EVP_PKEY_get0((EVP_PKEY*)evp_pkey);
    if (data == NULL) {
        ERROR("NULL data");
        return 0;
    }

    return data->header.size;
}

static int pkey_asn1_bits(const EVP_PKEY* evp_pkey) {
    return pkey_asn1_size(evp_pkey) * 8;
}

static void pkey_asn1_free(EVP_PKEY* evp_pkey) {
    if (evp_pkey != NULL) {
        pkey_data* data = EVP_PKEY_get0(evp_pkey);
        if (data != NULL)
            OPENSSL_free(data);
    }
}

static int pkey_asn1_ctrl(
        EVP_PKEY* evp_pkey,
        int command,
        long p1,
        void* p2) {

    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int type = EVP_PKEY_id(evp_pkey);
    if (command == ASN1_PKEY_CTRL_DEFAULT_MD_NID) {
        if (type == EVP_PKEY_SYM)
            *((int*) p2) = 0;
        else
            *((int*) p2) = NID_sha256;

        return 1;
    }

    return 0;
}

static int pkey_asn1_set_priv_key(
        EVP_PKEY* evp_pkey,
        const unsigned char* private_key,
        size_t private_key_length) {

    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    if (private_key_length != sizeof(pkey_data)) {
        ERROR("Invalid private key");
        return 0;
    }

    int result = 0;
    pkey_data* data = NULL;
    do {
        data = OPENSSL_malloc(sizeof(pkey_data));
        if (data == NULL) {
            ERROR("OPENSSL_malloc failed");
            break;
        }

        memcpy(data, private_key, private_key_length);
        if (EVP_PKEY_assign(evp_pkey, EVP_PKEY_SYM, data) != 1) {
            ERROR("EVP_PKEY_assign failed");
            break;
        }

        // data is assigned to the pkey.
        data = NULL;
        result = 1;
    } while (false);

    if (data != NULL)
        OPENSSL_free(data);

    return result;
}

static EVP_PKEY_ASN1_METHOD* get_pkey_asn1_method(
        int nid,
        const char* pem_str) {
    EVP_PKEY_ASN1_METHOD* evp_pkey_asn1_method = EVP_PKEY_asn1_new(nid, 0, pem_str, NULL);
    if (evp_pkey_asn1_method != NULL) {
        EVP_PKEY_asn1_set_public(evp_pkey_asn1_method, NULL, NULL, NULL, NULL, pkey_asn1_size, pkey_asn1_bits);
        EVP_PKEY_asn1_set_free(evp_pkey_asn1_method, pkey_asn1_free);
        EVP_PKEY_asn1_set_ctrl(evp_pkey_asn1_method, pkey_asn1_ctrl);
        EVP_PKEY_asn1_set_set_priv_key(evp_pkey_asn1_method, pkey_asn1_set_priv_key);
        if (EVP_PKEY_asn1_add0(evp_pkey_asn1_method) != 1) {
            ERROR("EVP_PKEY_asn1_add0 failed");
            EVP_PKEY_asn1_free(evp_pkey_asn1_method);
            return NULL;
        }
    }

    return evp_pkey_asn1_method;
}

int sa_get_engine_pkey_asn1_meths(
        ENGINE* engine,
        EVP_PKEY_ASN1_METHOD** method,
        const int** nids,
        int nid) {

    if (mtx_lock(&engine_mutex) != 0) {
        ERROR("mtx_lock failed");
        return 0;
    }

    if (sym_pkey_asn1_method == NULL)
        sym_pkey_asn1_method = get_pkey_asn1_method(EVP_PKEY_SYM, EVP_PKEY_SYM_NAME);


    if (!method) {
        if (nids == NULL)
            return 0;

        *nids = pkey_asn1_nids;
        return pkey_asn1_nids_num;
    }

    if (nid == EVP_PKEY_SYM)
        *method = sym_pkey_asn1_method;
    else
        *method = NULL;

    mtx_unlock(&engine_mutex);
    return *method == NULL ? 0 : 1;
}

#endif
