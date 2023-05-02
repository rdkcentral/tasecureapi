/*
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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

#include "sa_engine_internal.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000
#if OPENSSL_VERSION_NUMBER < 0x10100000
#include <memory.h>
#endif

static int digest_nids[] = {
        NID_sha1,
        NID_sha256,
        NID_sha384,
        NID_sha512,
        NID_undef};

static int digest_nids_num = (sizeof(digest_nids) / sizeof(digest_nids[0]));

static EVP_MD* digest_sha1 = NULL;
static EVP_MD* digest_sha256 = NULL;
static EVP_MD* digest_sha384 = NULL;
static EVP_MD* digest_sha512 = NULL;
static EVP_MD* digest_undef = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define EVP_MD_meth_set_app_datasize(x, y) x->ctx_size = (y)
#define EVP_MD_meth_free(x) OPENSSL_free(x)

EVP_MD* EVP_MD_meth_dup(const EVP_MD* md) {
    EVP_MD* to = OPENSSL_malloc(sizeof(EVP_MD));
    memcpy(to, md, sizeof(EVP_MD));
    return to;
}
#endif

int sa_get_engine_digests(
        ossl_unused ENGINE* engine,
        const EVP_MD** evp_md,
        const int** nids,
        int nid) {

    if (!evp_md) {
        if (nids == NULL)
            return 0;

        *nids = digest_nids;
        return digest_nids_num;
    }

    // Setting the app datasize to work around a problem in OpenSSL 3.
    if (nid == NID_sha1) {
        if (digest_sha1 == NULL) {
            digest_sha1 = EVP_MD_meth_dup(EVP_sha1());
            EVP_MD_meth_set_app_datasize(digest_sha1, 104);
        }

        *evp_md = digest_sha1;
    } else if (nid == NID_sha256) {
        if (digest_sha256 == NULL) {
            digest_sha256 = EVP_MD_meth_dup(EVP_sha256());
            EVP_MD_meth_set_app_datasize(digest_sha256, 120);
        }

        *evp_md = digest_sha256;
    } else if (nid == NID_sha384) {
        if (digest_sha384 == NULL) {
            digest_sha384 = EVP_MD_meth_dup(EVP_sha384());
            EVP_MD_meth_set_app_datasize(digest_sha384, 224);
        }

        *evp_md = digest_sha384;
    } else if (nid == NID_sha512) {
        if (digest_sha512 == NULL) {
            digest_sha512 = EVP_MD_meth_dup(EVP_sha512());
            EVP_MD_meth_set_app_datasize(digest_sha512, 224);
        }

        *evp_md = digest_sha512;
    } else if (nid == NID_undef) {
        if (digest_undef == NULL) {
            digest_undef = EVP_MD_meth_dup(EVP_md_null());
            EVP_MD_meth_set_app_datasize(digest_undef, 64);
        }

        *evp_md = digest_undef;
    } else {
        *evp_md = NULL;
    }

    return *evp_md == NULL ? 0 : 1;
}

void sa_free_engine_digests() {
    EVP_MD_meth_free(digest_sha1);
    digest_sha1 = NULL;

    EVP_MD_meth_free(digest_sha256);
    digest_sha256 = NULL;

    EVP_MD_meth_free(digest_sha384);
    digest_sha384 = NULL;

    EVP_MD_meth_free(digest_sha512);
    digest_sha512 = NULL;

    EVP_MD_meth_free(digest_undef);
    digest_undef = NULL;
}

#endif
