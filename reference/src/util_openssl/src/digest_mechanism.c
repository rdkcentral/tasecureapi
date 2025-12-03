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

#include "digest_mechanism.h"
#include "log.h"
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

const EVP_MD* digest_mechanism(sa_digest_algorithm digest_algorithm) {
    const EVP_MD* evp_md = NULL;
    
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            evp_md = EVP_sha1();
            break;

        case SA_DIGEST_ALGORITHM_SHA256:
            evp_md = EVP_sha256();
            break;

        case SA_DIGEST_ALGORITHM_SHA384:
            evp_md = EVP_sha384();
            break;

        case SA_DIGEST_ALGORITHM_SHA512:
            evp_md = EVP_sha512();
            break;

        default:
            break;
    }

    return evp_md;
}

sa_digest_algorithm digest_algorithm_from_evp_md(const EVP_MD* evp_md) {
    if (evp_md == NULL)
        return UINT32_MAX;
    
    int nid = EVP_MD_nid(evp_md);
    switch (nid) {
        case NID_sha1:
            return SA_DIGEST_ALGORITHM_SHA1;
        
        case NID_sha256:
            return SA_DIGEST_ALGORITHM_SHA256;
        
        case NID_sha384:
            return SA_DIGEST_ALGORITHM_SHA384;
        
        case NID_sha512:
            return SA_DIGEST_ALGORITHM_SHA512;
        
        default:
            ERROR("Unknown EVP_MD digest NID: %d", nid);
            return UINT32_MAX;
    }
}
