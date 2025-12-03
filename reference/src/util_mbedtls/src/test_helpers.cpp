/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

#include "test_helpers.h"
#include "digest_util.h"
#include "digest_util_mbedtls.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include <cstring>

namespace test_helpers_mbedtls {

std::vector<uint8_t> random(size_t size) {
    std::vector<uint8_t> result(size);
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    const char* personalization = "test_helpers";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char*)personalization,
                          strlen(personalization));
    
    mbedtls_ctr_drbg_random(&ctr_drbg, result.data(), size);
    
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return result;
}

std::vector<uint8_t> digest(
        sa_digest_algorithm digest_algorithm,
        const std::vector<uint8_t>& in1,
        const std::vector<uint8_t>& in2,
        const std::vector<uint8_t>& in3) {

    mbedtls_md_type_t md_type = digest_mechanism_mbedtls(digest_algorithm);
    if (md_type == MBEDTLS_MD_NONE) {
        return {};
    }

    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == nullptr) {
        return {};
    }

    size_t digest_length = mbedtls_md_get_size(md_info);
    std::vector<uint8_t> result(digest_length);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return {};
    }

    mbedtls_md_starts(&ctx);
    
    if (!in1.empty()) {
        mbedtls_md_update(&ctx, in1.data(), in1.size());
    }
    
    if (!in2.empty()) {
        mbedtls_md_update(&ctx, in2.data(), in2.size());
    }
    
    if (!in3.empty()) {
        mbedtls_md_update(&ctx, in3.data(), in3.size());
    }
    
    mbedtls_md_finish(&ctx, result.data());
    mbedtls_md_free(&ctx);
    
    return result;
}

} // namespace test_helpers_mbedtls
