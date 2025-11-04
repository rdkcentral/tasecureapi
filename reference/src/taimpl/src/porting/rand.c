/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

#include "pkcs12_mbedtls.h"
#include "porting/rand.h" // NOLINT
#include "log.h"

// Global DRBG context for random number generation
// CTR-DRBG (Counter mode Deterministic Random Bit Generator)
// Seeds from hardware entropy sources via mbedtls_entropy_func()
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static bool rand_initialized = false;

static bool rand_init(void) {
    if (rand_initialized) {
        return true;
    }

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char *personalization = "secapi_rand";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)personalization,
                                    strlen(personalization));
    if (ret != 0) {
        ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    rand_initialized = true;
    return true;
}

bool rand_bytes(void* out, size_t out_length) {
    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (!rand_init()) {
        ERROR("rand_init failed");
        return false;
    }

    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, out_length);
    if (ret != 0) {
        ERROR("mbedtls_ctr_drbg_random failed: -0x%04x", -ret);
        return false;
    }

    return true;
}
