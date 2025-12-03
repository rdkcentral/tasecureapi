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
#include "mbedtls_header.h"
#include "porting/rand.h" // NOLINT
#include "hardware_rng.h"  // From util_mbedtls
#include "log.h"
#include <string.h>
#include <threads.h>
#include <stdatomic.h>

// Global DRBG context for random number generation
// CTR-DRBG (Counter mode Deterministic Random Bit Generator)
// Seeds from hardware entropy sources via mbedtls_entropy_func()
// NOTE: With MBEDTLS_THREADING_C enabled, mbedTLS provides internal mutex protection
// for ctr_drbg_random() calls, but we still need application-level protection for
// initialization and to ensure rand_get_drbg_context() callers use it safely.
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static atomic_bool rand_initialized = ATOMIC_VAR_INIT(false);
// Application-level mutex to protect initialization and context access
static mtx_t rand_mutex;
static once_flag rand_once = ONCE_FLAG_INIT;

static void init_rand_mutex(void) {
    if (mtx_init(&rand_mutex, mtx_plain) != thrd_success) {
        ERROR("Failed to initialize rand_mutex");
        // Fatal error - can't proceed without mutex
        abort();
    }
}

/**
 * Platform-specific hardware RNG polling function.
 * 
 * This function provides hardware-backed random number generation.
 * The implementation is provided by util_mbedtls/hardware_rng.c which
 * automatically detects the platform and uses the appropriate RNG source.
 * 
 * Supported platforms (auto-detected):
 * - Linux: /dev/hwrng or /dev/urandom
 * - macOS/BSD: /dev/random
 * - Windows: CryptGenRandom
 * - ARM TrustZone: SMC (if USE_TRUSTZONE_RNG is defined)
 * - x86/x64: RDRAND instruction
 * 
 * This function is now just a wrapper that calls the util_mbedtls implementation.
 * Platform vendors can still override this by compiling with USE_TRUSTZONE_RNG
 * or other platform-specific flags.
 * 
 * @param data - Context data (unused, can be NULL)
 * @param output - Buffer to fill with random bytes
 * @param len - Number of random bytes to generate
 * @param olen - Actual number of bytes written (set to len on success)
 * @return 0 on success, non-zero on failure
 */

// Note: hardware_rng_poll() is now provided by util_mbedtls/src/hardware_rng.c
// The implementation is automatically selected based on the platform.
// No need to define it here unless using inline TrustZone implementation.

static bool rand_init(void) {
    // Ensure mutex is initialized exactly once, thread-safe
    call_once(&rand_once, init_rand_mutex);

    // Fast path: check without locking (atomic read)
    if (atomic_load(&rand_initialized)) {
        return true;
    }

    // Slow path: acquire lock for initialization
    if (mtx_lock(&rand_mutex) != thrd_success) {
        ERROR("Failed to lock rand_mutex for initialization");
        return false;
    }

    // Double-check: another thread might have initialized while we were waiting
    if (atomic_load(&rand_initialized)) {
        mtx_unlock(&rand_mutex);
        return true;
    }

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Register hardware RNG if available (platform-specific implementation)
    // The weak symbol allows vendors to override hardware_rng_poll()
    int ret = mbedtls_entropy_add_source(&entropy, 
                                         hardware_rng_poll,
                                         NULL,  // No context needed
                                         32,    // Minimum entropy threshold (256 bits)
                                         MBEDTLS_ENTROPY_SOURCE_STRONG);
    if (ret != 0) {
        ERROR("Failed to register hardware RNG source: -0x%04x", -ret);
        // Continue anyway - will use platform entropy sources
    }

    const char *personalization = "secapi_rand";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)personalization,
                                strlen(personalization));
    if (ret != 0) {
        ERROR("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mtx_unlock(&rand_mutex);
        return false;
    }

    // Set flag atomically before releasing lock
    atomic_store(&rand_initialized, true);
    mtx_unlock(&rand_mutex);
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

    // Protect global ctr_drbg context from concurrent access
    // This prevents race conditions when 255+ threads call this simultaneously
    if (mtx_lock(&rand_mutex) != thrd_success) {
        ERROR("Failed to lock rand_mutex");
        return false;
    }

    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, out_length);
    
    if (mtx_unlock(&rand_mutex) != thrd_success) {
        ERROR("Failed to unlock rand_mutex");
        return false;
    }

    if (ret != 0) {
        ERROR("mbedtls_ctr_drbg_random failed: -0x%04x", -ret);
        return false;
    }

    return true;
}

void* rand_get_drbg_context(void) {
    if (!rand_init()) {
        ERROR("rand_init failed");
        return NULL;
    }
    
    // Note: Returning raw pointer to ctr_drbg. With MBEDTLS_THREADING_C enabled,
    // mbedTLS functions (like mbedtls_ecp_gen_key) that use this context will
    // automatically acquire internal mutexes when calling mbedtls_ctr_drbg_random().
    // Callers should not hold rand_mutex while using this context to avoid deadlocks.
    return &ctr_drbg;
}
