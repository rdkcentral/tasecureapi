/*
 * Copyright 2019-2025 Comcast Cable Communications Management, LLC
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

/**
 * @file hardware_rng.h
 * 
 * Platform-agnostic hardware random number generator interface.
 * Automatically detects and uses the best available RNG source for the platform.
 */

#ifndef HARDWARE_RNG_H
#define HARDWARE_RNG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * Hardware RNG polling function compatible with mbedTLS entropy source.
 * 
 * This function reads random bytes from the platform's hardware RNG.
 * Implementation is automatically selected based on compile-time platform detection.
 * 
 * Supported platforms:
 * - Linux: /dev/hwrng or /dev/urandom
 * - macOS/BSD: /dev/random
 * - ARM TrustZone: Secure Monitor Call (SMC) - requires USE_TRUSTZONE_RNG=1
 * 
 * @param data   Context pointer (unused, can be NULL)
 * @param output Buffer to fill with random bytes
 * @param len    Number of bytes to generate
 * @param olen   Output: actual number of bytes generated
 * @return 0 on success, non-zero on error
 */
int hardware_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen);

/**
 * Initialize hardware RNG (if needed).
 * Some platforms require initialization before use.
 * 
 * @return 0 on success, non-zero on error
 */
int hardware_rng_init(void);

/**
 * Cleanup hardware RNG resources.
 * Call at shutdown to release any resources.
 */
void hardware_rng_cleanup(void);

/**
 * Get information about the active hardware RNG implementation.
 * 
 * @return String describing the RNG implementation (e.g., "Linux /dev/hwrng")
 */
const char* hardware_rng_get_info(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDWARE_RNG_H */
