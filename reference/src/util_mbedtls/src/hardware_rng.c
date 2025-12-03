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

#include "hardware_rng.h"
#include <string.h>

// ============================================================================
// Platform Detection and Configuration
// ============================================================================
// Supported platforms: Linux, macOS, ARM TrustZone

// Detect operating system
#if defined(__linux__) || defined(__linux) || defined(linux)
    #define PLATFORM_LINUX 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define PLATFORM_MACOS 1
#elif defined(__ANDROID__)
    #define PLATFORM_ANDROID 1
    #define PLATFORM_LINUX 1  // Android is Linux-based
#endif

// Detect ARM TrustZone support
#if defined(USE_TRUSTZONE_RNG) && (defined(__ARM_ARCH) || defined(__arm__) || defined(__aarch64__))
    #define PLATFORM_TRUSTZONE 1
#endif

// ============================================================================
// Linux Implementation
// ============================================================================
#if defined(PLATFORM_LINUX) && !defined(PLATFORM_TRUSTZONE)

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static int hwrng_fd = -1;
static const char *rng_source = NULL;

int hardware_rng_init(void) {
    if (hwrng_fd >= 0) {
        return 0;  // Already initialized
    }
    
    // Try /dev/hwrng first (dedicated hardware RNG)
    hwrng_fd = open("/dev/hwrng", O_RDONLY | O_NONBLOCK);
    if (hwrng_fd >= 0) {
        rng_source = "/dev/hwrng";
        return 0;
    }
    
    // Fallback to /dev/urandom (kernel CSPRNG, may use hardware)
    hwrng_fd = open("/dev/urandom", O_RDONLY);
    if (hwrng_fd >= 0) {
        rng_source = "/dev/urandom";
        return 0;
    }
    
    rng_source = "none";
    return -1;
}

void hardware_rng_cleanup(void) {
    if (hwrng_fd >= 0) {
        close(hwrng_fd);
        hwrng_fd = -1;
    }
}

int hardware_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    
    if (hwrng_fd < 0) {
        if (hardware_rng_init() != 0) {
            *olen = 0;
            return 0;  // Not critical error, just no entropy
        }
    }
    
    ssize_t bytes_read = read(hwrng_fd, output, len);
    
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Non-blocking mode, no data available yet
            *olen = 0;
            return 0;
        }
        *olen = 0;
        return -1;
    }
    
    *olen = (size_t)bytes_read;
    return 0;
}

const char* hardware_rng_get_info(void) {
    if (rng_source == NULL) {
        hardware_rng_init();
    }
    return rng_source ? rng_source : "uninitialized";
}

// ============================================================================
// macOS/BSD Implementation
// ============================================================================
#elif defined(PLATFORM_MACOS)

#include <fcntl.h>
#include <unistd.h>

static int random_fd = -1;

int hardware_rng_init(void) {
    if (random_fd >= 0) {
        return 0;
    }
    
    // macOS/BSD use /dev/random (non-blocking, cryptographically secure)
    random_fd = open("/dev/random", O_RDONLY);
    return (random_fd >= 0) ? 0 : -1;
}

void hardware_rng_cleanup(void) {
    if (random_fd >= 0) {
        close(random_fd);
        random_fd = -1;
    }
}

int hardware_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    
    if (random_fd < 0) {
        if (hardware_rng_init() != 0) {
            *olen = 0;
            return 0;
        }
    }
    
    ssize_t bytes_read = read(random_fd, output, len);
    
    if (bytes_read < 0) {
        *olen = 0;
        return -1;
    }
    
    *olen = (size_t)bytes_read;
    return 0;
}

const char* hardware_rng_get_info(void) {
    return "macOS/BSD /dev/random";
}

// ============================================================================
// ARM TrustZone Implementation
// ============================================================================
#elif defined(PLATFORM_TRUSTZONE)

#include <stdint.h>

#ifndef SMC_RNG_GET_RANDOM
    // Default SMC function ID - may need adjustment for specific platforms
    #if defined(__aarch64__)
        #define SMC_RNG_GET_RANDOM 0xC2000001  // ARMv8 64-bit
    #else
        #define SMC_RNG_GET_RANDOM 0x84000001  // ARMv7 32-bit
    #endif
#endif

#if defined(__aarch64__) || defined(__ARM_ARCH_8A) || defined(__ARM_ARCH_8__)
// ARMv8 64-bit
static inline unsigned long smc_call(unsigned long func_id, 
                                    unsigned long arg1,
                                    unsigned long arg2, 
                                    unsigned long arg3) {
    register unsigned long x0 asm("x0") = func_id;
    register unsigned long x1 asm("x1") = arg1;
    register unsigned long x2 asm("x2") = arg2;
    register unsigned long x3 asm("x3") = arg3;
    
    asm volatile("smc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3) : "memory");
    
    return x0;
}
#else
// ARMv7 32-bit
static inline uint32_t smc_call(uint32_t func_id, 
                                uint32_t arg1,
                                uint32_t arg2, 
                                uint32_t arg3) {
    register uint32_t r0 asm("r0") = func_id;
    register uint32_t r1 asm("r1") = arg1;
    register uint32_t r2 asm("r2") = arg2;
    register uint32_t r3 asm("r3") = arg3;
    
    asm volatile("smc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3) : "memory");
    
    return r0;
}
#endif

int hardware_rng_init(void) {
    return 0;  // No initialization needed for SMC
}

void hardware_rng_cleanup(void) {
    // No cleanup needed
}

int hardware_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    
    unsigned long result = smc_call(SMC_RNG_GET_RANDOM, 
                                   (unsigned long)output,
                                   (unsigned long)len,
                                   0);
    
    if (result == 0) {
        *olen = len;
        return 0;
    }
    
    *olen = 0;
    return -1;
}

const char* hardware_rng_get_info(void) {
    #if defined(__aarch64__)
        return "ARM TrustZone SMC (ARMv8 64-bit)";
    #else
        return "ARM TrustZone SMC (ARMv7 32-bit)";
    #endif
}

// ============================================================================
// Fallback: No Hardware RNG
// ============================================================================
#else

int hardware_rng_init(void) {
    return 0;
}

void hardware_rng_cleanup(void) {
}

int hardware_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    (void)output;
    (void)len;
    
    *olen = 0;
    return 0;  // No hardware RNG available
}

const char* hardware_rng_get_info(void) {
    return "No hardware RNG (using mbedTLS defaults)";
}

#endif
