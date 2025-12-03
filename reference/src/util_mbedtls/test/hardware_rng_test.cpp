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
#include "gtest/gtest.h"
#include <string.h>
#include <set>
#include <vector>

/**
 * Test fixture for hardware RNG tests
 */
class HardwareRngTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize RNG before each test
        init_result = hardware_rng_init();
    }

    void TearDown() override {
        // Cleanup after each test
        hardware_rng_cleanup();
    }

    int init_result;
};

/**
 * Test: Initialization succeeds or gracefully fails
 */
TEST_F(HardwareRngTest, InitializationSucceedsOrFails) {
    // Init should return 0 (success) or -1 (no hardware RNG)
    // Either is acceptable
    EXPECT_TRUE(init_result == 0 || init_result == -1);
    
    // Print RNG info for debugging
    const char* info = hardware_rng_get_info();
    ASSERT_NE(info, nullptr);
    std::cout << "Hardware RNG: " << info << std::endl;
}

/**
 * Test: Can generate random bytes
 */
TEST_F(HardwareRngTest, GeneratesRandomBytes) {
    unsigned char buffer[32];
    size_t olen = 0;
    
    memset(buffer, 0, sizeof(buffer));
    
    int result = hardware_rng_poll(nullptr, buffer, sizeof(buffer), &olen);
    
    // Function should succeed (0) or indicate no entropy available
    EXPECT_EQ(result, 0);
    
    // If hardware RNG is available, olen should be > 0
    // If not available, olen will be 0
    if (olen > 0) {
        EXPECT_LE(olen, sizeof(buffer));
        
        // Check that not all bytes are zero (extremely unlikely with real RNG)
        bool has_nonzero = false;
        for (size_t i = 0; i < olen; i++) {
            if (buffer[i] != 0) {
                has_nonzero = true;
                break;
            }
        }
        EXPECT_TRUE(has_nonzero) << "All random bytes are zero - suspicious!";
    } else {
        std::cout << "Note: Hardware RNG returned 0 bytes (no hardware RNG available)" << std::endl;
    }
}

/**
 * Test: Multiple calls generate different data
 */
TEST_F(HardwareRngTest, GeneratesDifferentData) {
    unsigned char buffer1[32];
    unsigned char buffer2[32];
    size_t olen1 = 0, olen2 = 0;
    
    int result1 = hardware_rng_poll(nullptr, buffer1, sizeof(buffer1), &olen1);
    int result2 = hardware_rng_poll(nullptr, buffer2, sizeof(buffer2), &olen2);
    
    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 0);
    
    if (olen1 > 0 && olen2 > 0) {
        // Buffers should be different (probability of same is ~2^-256)
        bool are_different = (memcmp(buffer1, buffer2, std::min(olen1, olen2)) != 0);
        EXPECT_TRUE(are_different) << "Two consecutive random calls returned identical data!";
    }
}

/**
 * Test: Can generate various sizes
 */
TEST_F(HardwareRngTest, GeneratesVariousSizes) {
    const size_t sizes[] = {1, 16, 32, 64, 128, 256, 1024};
    
    for (size_t size : sizes) {
        std::vector<unsigned char> buffer(size);
        size_t olen = 0;
        
        int result = hardware_rng_poll(nullptr, buffer.data(), size, &olen);
        
        EXPECT_EQ(result, 0) << "Failed for size " << size;
        
        if (olen > 0) {
            EXPECT_LE(olen, size) << "Generated more bytes than requested for size " << size;
        }
    }
}

/**
 * Test: NULL output pointer is handled safely
 */
TEST_F(HardwareRngTest, HandlesNullOutputPointer) {
    size_t olen = 999;  // Initialize with garbage
    
    // This should not crash - implementation should check for NULL
    int result = hardware_rng_poll(nullptr, nullptr, 32, &olen);
    
    // Function should handle this gracefully
    // Either return error or set olen to 0
    if (result != 0) {
        // Error return is acceptable
        EXPECT_NE(result, 0);
    } else {
        // If success, should have set olen to 0
        EXPECT_EQ(olen, 0);
    }
}

/**
 * Test: Zero length request
 */
TEST_F(HardwareRngTest, HandlesZeroLengthRequest) {
    unsigned char buffer[32];
    size_t olen = 999;
    
    int result = hardware_rng_poll(nullptr, buffer, 0, &olen);
    
    EXPECT_EQ(result, 0);
    EXPECT_EQ(olen, 0);
}

/**
 * Test: Repeated init/cleanup doesn't cause issues
 */
TEST_F(HardwareRngTest, RepeatedInitCleanup) {
    for (int i = 0; i < 10; i++) {
        hardware_rng_cleanup();
        int result = hardware_rng_init();
        EXPECT_TRUE(result == 0 || result == -1);
    }
}

/**
 * Test: Get info returns valid string
 */
TEST_F(HardwareRngTest, GetInfoReturnsValidString) {
    const char* info = hardware_rng_get_info();
    
    ASSERT_NE(info, nullptr);
    EXPECT_GT(strlen(info), 0);
    
    std::cout << "RNG Implementation: " << info << std::endl;
}

/**
 * Statistical Test: Basic randomness check
 * This is NOT a comprehensive randomness test, just a sanity check
 */
TEST_F(HardwareRngTest, BasicRandomnessCheck) {
    const size_t num_samples = 1000;
    const size_t sample_size = 1;
    unsigned char samples[num_samples];
    size_t olen;
    
    // Generate samples
    for (size_t i = 0; i < num_samples; i++) {
        int result = hardware_rng_poll(nullptr, &samples[i], sample_size, &olen);
        ASSERT_EQ(result, 0);
        
        if (olen == 0) {
            // No hardware RNG available, skip this test
            GTEST_SKIP() << "No hardware RNG available for statistical testing";
            return;
        }
    }
    
    // Count unique values
    std::set<unsigned char> unique_values(samples, samples + num_samples);
    
    // With 1000 random bytes, we should see at least 100 different values
    // (expected: ~181 unique values for perfect randomness)
    EXPECT_GE(unique_values.size(), 100) 
        << "Random data has very low diversity - only " 
        << unique_values.size() << " unique values in 1000 samples";
    
    // Check that we don't have too much repetition
    // Count most frequent byte
    unsigned int counts[256] = {0};
    for (unsigned char sample : samples) {
        counts[sample]++;
    }
    
    unsigned int max_count = 0;
    for (unsigned int count : counts) {
        if (count > max_count) {
            max_count = count;
        }
    }
    
    // Most frequent byte should appear less than 2% of the time (20 times out of 1000)
    // This is a very loose check - real random should be around 0.4%
    EXPECT_LT(max_count, 20) 
        << "Random data shows bias - one byte appears " << max_count << " times";
}

/**
 * Test: Integration with mbedTLS entropy context
 */
TEST_F(HardwareRngTest, IntegrationWithMbedtls) {
    // This test verifies the function signature is compatible with mbedTLS
    unsigned char buffer[32];
    size_t olen = 0;
    
    // Call exactly as mbedTLS would call it
    int result = hardware_rng_poll(nullptr, buffer, sizeof(buffer), &olen);
    
    // Return value should be 0 (mbedTLS expects 0 on success)
    EXPECT_EQ(result, 0);
    
    // olen should be set (either to actual bytes or 0)
    EXPECT_LE(olen, sizeof(buffer));
}

/**
 * Performance Test: Measure throughput
 */
TEST_F(HardwareRngTest, PerformanceTest) {
    const size_t total_bytes = 1024 * 1024;  // 1 MB
    const size_t buffer_size = 1024;
    unsigned char buffer[buffer_size];
    size_t total_generated = 0;
    size_t olen;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    while (total_generated < total_bytes) {
        size_t request_size = std::min(buffer_size, total_bytes - total_generated);
        
        int result = hardware_rng_poll(nullptr, buffer, request_size, &olen);
        ASSERT_EQ(result, 0);
        
        if (olen == 0) {
            GTEST_SKIP() << "No hardware RNG available for performance testing";
            return;
        }
        
        total_generated += olen;
        
        // Avoid infinite loop if RNG returns less than requested
        if (olen < request_size) {
            break;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    if (duration.count() > 0) {
        double mbps = (total_generated / 1024.0 / 1024.0) / (duration.count() / 1000.0);
        std::cout << "Hardware RNG throughput: " << mbps << " MB/s" << std::endl;
        std::cout << "Generated " << total_generated << " bytes in " 
                  << duration.count() << " ms" << std::endl;
    }
}
