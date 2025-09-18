/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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

#include "sa_process_common_encryption.h" // NOLINT
#include "client_test_helpers.h"
#include "sa_crypto_cipher_common.h"
#include <chrono>

#define SUBSAMPLE_SIZE 256UL

using namespace client_test_helpers;

sa_status SaProcessCommonEncryptionBase::svp_buffer_write(
        sa_svp_buffer out,
        const void* in,
        size_t in_length) {
#ifndef DISABLE_SVP
    sa_svp_offset offsets = {0, 0, in_length};
    return sa_svp_buffer_write(out, in, in_length, &offsets, 1);
#else
    return SA_STATUS_OPERATION_NOT_SUPPORTED;
#endif // DISABLE_SVP 
}
void SaProcessCommonEncryptionTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        auto buffer_types = std::get<5>(GetParam());
        sa_buffer_type const out_buffer_type = std::get<0>(buffer_types);
        sa_buffer_type const in_buffer_type = std::get<1>(buffer_types);
        if (in_buffer_type == SA_BUFFER_TYPE_SVP || out_buffer_type == SA_BUFFER_TYPE_SVP)
            GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
    }
}


TEST_P(SaProcessCommonEncryptionTest, nominal) {
    auto sample_size_and_time = std::get<0>(GetParam());
    auto sample_size = std::get<0>(sample_size_and_time);
    auto sample_time = std::get<1>(sample_size_and_time);
    size_t const crypt_byte_block = std::get<1>(GetParam());
    size_t const skip_byte_block = (10 - crypt_byte_block) % 10;
    size_t const subsample_count = std::get<2>(GetParam());
    size_t const bytes_of_clear_data = std::get<3>(GetParam());

    cipher_parameters parameters;
    parameters.cipher_algorithm = std::get<4>(GetParam());
    auto buffer_types = std::get<5>(GetParam());
    sa_buffer_type const out_buffer_type = std::get<0>(buffer_types);
    sa_buffer_type const in_buffer_type = std::get<1>(buffer_types);
    parameters.svp_required = (out_buffer_type == SA_BUFFER_TYPE_SVP && in_buffer_type == SA_BUFFER_TYPE_SVP);

    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFE to test rollover condition.
    memset(&parameters.iv[8], 0xff, 7);
    parameters.iv[15] = 0xfe;

    sample_data sample_data;
    sample_data.out = buffer_alloc(out_buffer_type, sample_size);
    ASSERT_NE(sample_data.out, nullptr);
    sample_data.in = buffer_alloc(in_buffer_type, sample_size);
    ASSERT_NE(sample_data.in, nullptr);
    std::vector<sa_sample> samples(1);
    ASSERT_TRUE(build_samples(sample_size, crypt_byte_block, skip_byte_block, subsample_count, bytes_of_clear_data,
            parameters.iv, parameters.cipher_algorithm, parameters.clear_key, cipher, sample_data, samples));

    auto start_time = std::chrono::high_resolution_clock::now();
    sa_status const status = sa_process_common_encryption(samples.size(), samples.data());
    auto end_time = std::chrono::high_resolution_clock::now();
    ASSERT_EQ(status, SA_STATUS_OK);
    std::chrono::milliseconds const duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    if (duration.count() > sample_time) {
        WARN("sa_process_common_encryption ((%d, %d), %d, %d, %d, %d, (%d, %d)) execution time: %lld ms", sample_size,
                sample_time, crypt_byte_block, subsample_count, bytes_of_clear_data, parameters.cipher_algorithm,
                out_buffer_type, in_buffer_type, duration.count());
    } else {
        INFO("sa_process_common_encryption ((%d, %d), %d, %d, %d, %d, (%d, %d)) execution time: %lld ms", sample_size,
                sample_time, crypt_byte_block, subsample_count, bytes_of_clear_data, parameters.cipher_algorithm,
                out_buffer_type, in_buffer_type, duration.count());
    }

    // SVP case tested in taimpltest.
    if (out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        int const result = memcmp(sample_data.out->context.clear.buffer, sample_data.clear.data(),
                sample_data.clear.size());
        ASSERT_EQ(result, 0);
    }

    // SVP buffer verified in taimpltest.
#ifndef DISABLE_CENC_TIMING
    ASSERT_LE(duration.count(), sample_time);
#endif
}

TEST_F(SaProcessCommonEncryptionAlternativeTest, multipleSamples) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
    parameters.svp_required = false;
    sa_buffer_type const out_buffer_type =
            sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED ? SA_BUFFER_TYPE_CLEAR : SA_BUFFER_TYPE_SVP;
    sa_buffer_type const in_buffer_type = SA_BUFFER_TYPE_CLEAR;

    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFF to test rollover condition.
    memset(&parameters.iv[8], 0xff, 8);

    sample_data sample_data;
    sample_data.out = buffer_alloc(out_buffer_type, static_cast<size_t>(5000 * 5));
    ASSERT_NE(sample_data.out, nullptr);
    sample_data.in = buffer_alloc(in_buffer_type, static_cast<size_t>(5000 * 5));
    ASSERT_NE(sample_data.in, nullptr);
    std::vector<sa_sample> samples(5);
    ASSERT_TRUE(build_samples(5000, 0, 0, 5, 20, parameters.iv, parameters.cipher_algorithm, parameters.clear_key,
            cipher, sample_data, samples));

    sa_status const status = sa_process_common_encryption(samples.size(), samples.data());
    ASSERT_EQ(status, SA_STATUS_OK);

    if (out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        int const result = memcmp(sample_data.out->context.clear.buffer, sample_data.clear.data(),
                sample_data.clear.size());
        ASSERT_EQ(result, 0);
    }

    // SVP buffer verified in taimpltest.
}

TEST_F(SaProcessCommonEncryptionAlternativeTest, boundaryCtrRolloverTest) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
    parameters.svp_required = false;
    sa_buffer_type const out_buffer_type =
            sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED ? SA_BUFFER_TYPE_CLEAR : SA_BUFFER_TYPE_SVP;
    sa_buffer_type const in_buffer_type = SA_BUFFER_TYPE_CLEAR;

    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFD to test rollover condition.
    memset(&parameters.iv[8], 0xff, 7);
    parameters.iv[15] = 0xfd;

    sample_data sample_data;
    sample_data.out = buffer_alloc(out_buffer_type, 100);
    ASSERT_NE(sample_data.out, nullptr);
    sample_data.in = buffer_alloc(in_buffer_type, 100);
    ASSERT_NE(sample_data.in, nullptr);
    std::vector<sa_sample> samples(1);
    ASSERT_TRUE(build_samples(100, 0, 0, 5, 0, parameters.iv, parameters.cipher_algorithm, parameters.clear_key, cipher,
            sample_data, samples));

    sa_status const status = sa_process_common_encryption(samples.size(), samples.data());
    ASSERT_EQ(status, SA_STATUS_OK);

    if (out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        int const result = memcmp(sample_data.out->context.clear.buffer, sample_data.clear.data(),
                sample_data.clear.size());
        ASSERT_EQ(result, 0);
    }

    // SVP buffer verified in taimpltest.
}

TEST_F(SaProcessCommonEncryptionAlternativeTest, boundaryCtrRolloverTest2) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
    parameters.svp_required = false;
    sa_buffer_type const out_buffer_type =
            sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED ? SA_BUFFER_TYPE_CLEAR : SA_BUFFER_TYPE_SVP;
    sa_buffer_type const in_buffer_type = SA_BUFFER_TYPE_CLEAR;

    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFD to test rollover condition.
    memset(&parameters.iv[8], 0xff, 7);
    parameters.iv[15] = 0xfd;

    sample_data sample_data;
    sample_data.out = buffer_alloc(out_buffer_type, 180);
    ASSERT_NE(sample_data.out, nullptr);
    sample_data.in = buffer_alloc(in_buffer_type, 180);
    ASSERT_NE(sample_data.in, nullptr);
    std::vector<sa_sample> samples(1);
    ASSERT_TRUE(build_samples(180, 0, 0, 5, 0, parameters.iv, parameters.cipher_algorithm, parameters.clear_key, cipher,
            sample_data, samples));

    sa_status const status = sa_process_common_encryption(samples.size(), samples.data());
    ASSERT_EQ(status, SA_STATUS_OK);

    if (out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        int const result = memcmp(sample_data.out->context.clear.buffer, sample_data.clear.data(),
                sample_data.clear.size());
        ASSERT_EQ(result, 0);
    }

    // SVP buffer verified in taimpltest.
}

TEST_F(SaProcessCommonEncryptionAlternativeTest, boundaryCtrRolloverTest3) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
    parameters.svp_required = false;
    sa_buffer_type const out_buffer_type =
            sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED ? SA_BUFFER_TYPE_CLEAR : SA_BUFFER_TYPE_SVP;
    sa_buffer_type const in_buffer_type = SA_BUFFER_TYPE_CLEAR;

    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFC to test rollover condition.
    memset(&parameters.iv[8], 0xff, 7);
    parameters.iv[15] = 0xfc;

    sample_data sample_data;
    sample_data.out = buffer_alloc(out_buffer_type, 180);
    ASSERT_NE(sample_data.out, nullptr);
    sample_data.in = buffer_alloc(in_buffer_type, 180);
    ASSERT_NE(sample_data.in, nullptr);
    std::vector<sa_sample> samples(1);
    ASSERT_TRUE(build_samples(180, 0, 0, 5, 0, parameters.iv, parameters.cipher_algorithm, parameters.clear_key, cipher,
            sample_data, samples));

    sa_status const status = sa_process_common_encryption(samples.size(), samples.data());
    ASSERT_EQ(status, SA_STATUS_OK);

    if (out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        int const result = memcmp(sample_data.out->context.clear.buffer, sample_data.clear.data(),
                sample_data.clear.size());
        ASSERT_EQ(result, 0);
    }

    // SVP buffer verified in taimpltest.
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullSamples) {
    sa_status const status = sa_process_common_encryption(0, nullptr);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullIv) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = nullptr;
    sample.iv_length = 0;
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidIvLength) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = AES_BLOCK_SIZE + 1;
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullSubsampleLengths) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample.subsample_lengths = nullptr;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidSubsampleCount) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 0;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullOut) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample.out = nullptr;
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullOutBuffer) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sa_buffer out = {SA_BUFFER_TYPE_CLEAR, {.clear = {nullptr, 0, 0}}};
    sample.out = &out;
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}
#ifndef DISABLE_SVP
TEST_F(SaProcessCommonEncryptionNegativeTest, invalidOutSvpBuffer) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sa_buffer out;
    out.buffer_type = SA_BUFFER_TYPE_SVP;
    out.context.svp.buffer = INVALID_HANDLE;
    out.context.svp.offset = 0;
    sample.out = &out;
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}
#endif // DISABLE_SVP

TEST_F(SaProcessCommonEncryptionNegativeTest, nullIn) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample.in = nullptr;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullInBuffer) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sa_buffer in;
    sample.in = &in;
    sample.in->buffer_type = SA_BUFFER_TYPE_CLEAR;
    sample.in->context.clear.buffer = nullptr;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}
#ifndef DISABLE_SVP
TEST_F(SaProcessCommonEncryptionNegativeTest, nullInSvpBuffer) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);

    sa_buffer in = {SA_BUFFER_TYPE_SVP, {.svp = {INVALID_HANDLE, 0}}};
    sample.in = &in;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}
#endif

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidSkipByteBlock) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 1;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidCipher) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = INVALID_HANDLE;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidCipherMode) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidOutBufferType) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sa_buffer out;
    sample.out = &out;
    sample.out->buffer_type = static_cast<sa_buffer_type>(UINT8_MAX);
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidInBufferType) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);

    sa_buffer in;
    sample.in = &in;
    sample.in->buffer_type = static_cast<sa_buffer_type>(UINT8_MAX);

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidCipherAlgorithm) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

#ifndef DISABLE_SVP
TEST_F(SaProcessCommonEncryptionNegativeTest, invalidBufferTypeCombo) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_SVP, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, outBufferTypeDisallowed) {
    cipher_parameters parameters;
    parameters.clear_key = random(SYM_128_KEY_SIZE);

    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

    parameters.key = create_sa_key_symmetric(&rights, parameters.clear_key);
    ASSERT_NE(parameters.key, nullptr);

    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;

    auto cipher = create_uninitialized_sa_crypto_cipher_context();
    ASSERT_NE(cipher, nullptr);

    get_cipher_parameters(parameters);
    sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
            *parameters.key, parameters.parameters.get());
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "Cipher algorithm not supported";
    ERROR("status = %d\n", status);
    ASSERT_EQ(status, SA_STATUS_OK);
    ASSERT_NE(cipher, nullptr);

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
}
#endif
TEST_F(SaProcessCommonEncryptionNegativeTest, outBufferTooShort) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sample.out->context.clear.offset++;
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, outBufferOverflow) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sample.out->context.clear.offset = SIZE_MAX - 4;
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, inBufferTooShort) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();
    sample.in->context.clear.offset++;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, inBufferOverflow) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();
    sample.in->context.clear.offset = SIZE_MAX - 4;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, failClearBufferOverlap) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();
    sample.in->context.clear.offset++;

    sample.out = sample_data.in.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, failSvpBufferOverlap) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
    parameters.svp_required = false;
    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    sa_sample sample;
    sample_data sample_data;
    sample.iv = parameters.iv.data();
    sample.iv_length = parameters.iv.size();
    sample.crypt_byte_block = 0;
    sample.skip_byte_block = 0;
    sample.subsample_count = 1;

    sample_data.subsample_lengths.resize(1);
    sample.subsample_lengths = sample_data.subsample_lengths.data();
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_SVP, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample.out = sample_data.in.get();
    sa_status const status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProcessCommonEncryptionTests_1000,
        SaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(1000, 1)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC),
                ::testing::Values(std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP))));

INSTANTIATE_TEST_SUITE_P(
        SaProcessCommonEncryptionTests_10000,
        SaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(10000, 2)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC),
                ::testing::Values(std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP))));

INSTANTIATE_TEST_SUITE_P(
        SaProcessCommonEncryptionTests_100000,
        SaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(100000, 5)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC),
                ::testing::Values(std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP))));

#ifndef DISABLE_CENC_1000000_TESTS
INSTANTIATE_TEST_SUITE_P(
        SaProcessCommonEncryptionTests_1000000,
        SaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(1000000, 10)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC),
                ::testing::Values(std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP))));
#endif
// clang-format on
