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

#include "client_test_helpers.h"
#include "sa_process_common_encryption_common.h"

using namespace client_test_helpers;

TEST_P(SaProcessCommonEncryptionTest, nominal) {
    size_t crypt_byte_block = std::get<0>(GetParam());
    size_t skip_byte_block = (10 - crypt_byte_block) % 10;
    size_t subsample_count = std::get<1>(GetParam());
    size_t bytes_of_clear_data = std::get<2>(GetParam());
    size_t number_samples = std::get<3>(GetParam());

    cipher_parameters parameters;
    parameters.cipher_algorithm = std::get<4>(GetParam());
    auto buffer_types = std::get<5>(GetParam());
    sa_buffer_type out_buffer_type = std::get<0>(buffer_types);
    sa_buffer_type in_buffer_type = std::get<1>(buffer_types);

    auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
    ASSERT_NE(cipher, nullptr);
    if (*cipher == UNSUPPORTED_CIPHER)
        GTEST_SKIP() << "Cipher algorithm not supported";

    // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFE to test rollover condition.
    memset(&parameters.iv[8], 0xff, 7);
    parameters.iv[15] = 0xfe;

    sample_data sample_data;
    std::vector<sa_sample> samples(number_samples);
    ASSERT_TRUE(build_samples(crypt_byte_block, skip_byte_block, subsample_count, bytes_of_clear_data,
            parameters, out_buffer_type, in_buffer_type, cipher, sample_data, samples));

    sa_status status = sa_process_common_encryption(samples.size(), samples.data());
    ASSERT_EQ(status, SA_STATUS_OK);

    if (out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        int result = memcmp(sample_data.out->context.clear.buffer, sample_data.clear.data(), sample_data.clear.size());
        ASSERT_EQ(result, 0);
    } else {
        std::vector<uint8_t> digest;
        ASSERT_TRUE(digest_openssl(digest, SA_DIGEST_ALGORITHM_SHA256, sample_data.clear, {}, {}));
        status = sa_svp_buffer_check(sample_data.out->context.svp.buffer, 0, sample_data.clear.size(),
                SA_DIGEST_ALGORITHM_SHA256, digest.data(), digest.size());
        ASSERT_EQ(status, SA_STATUS_OK);
    }
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullSamples) {
    sa_status status = sa_process_common_encryption(0, nullptr);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullIv) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidIvLength) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullSubsampleLengths) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidSubsampleCount) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullOut) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample.out = nullptr;
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullOutBuffer) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sa_buffer out = {SA_BUFFER_TYPE_CLEAR, {.clear = {nullptr, 0, 0}}};
    sample.out = &out;
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidOutSvpBuffer) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullIn) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample.in = nullptr;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullInBuffer) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, nullInSvpBuffer) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);

    sa_buffer in = {SA_BUFFER_TYPE_SVP, {.svp = {INVALID_HANDLE, 0}}};
    sample.in = &in;

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidSkipByteBlock) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    sample.in = sample_data.in.get();

    sample_data.out = buffer_alloc(SA_BUFFER_TYPE_CLEAR, SUBSAMPLE_SIZE);
    ASSERT_NE(sample_data.out, nullptr);
    sample.out = sample_data.out.get();
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidCipher) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidCipherMode) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidOutBufferType) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidInBufferType) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, badCipherAlgorithm) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, invalidBufferTypeCombo) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
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

    ASSERT_TRUE(get_cipher_parameters(parameters));

    sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
            *parameters.key, parameters.parameters.get());
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "Cipher algorithm not supported";
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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

TEST_F(SaProcessCommonEncryptionNegativeTest, outBufferTooShort) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, inBufferTooShort) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
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
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, failClearBufferOverlap) {
    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_CLEAR, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();
    sample.in->context.clear.offset++;

    sample.out = sample_data.in.get();
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}

TEST_F(SaProcessCommonEncryptionNegativeTest, failSvpBufferOverlap) {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

    cipher_parameters parameters;
    parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
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
    sample.subsample_lengths = &sample_data.subsample_lengths[0];
    sample.subsample_lengths[0].bytes_of_clear_data = 0;
    sample.subsample_lengths[0].bytes_of_protected_data = SUBSAMPLE_SIZE;

    sample.context = *cipher;
    sample_data.clear = random(SUBSAMPLE_SIZE);
    sample_data.in = buffer_alloc(SA_BUFFER_TYPE_SVP, sample_data.clear);
    ASSERT_NE(sample_data.in, nullptr);
    sample.in = sample_data.in.get();

    sample.out = sample_data.in.get();
    sa_status status = sa_process_common_encryption(1, &sample);
    ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
}
