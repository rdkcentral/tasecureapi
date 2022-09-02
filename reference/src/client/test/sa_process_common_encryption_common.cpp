/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#include "sa_process_common_encryption_common.h" // NOLINT
#include "client_test_helpers.h"
#include <openssl/evp.h>

#ifdef __APPLE__
#define htobe64(x) htonll(x)
#define be64toh(x) ntohll(x)
#endif

using namespace client_test_helpers;

#define MIN(A, B) ((A) <= (B) ? (A) : (B))

EVP_CIPHER_CTX* SaProcessCommonEncryptionBase::openssl_init(
        const void* iv,
        const uint8_t* key,
        sa_cipher_algorithm cipher_algorithm) {

    EVP_CIPHER_CTX* context;
    do {
        context = EVP_CIPHER_CTX_new();
        if (context == nullptr) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = nullptr;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC)
            cipher = EVP_aes_128_cbc();
        else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR)
            cipher = EVP_aes_128_ctr();

        if (cipher == nullptr) {
            ERROR("EVP_aes_128_??? failed");
            EVP_CIPHER_CTX_free(context);
            context = nullptr;
            break;
        }

        if (EVP_EncryptInit_ex(context, cipher, nullptr, key, static_cast<const uint8_t*>(iv)) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            EVP_CIPHER_CTX_free(context);
            context = nullptr;
            break;
        }

        // set padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            EVP_CIPHER_CTX_free(context);
            context = nullptr;
            break;
        }
    } while (false);

    return context;
}

bool SaProcessCommonEncryptionBase::encrypt(
        uint8_t* out_bytes,
        uint8_t* in_bytes,
        size_t bytes_to_process,
        size_t* enc_byte_count,
        uint8_t* iv,
        EVP_CIPHER_CTX* context) {

    bool ctr_mode = EVP_CIPHER_CTX_mode(context) == EVP_CIPH_CTR_MODE;
    bool first_block = true;
    for (size_t bytes_encrypted = 0; bytes_to_process > bytes_encrypted;) {
        if (ctr_mode) {
            int remaining_in_block = MIN(AES_BLOCK_SIZE - *enc_byte_count % AES_BLOCK_SIZE,
                    bytes_to_process - bytes_encrypted);
            if (!first_block || remaining_in_block == AES_BLOCK_SIZE) {
                if (EVP_EncryptInit_ex(context, nullptr, nullptr, nullptr, iv) != 1) {
                    ERROR("EVP_EncryptInit_ex failed");
                    return false;
                }
            }

            int out_length = remaining_in_block;
            if (EVP_EncryptUpdate(context, out_bytes + bytes_encrypted, &out_length, in_bytes + bytes_encrypted,
                        remaining_in_block) != 1) {
                ERROR("EVP_EncryptUpdate failed");
                return false;
            }

            if ((*enc_byte_count + remaining_in_block) % AES_BLOCK_SIZE == 0) {
                auto* counterBuffer = reinterpret_cast<uint64_t*>(iv + 8);
                (*counterBuffer) = htobe64(be64toh(*counterBuffer) + 1);
            }

            bytes_encrypted += remaining_in_block;
            *enc_byte_count += remaining_in_block;
        } else {
            int length = 0;
            if (EVP_EncryptUpdate(context, out_bytes + bytes_encrypted, &length, in_bytes + bytes_encrypted,
                        static_cast<int>(bytes_to_process)) != 1) {
                ERROR("EVP_EncryptUpdate failed");
                return false;
            }

            bytes_encrypted += bytes_to_process;
            *enc_byte_count += bytes_to_process;
        }

        first_block = false;
    }

    return true;
}

bool SaProcessCommonEncryptionBase::encrypt_samples(
        uint8_t* in_bytes,
        std::vector<sa_sample>& samples,
        std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm cipher_algorithm) {

    size_t offset = 0;
    for (sa_sample& sample : samples) {
        uint8_t iv[AES_BLOCK_SIZE];
        memcpy(iv, sample.iv, sample.iv_length);

        EVP_CIPHER_CTX* context = openssl_init(static_cast<const uint8_t*>(sample.iv), clear_key.data(),
                cipher_algorithm);
        if (context == nullptr) {
            ERROR("openssl_init failed");
            return false;
        }

        size_t enc_byte_count = 0;
        for (size_t i = 0; i < sample.subsample_count; i++) {
            offset += sample.subsample_lengths[i].bytes_of_clear_data;

            if (sample.subsample_lengths[i].bytes_of_protected_data > 0) {
                if (sample.crypt_byte_block == 0) {
                    int block_size;
                    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
                        // In CBC1 mode, only encrypt full blocks, leave the last partial block clear.
                        block_size = MIN(sample.subsample_lengths[i].bytes_of_protected_data,
                                (sample.subsample_lengths[i].bytes_of_protected_data / AES_BLOCK_SIZE) *
                                        AES_BLOCK_SIZE);
                    } else {
                        // In CENC mode, encrypt the entire protected block.
                        block_size = static_cast<int>(sample.subsample_lengths[i].bytes_of_protected_data);
                    }

                    std::vector<uint8_t> out_bytes(block_size);
                    if (!encrypt(out_bytes.data(), in_bytes + offset, block_size, &enc_byte_count, iv, context)) {
                        ERROR("encrypt_block failed");
                        EVP_CIPHER_CTX_free(context);
                        return false;
                    }

                    memcpy(in_bytes + offset, out_bytes.data(), block_size);
                    offset += sample.subsample_lengths[i].bytes_of_protected_data;
                } else {
                    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
                        // Reset the IV on every subsample in CBCS mode.
                        if (EVP_EncryptInit_ex(context, nullptr, nullptr, nullptr,
                                    static_cast<const uint8_t*>(sample.iv)) != 1) {
                            ERROR("EVP_EncryptInit_ex failed");
                            EVP_CIPHER_CTX_free(context);
                            return false;
                        }
                    }

                    size_t bytes_left = sample.subsample_lengths[i].bytes_of_protected_data;
                    while (bytes_left >= AES_BLOCK_SIZE) {
                        int block_size = MIN(sample.crypt_byte_block * AES_BLOCK_SIZE,
                                (bytes_left / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
                        std::vector<uint8_t> out_bytes(block_size);
                        if (!encrypt(out_bytes.data(), in_bytes + offset, block_size, &enc_byte_count, iv, context)) {
                            ERROR("encrypt_block failed");
                            EVP_CIPHER_CTX_free(context);
                            return false;
                        }

                        memcpy(in_bytes + offset, out_bytes.data(), block_size);
                        offset += block_size;
                        bytes_left -= block_size;

                        block_size = MIN(sample.skip_byte_block * AES_BLOCK_SIZE,
                                (bytes_left / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
                        bytes_left -= block_size;
                        offset += block_size;
                    }

                    offset += bytes_left;
                }
            }
        }

        EVP_CIPHER_CTX_free(context);
    }

    return true;
}

bool SaProcessCommonEncryptionBase::build_samples(
        size_t sample_size,
        size_t crypt_byte_block,
        size_t skip_byte_block,
        size_t subsample_count,
        size_t bytes_of_clear_data,
        cipher_parameters& parameters,
        sa_buffer_type out_buffer_type,
        sa_buffer_type in_buffer_type,
        const std::shared_ptr<sa_crypto_cipher_context>& cipher,
        sample_data& sample_data,
        std::vector<sa_sample>& samples) {

    size_t sample_count = samples.size();
    size_t subsample_size = sample_size / subsample_count;
    sample_data.clear = random(subsample_size * subsample_count * sample_count);
    sample_data.out = buffer_alloc(out_buffer_type, sample_data.clear.size());
    if (sample_data.out == nullptr)
        return false;

    sample_data.subsample_lengths.resize(subsample_count * sample_count);

    for (size_t i = 0; i < sample_count; i++) {
        auto* sample = &samples[i];
        sample->iv = parameters.iv.data();
        sample->iv_length = parameters.iv.size();
        sample->crypt_byte_block = crypt_byte_block;
        sample->skip_byte_block = skip_byte_block;
        sample->subsample_count = subsample_count;

        sample->subsample_lengths = &sample_data.subsample_lengths[i * subsample_count];
        for (size_t j = 0; j < subsample_count; j++) {
            sample->subsample_lengths[j].bytes_of_clear_data =
                    bytes_of_clear_data == UINT32_MAX ? subsample_size : bytes_of_clear_data;
            sample->subsample_lengths[j].bytes_of_protected_data =
                    subsample_size - sample->subsample_lengths[j].bytes_of_clear_data;
        }

        sample->context = *cipher;
        sample->out = sample_data.out.get();
    }

    // Encrypt the data in the clear and then copy it into the clear or SVP input buffer and then update the sample
    // data.
    std::vector<uint8_t> in = sample_data.clear;
    if (!encrypt_samples(in.data(), samples, parameters.clear_key, parameters.cipher_algorithm)) {
        ERROR("encrypt_sample failed");
        return false;
    }

    sample_data.in = buffer_alloc(in_buffer_type, in);
    if (sample_data.in == nullptr)
        return false;

    for (sa_sample& sample : samples)
        sample.in = sample_data.in.get();

    return true;
}

void SaProcessCommonEncryptionTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        auto buffer_types = std::get<5>(GetParam());
        sa_buffer_type out_buffer_type = std::get<0>(buffer_types);
        sa_buffer_type in_buffer_type = std::get<1>(buffer_types);
        if (in_buffer_type == SA_BUFFER_TYPE_SVP || out_buffer_type == SA_BUFFER_TYPE_SVP)
            GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
    }
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProcessCommonEncryptionTests,
        SaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(1000, 1), std::make_tuple(10000, 2), std::make_tuple(100000, 5),
                        std::make_tuple(1000000, 10)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC),
                ::testing::Values(std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_CLEAR),
                        std::make_tuple(SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP))));
// clang-format on
