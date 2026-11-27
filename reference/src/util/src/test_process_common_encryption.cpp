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

#include "test_process_common_encryption.h" // NOLINT
#include "common.h"
#include "log.h"
#include "test_helpers.h"
#include <cstring>
#include <openssl/evp.h>

#ifdef __APPLE__
#define htobe64(x) htonll(x)
#define be64toh(x) ntohll(x)
#endif

#define MIN(A, B) ((A) <= (B) ? (A) : (B))

using namespace test_helpers;

EVP_CIPHER_CTX* ProcessCommonEncryptionBase::openssl_init(
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

bool ProcessCommonEncryptionBase::encrypt(
        uint8_t* out_bytes,
        uint8_t* in_bytes,
        size_t bytes_to_process,
        size_t* enc_byte_count,
        uint8_t* iv,
        EVP_CIPHER_CTX* context) {

    bool const ctr_mode = EVP_CIPHER_CTX_mode(context) == EVP_CIPH_CTR_MODE;
    bool first_block = true;
    for (size_t bytes_encrypted = 0; bytes_to_process > bytes_encrypted;) {
        if (ctr_mode) {
            int const remaining_in_block = MIN(AES_BLOCK_SIZE - *enc_byte_count % AES_BLOCK_SIZE,
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
                auto* counterBuffer = reinterpret_cast<uint64_t*>(iv + 8); // NOLINT
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

bool ProcessCommonEncryptionBase::encrypt_samples(
        uint8_t* in_bytes,
        std::vector<sa_sample>& samples,
        std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm cipher_algorithm) {

    size_t offset = 0;
    for (const sa_sample& sample : samples) {
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

bool ProcessCommonEncryptionBase::build_samples(
        size_t sample_size,
        size_t crypt_byte_block,
        size_t skip_byte_block,
        size_t subsample_count,
        size_t bytes_of_clear_data,
        std::vector<uint8_t>& iv,
        sa_cipher_algorithm cipher_algorithm,
        std::vector<uint8_t>& clear_key,
        const std::shared_ptr<sa_crypto_cipher_context>& cipher,
        sample_data& sample_data,
        std::vector<sa_sample>& samples) {

    size_t const sample_count = samples.size();
    size_t const subsample_size = sample_size / subsample_count;
    sample_data.clear = random(subsample_size * subsample_count * sample_count);
    sample_data.subsample_lengths.resize(subsample_count * sample_count);

    for (size_t i = 0; i < sample_count; i++) {
        auto* sample = &samples[i];
        sample->iv = iv.data();
        sample->iv_length = iv.size();
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
    if (!encrypt_samples(in.data(), samples, clear_key, cipher_algorithm)) {
        ERROR("encrypt_sample failed");
        return false;
    }

    if (sample_data.in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
        memcpy(sample_data.in->context.clear.buffer, in.data(), in.size());
    } 
#ifdef ENABLE_SVP
    else {
        if (svp_buffer_write(sample_data.in->context.svp.buffer, in.data(), in.size()) != SA_STATUS_OK) {
            ERROR("svp_buffer_write");
            return false;
        }

        sample_data.in->context.svp.offset = 0;
    }
#endif // ENABLE_SVP

    for (sa_sample& sample : samples)
        sample.in = sample_data.in.get();

    return true;
}

namespace ctr_partial_block_test {
    namespace {
        std::vector<uint8_t> ctr_key_stream(
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& iv,
                size_t length) {

            std::vector<uint8_t> key_stream;
            std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(),
                    EVP_CIPHER_CTX_free);
            if (context == nullptr ||
                    EVP_EncryptInit_ex(context.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1 ||
                    EVP_CIPHER_CTX_set_padding(context.get(), 0) != 1)
                return key_stream;

            // Only the lower 8 bytes of the IV are the counter. It rolls over without carrying into the nonce.
            uint64_t counter = 0;
            for (size_t i = 8; i < AES_BLOCK_SIZE; i++)
                counter = (counter << 8) | iv[i];

            uint8_t block[AES_BLOCK_SIZE];
            memcpy(block, iv.data(), AES_BLOCK_SIZE);
            for (size_t position = 0; position < length; position += AES_BLOCK_SIZE, counter++) {
                for (size_t i = 0; i < 8; i++)
                    block[8 + i] = static_cast<uint8_t>(counter >> (56 - 8 * i));

                uint8_t out[AES_BLOCK_SIZE];
                int out_length = 0;
                if (EVP_EncryptUpdate(context.get(), out, &out_length, block, AES_BLOCK_SIZE) != 1) {
                    key_stream.clear();
                    return key_stream;
                }

                key_stream.insert(key_stream.end(), out, out + AES_BLOCK_SIZE);
            }

            return key_stream;
        }
    } // namespace

    const std::vector<std::vector<sa_subsample_length>>& subsample_cases() {
        // {bytes_of_clear_data, bytes_of_protected_data}
        static const std::vector<std::vector<sa_subsample_length>> cases = {
                {{0, 1}, {0, 1}},
                {{0, 1}, {0, 1}, {0, 1}},
                {{0, 1}, {0, 1}, {0, 14}, {0, 1}},
                {{0, 10}, {0, 5}},
                {{3, 1}, {2, 1}}};
        return cases;
    }

    const std::vector<uint64_t>& counters() {
        static const std::vector<uint64_t> values = {0, 1, UINT64_MAX - 1, UINT64_MAX, 0xF000000000000000ULL,
                0xFFFFFFFFFFFFFFF0ULL};
        return values;
    }

    void set_counter(
            std::vector<uint8_t>& iv,
            uint64_t counter) {

        for (size_t i = 0; i < 8; i++)
            iv[8 + i] = static_cast<uint8_t>(counter >> (56 - 8 * i));
    }

    bool build_sample(
            sample_case& sample_case,
            const std::vector<sa_subsample_length>& subsample_lengths,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv) {

        sample_case.subsample_lengths = subsample_lengths;
        sample_case.total_length = 0;
        size_t protected_length = 0;
        for (const auto& subsample : subsample_lengths) {
            sample_case.total_length += subsample.bytes_of_clear_data + subsample.bytes_of_protected_data;
            protected_length += subsample.bytes_of_protected_data;
        }

        sample_case.clear = random(sample_case.total_length);
        auto key_stream = ctr_key_stream(key, iv, protected_length);
        if (key_stream.empty()) {
            ERROR("ctr_key_stream failed");
            return false;
        }

        // The key stream continues across subsamples and is used only for the protected bytes.
        sample_case.in_bytes = sample_case.clear;
        size_t offset = 0;
        size_t key_stream_position = 0;
        for (const auto& subsample : subsample_lengths) {
            offset += subsample.bytes_of_clear_data;
            for (size_t i = 0; i < subsample.bytes_of_protected_data; i++)
                sample_case.in_bytes[offset++] ^= key_stream[key_stream_position++];
        }

        sample_case.in_bytes.resize(sample_case.total_length + GUARD_SIZE, GUARD_VALUE);
        sample_case.out_bytes.assign(sample_case.total_length + GUARD_SIZE, GUARD_VALUE);
        return true;
    }

    bool verify_output(
            const sample_case& sample_case,
            const uint8_t* result,
            std::string& error) {

        if (memcmp(result, sample_case.clear.data(), sample_case.total_length) != 0) {
            error = "decrypted data is wrong";
            return false;
        }

        for (size_t i = sample_case.total_length; i < sample_case.total_length + GUARD_SIZE; i++) {
            if (result[i] != GUARD_VALUE) {
                error = "write past the end of the sample at " + std::to_string(i);
                return false;
            }
        }

        return true;
    }
} // namespace ctr_partial_block_test
