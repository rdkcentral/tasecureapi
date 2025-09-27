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

#include "ta_sa_svp_crypto.h" // NOLINT
#include "log.h"
#include "sa_rights.h"
#include "ta_sa_cenc.h"
#include "ta_sa_svp.h"
#include "ta_test_helpers.h"
#include "gtest/gtest.h" // NOLINT
#include <chrono>

#define PADDED_SIZE(size) AES_BLOCK_SIZE*(((size) / AES_BLOCK_SIZE) + 1)
#define SUBSAMPLE_SIZE 256UL

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(TaProcessCommonEncryptionTest);
using namespace ta_test_helpers;

std::shared_ptr<sa_key> TaCryptoCipherBase::import_key(
        std::vector<uint8_t>& clear_key,
        bool svp) {
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    if (svp)
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

    auto key = create_uninitialized_sa_key();
    sa_import_parameters_symmetric params = {&rights};
    sa_status const status = ta_sa_key_import(key.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_key.data(),
            clear_key.size(), &params, client(), ta_uuid());
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        ERROR("Unsupported key type");
        *key = UNSUPPORTED_KEY;
    } else if (status != SA_STATUS_OK) {
        ERROR("ta_sa_key_import failed");
        key = nullptr;
    }

    return key;
}

std::vector<uint8_t> TaCryptoCipherBase::encrypt_openssl(
        sa_cipher_algorithm cipher_algorithm,
        const std::vector<uint8_t>& in,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& key) {

    if ((key.size() != SYM_128_KEY_SIZE && key.size() != SYM_256_KEY_SIZE)) {
        ERROR("Invalid key_length");
        return {};
    }

    std::vector<uint8_t> result = {};
    EVP_CIPHER_CTX* context;
    do {
        context = EVP_CIPHER_CTX_new();
        if (context == nullptr) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = nullptr;
        bool pad = false;
        std::vector<uint8_t> temp_iv;
        switch (cipher_algorithm) {
            case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
                pad = true;
                // Fall through
            case SA_CIPHER_ALGORITHM_AES_CBC:
                if (key.size() == SYM_128_KEY_SIZE)
                    cipher = EVP_aes_128_cbc();
                else if (key.size() == SYM_256_KEY_SIZE)
                    cipher = EVP_aes_256_cbc();

                temp_iv = iv;
                break;

            case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
                pad = true;
                // Fall through
            case SA_CIPHER_ALGORITHM_AES_ECB:
                if (key.size() == SYM_128_KEY_SIZE)
                    cipher = EVP_aes_128_ecb();
                else if (key.size() == SYM_256_KEY_SIZE)
                    cipher = EVP_aes_256_ecb();

                break;

            case SA_CIPHER_ALGORITHM_AES_CTR:
                if (key.size() == SYM_128_KEY_SIZE)
                    cipher = EVP_aes_128_ctr();
                else if (key.size() == SYM_256_KEY_SIZE)
                    cipher = EVP_aes_256_ctr();

                temp_iv = iv;
                break;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
            case SA_CIPHER_ALGORITHM_CHACHA20: {
                if (iv.size() != CHACHA20_NONCE_LENGTH) {
                    ERROR("Invalid iv length");
                    break;
                }

                cipher = EVP_chacha20();
                std::vector<uint8_t> counter = {1, 0, 0, 0};
                temp_iv.insert(temp_iv.end(), counter.begin(), counter.end());
                temp_iv.insert(temp_iv.end(), iv.begin(), iv.end());
                break;
            }
#endif
            default:
                ERROR("Unsupported cipher algorithm");
        }

        if (cipher == nullptr) {
            ERROR("Unknown cipher");
            break;
        }

        if ((cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB) &&
                (in.size() % AES_BLOCK_SIZE != 0)) {
            ERROR("Invalid in_length");
            break;
        }

        if (EVP_EncryptInit_ex(context, cipher, nullptr, key.data(), temp_iv.data()) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // set padding
        if (EVP_CIPHER_CTX_set_padding(context, pad ? 1 : 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        if (pad)
            result.resize(((in.size() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE) + AES_BLOCK_SIZE);
        else
            result.resize(in.size());

        auto* out_bytes = result.data();
        int length = 0;
        if (EVP_EncryptUpdate(context, out_bytes, &length, in.data(), static_cast<int>(in.size())) != 1) {
            ERROR("EVP_EncryptUpdate failed");
            result.resize(0);
            break;
        }

        size_t decrypted_length = length;
        out_bytes += length;

        if (pad) {
            if (EVP_EncryptFinal_ex(context, out_bytes, &length) != 1) {
                ERROR("EVP_EncryptFinal_ex failed");
                result.resize(0);
                break;
            }

            decrypted_length += length;
        }

        result.resize(decrypted_length);
    } while (false);

    EVP_CIPHER_CTX_free(context);
    return result;
}

void TaProcessCommonEncryptionTest::SetUp() {
    if (ta_sa_svp_supported(client(), ta_uuid()) == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
    }
}

void TaCryptoCipherTest::SetUp() {
    if (ta_sa_svp_supported(client(), ta_uuid()) == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
    }
}
#ifndef DISABLE_SVP
sa_status TaProcessCommonEncryptionTest::svp_buffer_write(
        sa_svp_buffer out,
        const void* in,
        size_t in_length) {
    sa_svp_offset offsets = {0, 0, in_length};
    return ta_sa_svp_buffer_write(out, in, in_length, &offsets, 1, client(), ta_uuid());
}
#endif
namespace {
    void get_cipher_parameters(
            sa_cipher_algorithm cipher_algorithm,
            std::shared_ptr<void>& parameters,
            std::vector<uint8_t>& iv,
            std::vector<uint8_t>& counter) {

        switch (cipher_algorithm) {
            case SA_CIPHER_ALGORITHM_AES_CBC:
            case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7: {
                iv = random(AES_BLOCK_SIZE);
                auto* cipher_parameters_aes_cbc = new sa_cipher_parameters_aes_cbc;
                cipher_parameters_aes_cbc->iv = iv.data();
                cipher_parameters_aes_cbc->iv_length = iv.size();
                parameters = std::shared_ptr<void>(cipher_parameters_aes_cbc);
                break;
            }
            case SA_CIPHER_ALGORITHM_AES_CTR: {
                iv = random(AES_BLOCK_SIZE);
                auto* cipher_parameters_aes_ctr = new sa_cipher_parameters_aes_ctr;
                cipher_parameters_aes_ctr->ctr = iv.data();
                cipher_parameters_aes_ctr->ctr_length = iv.size();
                parameters = std::shared_ptr<void>(cipher_parameters_aes_ctr);
                break;
            }
            case SA_CIPHER_ALGORITHM_CHACHA20: {
                iv = random(CHACHA20_NONCE_LENGTH);
                counter = {1, 0, 0, 0};
                auto* cipher_parameters_chacha20 = new sa_cipher_parameters_chacha20;
                cipher_parameters_chacha20->nonce = iv.data();
                cipher_parameters_chacha20->nonce_length = iv.size();
                cipher_parameters_chacha20->counter = counter.data();
                cipher_parameters_chacha20->counter_length = counter.size();
                parameters = std::shared_ptr<void>(cipher_parameters_chacha20);
                break;
            }
            default:
                parameters = nullptr;
        }
    }

#ifndef DISABLE_SVP
    size_t get_required_length(
            sa_cipher_algorithm cipher_algorithm,
            sa_cipher_mode cipher_mode,
            size_t key_length,
            size_t bytes_to_process) {

        switch (cipher_algorithm) {
            case SA_CIPHER_ALGORITHM_AES_CBC:
            case SA_CIPHER_ALGORITHM_AES_CTR:
            case SA_CIPHER_ALGORITHM_AES_ECB:
            case SA_CIPHER_ALGORITHM_AES_GCM:
            case SA_CIPHER_ALGORITHM_CHACHA20:
            case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
                return bytes_to_process;

            case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
                return PADDED_SIZE(bytes_to_process);

            case SA_CIPHER_ALGORITHM_RSA_PKCS1V15:
            case SA_CIPHER_ALGORITHM_RSA_OAEP:
            case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
                return key_length;

            default:
                return 0;
        }
    }

    bool verify(
            sa_buffer* buffer,
            std::vector<uint8_t>& data) {

        std::vector<uint8_t> hash;
        if (!digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, data, {}, {}))
            return false;

        return ta_sa_svp_buffer_check(buffer->context.svp.buffer, 0, data.size(), SA_DIGEST_ALGORITHM_SHA256,
                       hash.data(), hash.size(), client(), ta_uuid()) == SA_STATUS_OK;
    }
    TEST_P(TaCryptoCipherTest, processNominal) {
        auto cipher_algorithm = std::get<0>(GetParam());
        auto cipher_mode = std::get<1>(GetParam());
        size_t const key_size = std::get<2>(GetParam());
        size_t const data_size = std::get<3>(GetParam());

        std::shared_ptr<void> parameters;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        get_cipher_parameters(cipher_algorithm, parameters, iv, counter);

        auto clear_key = random(key_size);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);
        sa_status status = ta_sa_crypto_cipher_init(cipher.get(), cipher_algorithm, cipher_mode, *key, parameters.get(),
                client(), ta_uuid());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(data_size);
        std::vector<uint8_t> in;
        if (cipher_mode == SA_CIPHER_MODE_DECRYPT)
            in = encrypt_openssl(cipher_algorithm, clear, iv, clear_key);
        else
            in = clear;

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, in);
        ASSERT_NE(in_buffer, nullptr);

        bool const pkcs7 = cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                           cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
        size_t bytes_to_process = in.size();
        if (pkcs7)
            status = ta_sa_crypto_cipher_process_last(nullptr, *cipher, in_buffer.get(), &bytes_to_process, nullptr,
                    client(), ta_uuid());
        else
            status = ta_sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process,
                    client(), ta_uuid());

        ASSERT_EQ(status, SA_STATUS_OK);
        size_t const required_length = get_required_length(cipher_algorithm, cipher_mode, key_size, in.size());
        ASSERT_EQ(bytes_to_process, required_length);

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);

        size_t total_length = 0;
        if (pkcs7) {
            if (in.size() % AES_BLOCK_SIZE == 0)
                bytes_to_process = in.size() - AES_BLOCK_SIZE;
            else
                bytes_to_process = in.size() - (in.size() % AES_BLOCK_SIZE);

            status = ta_sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                    client(), ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
            total_length += bytes_to_process;
            bytes_to_process = in.size() % AES_BLOCK_SIZE == 0 ? AES_BLOCK_SIZE : in.size() % AES_BLOCK_SIZE;
            status = ta_sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                    nullptr, client(), ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
            total_length += bytes_to_process;
        } else {
            bytes_to_process = in.size();
            status = ta_sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                    client(), ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
            total_length += bytes_to_process;
        }

        ASSERT_EQ(total_length, cipher_mode == SA_CIPHER_MODE_ENCRYPT ? required_length : clear.size());

        // Verify the encryption.
        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            auto encrypted_data = encrypt_openssl(cipher_algorithm, clear, iv, clear_key);
            ASSERT_FALSE(encrypted_data.empty());
            ASSERT_TRUE(verify(out_buffer.get(), encrypted_data));
        } else {
            ASSERT_TRUE(verify(out_buffer.get(), clear));
        }
    }
#endif //DISABLE_SVP
    TEST_P(TaCryptoCipherTest, processFailsOutOffsetOverflow) {
        auto cipher_algorithm = std::get<0>(GetParam());
        auto cipher_mode = std::get<1>(GetParam());
        size_t const key_size = std::get<2>(GetParam());

        std::shared_ptr<void> parameters;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        get_cipher_parameters(cipher_algorithm, parameters, iv, counter);

        auto clear_key = random(key_size);
        auto key = import_key(clear_key, false);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = ta_sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, cipher_mode, *key,
                nullptr, client(), ta_uuid());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = clear.size();
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        out_buffer->context.clear.offset = SIZE_MAX - 4;

        status = ta_sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(TaCryptoCipherTest, processFailsInOffsetOverflow) {
        auto cipher_algorithm = std::get<0>(GetParam());
        auto cipher_mode = std::get<1>(GetParam());
        size_t const key_size = std::get<2>(GetParam());

        std::shared_ptr<void> parameters;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        get_cipher_parameters(cipher_algorithm, parameters, iv, counter);

        auto clear_key = random(key_size);
        auto key = import_key(clear_key, false);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = ta_sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, cipher_mode, *key,
                nullptr, client(), ta_uuid());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = clear.size();
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        in_buffer->context.clear.offset = SIZE_MAX - 4;

        status = ta_sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process, client(),
                ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
#ifndef DISABLE_SVP
    TEST_P(TaProcessCommonEncryptionTest, nominal) {
        auto sample_size_and_time = std::get<0>(GetParam());
        auto sample_size = std::get<0>(sample_size_and_time);
        auto sample_time = std::get<1>(sample_size_and_time);
        auto crypt_byte_block = std::get<1>(GetParam());
        auto skip_byte_block = (10 - crypt_byte_block) % 10;
        auto subsample_count = std::get<2>(GetParam());
        auto bytes_of_clear_data = std::get<3>(GetParam());
        auto cipher_algorithm = std::get<4>(GetParam());

        std::shared_ptr<void> parameters;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        get_cipher_parameters(cipher_algorithm, parameters, iv, counter);

        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, true);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);
        sa_status status = ta_sa_crypto_cipher_init(cipher.get(), cipher_algorithm, SA_CIPHER_MODE_DECRYPT, *key,
                parameters.get(), client(), ta_uuid());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        // Set lower 8 bytes of IV to FFFFFFFFFFFFFFFE to test rollover condition.
        memset(&iv[8], 0xff, 7);
        iv[15] = 0xfe;

        sample_data sample_data;
        sample_data.out = buffer_alloc(SA_BUFFER_TYPE_SVP, sample_size);
        ASSERT_NE(sample_data.out, nullptr);
        sample_data.in = buffer_alloc(SA_BUFFER_TYPE_SVP, sample_size);
        ASSERT_NE(sample_data.in, nullptr);
        std::vector<sa_sample> samples(1);
        ASSERT_TRUE(build_samples(sample_size, crypt_byte_block, skip_byte_block, subsample_count, bytes_of_clear_data,
                iv, cipher_algorithm, clear_key, cipher, sample_data, samples));

        auto start_time = std::chrono::high_resolution_clock::now();
        status = ta_sa_process_common_encryption(samples.size(), samples.data(), client(), ta_uuid());
        auto end_time = std::chrono::high_resolution_clock::now();
        ASSERT_EQ(status, SA_STATUS_OK);
        std::chrono::milliseconds const duration =
                std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (duration.count() > sample_time) {
            WARN("sa_process_common_encryption ((%d, %d), %d, %d, %d, %d, (%d, %d)) execution time: %lld ms",
                    sample_size, sample_time, crypt_byte_block, subsample_count, bytes_of_clear_data, cipher_algorithm,
                    SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP, duration.count());
        } else {
            INFO("sa_process_common_encryption ((%d, %d), %d, %d, %d, %d, (%d, %d)) execution time: %lld ms",
                    sample_size, sample_time, crypt_byte_block, subsample_count, bytes_of_clear_data, cipher_algorithm,
                    SA_BUFFER_TYPE_SVP, SA_BUFFER_TYPE_SVP, duration.count());
        }
        std::vector<uint8_t> digest;
        ASSERT_TRUE(digest_openssl(digest, SA_DIGEST_ALGORITHM_SHA256, sample_data.clear, {}, {}));
        status = ta_sa_svp_buffer_check(sample_data.out->context.svp.buffer, 0, sample_data.clear.size(),
                SA_DIGEST_ALGORITHM_SHA256, digest.data(), digest.size(), client(), ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);
#ifndef DISABLE_CENC_TIMING
        ASSERT_LE(duration.count(), sample_time);
#endif
    }
    TEST_F(TaProcessCommonEncryptionTest, failsOutBufferOverflow) {
        std::shared_ptr<void> parameters;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        get_cipher_parameters(SA_CIPHER_ALGORITHM_AES_CBC, parameters, iv, counter);

        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, false);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);
        sa_status status = ta_sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_CBC, SA_CIPHER_MODE_DECRYPT,
                *key, parameters.get(), client(), ta_uuid());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_sample sample;
        sample_data sample_data;
        sample.iv = iv.data();
        sample.iv_length = iv.size();
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

        sample_data.out = buffer_alloc(SA_BUFFER_TYPE_SVP, SUBSAMPLE_SIZE);
        ASSERT_NE(sample_data.out, nullptr);
        sample.out = sample_data.out.get();
        sample.out->context.svp.offset = SIZE_MAX - 4;
        status = ta_sa_process_common_encryption(1, &sample, client(), ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(TaProcessCommonEncryptionTest, failsInBufferOverflow) {
        std::shared_ptr<void> parameters;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> counter;
        get_cipher_parameters(SA_CIPHER_ALGORITHM_AES_CBC, parameters, iv, counter);

        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = import_key(clear_key, false);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "Key type not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);
        sa_status status = ta_sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_CBC, SA_CIPHER_MODE_DECRYPT,
                *key, parameters.get(), client(), ta_uuid());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_sample sample;
        sample_data sample_data;
        sample.iv = iv.data();
        sample.iv_length = iv.size();
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
        sample.in->context.svp.offset = SIZE_MAX - 4;

        sample_data.out = buffer_alloc(SA_BUFFER_TYPE_SVP, SUBSAMPLE_SIZE);
        ASSERT_NE(sample_data.out, nullptr);
        sample.out = sample_data.out.get();
        status = ta_sa_process_common_encryption(1, &sample, client(), ta_uuid());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
#endif // DISABLE_SVP

} // namespace

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        AesCbcEcbTests,
        TaCryptoCipherTest,
        ::testing::Combine(
            ::testing::Values(SA_CIPHER_ALGORITHM_AES_CBC, SA_CIPHER_ALGORITHM_AES_ECB),
            ::testing::Values(SA_CIPHER_MODE_DECRYPT, SA_CIPHER_MODE_ENCRYPT),
            ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
            ::testing::Values(AES_BLOCK_SIZE * 2)));

INSTANTIATE_TEST_SUITE_P(
        AesCbcEcbPkcs7Tests,
        TaCryptoCipherTest,
        ::testing::Combine(
            ::testing::Values(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7),
            ::testing::Values(SA_CIPHER_MODE_ENCRYPT, SA_CIPHER_MODE_DECRYPT),
            ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
            ::testing::Values(AES_BLOCK_SIZE * 2, AES_BLOCK_SIZE * 2 + 1, AES_BLOCK_SIZE * 2 + 15)));

INSTANTIATE_TEST_SUITE_P(
        AesCtrTests,
        TaCryptoCipherTest,
        ::testing::Combine(
            ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR),
            ::testing::Values(SA_CIPHER_MODE_ENCRYPT, SA_CIPHER_MODE_DECRYPT),
            ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
            ::testing::Values(AES_BLOCK_SIZE * 2, AES_BLOCK_SIZE * 2 + 1, AES_BLOCK_SIZE * 2 + 15)));

INSTANTIATE_TEST_SUITE_P(
        Chacha20Tests,
        TaCryptoCipherTest,
        ::testing::Combine(
            ::testing::Values(SA_CIPHER_ALGORITHM_CHACHA20),
            ::testing::Values(SA_CIPHER_MODE_ENCRYPT, SA_CIPHER_MODE_DECRYPT),
            ::testing::Values(SYM_256_KEY_SIZE),
            ::testing::Values(AES_BLOCK_SIZE * 2, AES_BLOCK_SIZE * 2 + 1, AES_BLOCK_SIZE * 2 + 15)));

INSTANTIATE_TEST_SUITE_P(
        TaProcessCommonEncryptionTests_1000,
        TaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(1000, 1)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC)));

INSTANTIATE_TEST_SUITE_P(
        TaProcessCommonEncryptionTests_10000,
        TaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(10000, 2)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC)));

INSTANTIATE_TEST_SUITE_P(
        TaProcessCommonEncryptionTests_100000,
        TaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(100000, 5)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC)));

#ifndef DISABLE_CENC_1000000_TESTS
INSTANTIATE_TEST_SUITE_P(
        TaProcessCommonEncryptionTests_1000000,
        TaProcessCommonEncryptionTest,
        ::testing::Combine(
                ::testing::Values(std::make_tuple(1000000, 10)),          // Sample size and time
                ::testing::Values(0UL, 1UL, 5UL, 9UL),          // crypt_byte_block
                ::testing::Values(1UL, 2UL, 5UL, 10UL),         // subsample_size
                ::testing::Values(0UL, 16UL, 20UL, UINT32_MAX), // bytes_of_clear_data
                ::testing::Values(SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_ALGORITHM_AES_CBC)));
#endif
// clang-format on
