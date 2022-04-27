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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

typedef struct {
    pthread_t thread_id;
    int thread_num;
} thread_info;

void* SaCryptoCipherMultipleThread::process_multiple_threads(void* args) {
    auto* thread_data = static_cast<thread_info*>(args);
    for (size_t i = 0; i < 100 && args != nullptr; i++) {
        char message[30];
        sprintf(message, "Thread %d-Iteration %zu", thread_data->thread_num, i);
        ERROR(message);

        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
        sa_key_type key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t key_size = SYM_128_KEY_SIZE;
        sa_buffer_type buffer_type = SA_BUFFER_TYPE_CLEAR;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        if (cipher == nullptr || *cipher == UNSUPPORTED_CIPHER) {
            ERROR("initialize_cipher failed");
            return reinterpret_cast<void*>(1);
        }

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        if (in_buffer == nullptr) {
            return reinterpret_cast<void*>(1);
        }

        // get out_length
        size_t bytes_to_process = clear.size();
        if (sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process) != SA_STATUS_OK) {
            ERROR("sa_crypto_cipher_process failed");
            return reinterpret_cast<void*>(1);
        }

        if (bytes_to_process != get_required_length(parameters.cipher_algorithm, key_size, clear.size(), true)) {
            ERROR("bytes_to_process failed");
            return reinterpret_cast<void*>(1);
        }

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        if (out_buffer == nullptr) {
            return reinterpret_cast<void*>(1);
        }

        bytes_to_process = clear.size();
        if (sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process) != SA_STATUS_OK) {
            ERROR("sa_crypto_cipher_process failed");
            return reinterpret_cast<void*>(1);
        }

        if (bytes_to_process != clear.size()) {
            ERROR("bytes_to_process not correct");
            return reinterpret_cast<void*>(1);
        }

        // Verify the encryption.
        if (!verify_encrypt(out_buffer.get(), clear, parameters, false)) {
            ERROR("verify_encrypt failed");
            return reinterpret_cast<void*>(1);
        }
    }

    return nullptr;
}

namespace {
    TEST(SaCryptoCipherMultipleThread, processMultipleThread) {
        thread_info threads[255];
        int i = 0;
        for (auto& thread : threads) {
            thread.thread_num = i++;
            int result = pthread_create(&thread.thread_id, nullptr,
                    SaCryptoCipherMultipleThread::process_multiple_threads, &thread);
            ASSERT_EQ(result, 0);
        }

        ASSERT_EQ(SaCryptoCipherMultipleThread::process_multiple_threads(nullptr), nullptr);

        void* result;
        for (auto& thread : threads) {
            ASSERT_EQ(pthread_join(thread.thread_id, &result), 0);
            ASSERT_EQ(result, nullptr);
        }
    }
} // namespace
