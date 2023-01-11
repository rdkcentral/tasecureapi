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
#include "gtest/gtest.h" // NOLINT
#include <future>

using namespace client_test_helpers;

sa_status SaCryptoCipherMultipleThread::process_multiple_threads(size_t id) {
    for (size_t i = 0; i < 100; i++) {
        INFO("Thread %d-Iteration %zu", id, i);

        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
        parameters.svp_required = false;
        sa_key_type key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t key_size = SYM_128_KEY_SIZE;
        sa_buffer_type buffer_type = SA_BUFFER_TYPE_CLEAR;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        if (cipher == nullptr || *cipher == UNSUPPORTED_CIPHER) {
            ERROR("initialize_cipher failed");
            return SA_STATUS_OPERATION_NOT_SUPPORTED;
        }

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        if (in_buffer == nullptr) {
            return SA_STATUS_NULL_PARAMETER;
        }

        // get out_length
        size_t bytes_to_process = clear.size();
        sa_status status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("sa_crypto_cipher_process failed");
            return status;
        }

        if (get_required_length(parameters.cipher_algorithm, key_size, clear.size(), true) != bytes_to_process) {
            ERROR("bytes_to_process failed");
            return SA_STATUS_INVALID_PARAMETER;
        }

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        if (out_buffer == nullptr) {
            return SA_STATUS_NULL_PARAMETER;
        }

        bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("sa_crypto_cipher_process failed");
            return status;
        }

        if (bytes_to_process != clear.size()) {
            ERROR("bytes_to_process not correct");
            return SA_STATUS_INVALID_PARAMETER;
        }

        // Verify the encryption.
        if (!verify_encrypt(out_buffer.get(), clear, parameters, false)) {
            ERROR("verify_encrypt failed");
            return SA_STATUS_INVALID_PARAMETER;
        }
    }

    return SA_STATUS_OK;
}

namespace {
    TEST(SaCryptoCipherMultipleThread, processMultipleThread) {
        std::vector<std::future<sa_status>> futures(255);
        for (size_t i = 0; i < futures.size(); i++)
            futures[i] = std::async(SaCryptoCipherMultipleThread::process_multiple_threads, i);

        for (auto& future : futures)
            ASSERT_EQ(SA_STATUS_OK, future.get());
    }
} // namespace
