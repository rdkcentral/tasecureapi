/*
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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
#include "gtest/gtest.h" // NOLINT
#include <future>

using namespace client_test_helpers;

sa_status client_thread_verify(
        sa_key key,
        sa_crypto_cipher_context cipher_context,
        sa_crypto_mac_context mac_context) {

    sa_header header;
    sa_status status = sa_key_header(&header, key);
    if (status != SA_STATUS_OK) {
        ERROR("key %d was not found in a thread different from the one it was created in", key);
        return SA_STATUS_INVALID_PARAMETER;
    }

    std::vector<uint8_t> out_buffer(AES_BLOCK_SIZE);
    std::vector<uint8_t> in_buffer = random(AES_BLOCK_SIZE);
    sa_buffer out = {SA_BUFFER_TYPE_CLEAR, {.clear = {out_buffer.data(), out_buffer.size(), 0}}};
    sa_buffer in = {SA_BUFFER_TYPE_CLEAR, {.clear = {in_buffer.data(), in_buffer.size(), 0}}};
    size_t bytes_to_process = AES_BLOCK_SIZE;
    status = sa_crypto_cipher_process(&out, cipher_context, &in, &bytes_to_process);
    if (status != SA_STATUS_OK) {
        ERROR("cipher %d was not found in a thread different from the one it was created in", cipher_context);
        return SA_STATUS_INVALID_PARAMETER;
    }

    status = sa_crypto_mac_process(mac_context, in_buffer.data(), in_buffer.size());
    if (status != SA_STATUS_OK) {
        ERROR("mac %d was not found in a thread different from the one it was created in", mac_context);
        return SA_STATUS_INVALID_PARAMETER;
    }

    return status;
}

namespace {
    TEST(SaClientThreadTest, nominal) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher_context = create_uninitialized_sa_crypto_cipher_context();
        sa_status status = sa_crypto_cipher_init(cipher_context.get(), SA_CIPHER_ALGORITHM_AES_ECB,
                SA_CIPHER_MODE_ENCRYPT, *key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto mac_context = create_uninitialized_sa_crypto_mac_context();
        status = sa_crypto_mac_init(mac_context.get(), SA_MAC_ALGORITHM_CMAC, *key, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::future<sa_status> future = std::async(client_thread_verify, *key, *cipher_context, *mac_context);
        ASSERT_EQ(SA_STATUS_OK, future.get());
    }
} // namespace
