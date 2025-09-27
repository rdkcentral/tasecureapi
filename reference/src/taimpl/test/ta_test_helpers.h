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

#ifndef TA_TEST_HELPERS_H
#define TA_TEST_HELPERS_H

#include "ta_sa.h"
#include "test_helpers.h"
#include <memory>
#include <vector>

#define MAX_CLIENT_SLOTS 256

namespace ta_test_helpers {
    using namespace test_helpers;

    /**
     * Returns the UUID of the "test" TA.
     *
     * @return the UUID of the "test" TA.
     */
    const sa_uuid* ta_uuid();

    /**
     * Returns the test TA client.
     *
     * @return the test TA client.
     */
    ta_client client();

    /**
     * Creates a shared pointer holding the sa_key value. Key will be released using
     * sa_key_release when the shared pointer gets destroyed.
     *
     * @return created shared pointer.
     */
    std::shared_ptr<sa_key> create_uninitialized_sa_key();

    /**
     * Creates a shared pointer holding the sa_crypto_cipher_context value. Context will be
     * released using sa_crypto_cipher_release when the shared pointer gets destroyed.
     *
     * @return created shared pointer.
     */
    std::shared_ptr<sa_crypto_cipher_context> create_uninitialized_sa_crypto_cipher_context();

    /**
     * Allocates an sa_buffer with the given type and size.
     *
     * @param[in] buffer_type the type of the buffer.
     * @param[in] size the size of the buffer.
     * @return the buffer.
     */
    std::shared_ptr<sa_buffer> buffer_alloc(
            sa_buffer_type buffer_type,
            size_t size);

    /**
     * Allocates an sa_buffer with the given type and initializes it with the given value.
     *
     * @param[in] buffer_type the type of the buffer.
     * @param[in] initial_value the value to initialize the buffer.
     * @return the buffer.
     */
    std::shared_ptr<sa_buffer> buffer_alloc(
            sa_buffer_type buffer_type,
            std::vector<uint8_t>& initial_value);
#ifndef DISABLE_SVP
    /**
     * Allocates SVP memory from inside the test TA.
     *
     * @param[out] svp_memory the SVP memory region.
     * @param[in] size the size of the SVP memory.
     * @return the status of the operation.
     */
    sa_status ta_sa_svp_memory_alloc(
            void** svp_memory,
            size_t size);

    /**
     * Frees SVP memory from inside the TA.
     *
     * @param[in] svp_memory the SVP memory region to free.
     * @return the status of the operation.
     */
    sa_status ta_sa_svp_memory_free(void* svp_memory);
#endif // DISABLE_SVP
} // namespace ta_test_helpers

#endif // TA_TEST_HELPERS_H
