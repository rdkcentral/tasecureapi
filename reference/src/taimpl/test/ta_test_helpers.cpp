/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

#include "ta_test_helpers.h" // NOLINT
#include "log.h"
#include <cstdlib>
#include <cstring>

namespace ta_test_helpers {

    // This is sample code for example purposes only and matches the definition in svp.h.
    typedef struct {
        size_t svp_memory_size;
        uint8_t* svp_memory;
    } svp_memory_s;

    const sa_uuid* ta_uuid() {
        static sa_uuid const uuid = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

        return &uuid;
    }

    namespace {
        void ta_client_shutdown() {
            ta_client const client = ta_test_helpers::client();
            ta_sa_close(client, ta_uuid());
        }
    } // namespace

    ta_client client() {
        static ta_client client = INVALID_HANDLE;

        if (client == INVALID_HANDLE) {
            if (SA_STATUS_OK != ta_sa_init(&client, ta_uuid())) {
                ERROR("ta_sa_init failed");
                return client;
            }

            atexit(ta_client_shutdown);
        }

        return client;
    }

    // TODO SoC Vendor: replace this call with a call to allocate secure memory.
    sa_status ta_sa_svp_memory_alloc(
            void** svp_memory,
            size_t size) {

        if (svp_memory == nullptr) {
            ERROR("NULL svp_memory");
            return SA_STATUS_NULL_PARAMETER;
        }

        // TODO SoC Vendor: replace this call with a call to allocate secure memory.
        auto* temp = new svp_memory_s;
        if (temp == nullptr) {
            ERROR("new failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        temp->svp_memory = new uint8_t[size];
        if (temp->svp_memory == nullptr) {
            ERROR("new failed");
            delete temp;
            return SA_STATUS_INTERNAL_ERROR;
        }

        temp->svp_memory_size = size;
        *svp_memory = temp;
        return SA_STATUS_OK;
    }

    // TODO SoC Vendor: replace this call with a call to free secure memory.
    sa_status ta_sa_svp_memory_free(void* svp_memory) {
        auto* temp = static_cast<svp_memory_s*>(svp_memory);

        if (temp->svp_memory != nullptr)
            free(temp->svp_memory);

        if (temp != nullptr)
            free(temp);

        return SA_STATUS_OK;
    }

    std::shared_ptr<sa_key> create_uninitialized_sa_key() {
        return {new sa_key(INVALID_HANDLE),
                [](const sa_key* p) {
                    if (p != nullptr) {
                        if (*p != INVALID_HANDLE) {
                            ta_sa_key_release(*p, client(), ta_uuid());
                        }

                        delete p;
                    }
                }};
    }

    std::shared_ptr<sa_crypto_cipher_context> create_uninitialized_sa_crypto_cipher_context() {
        return {new sa_crypto_cipher_context(INVALID_HANDLE),
                [](const sa_crypto_cipher_context* p) {
                    if (p != nullptr) {
                        if (*p != INVALID_HANDLE) {
                            ta_sa_crypto_cipher_release(*p, client(), ta_uuid());
                        }

                        delete p;
                    }
                }};
    }

    std::shared_ptr<sa_buffer> buffer_alloc(
            sa_buffer_type buffer_type,
            size_t size) {

        auto buffer = std::shared_ptr<sa_buffer>(
                new sa_buffer,
                [buffer_type](const sa_buffer* buffer) {
                    if (buffer != nullptr) {
                        if (buffer_type == SA_BUFFER_TYPE_CLEAR) {
                            if (buffer->context.clear.buffer != nullptr)
                                free(buffer->context.clear.buffer);
                        } else {
                            if (buffer->context.svp.svp_memory != nullptr)
                                free(buffer->context.svp.svp_memory);
                        }
                    }

                    delete buffer;
                });

        if (buffer_type == SA_BUFFER_TYPE_CLEAR) {
            buffer->buffer_type = SA_BUFFER_TYPE_CLEAR;
            buffer->context.clear.length = size;
            buffer->context.clear.offset = 0;
            buffer->context.clear.buffer = malloc(size);
            if (buffer->context.clear.buffer == nullptr) {
                ERROR("malloc failed");
                return nullptr;
            }
        } else if (buffer_type == SA_BUFFER_TYPE_SVP) {
            buffer->buffer_type = SA_BUFFER_TYPE_SVP;
            if (ta_sa_svp_memory_alloc(&buffer->context.svp.svp_memory, size) != SA_STATUS_OK)
                return nullptr;

            buffer->context.svp.offset = 0;
        }

        return buffer;
    }

    std::shared_ptr<sa_buffer> buffer_alloc(
            sa_buffer_type buffer_type,
            std::vector<uint8_t>& initial_value) {

        auto buffer = buffer_alloc(buffer_type, initial_value.size());
        if (buffer == nullptr)
            return nullptr;

        if (buffer_type == SA_BUFFER_TYPE_CLEAR) {
            memcpy(buffer->context.clear.buffer, initial_value.data(), initial_value.size());
        } else {
            sa_svp_offset offsets = {0, 0, initial_value.size()};
            if (ta_sa_svp_write(buffer->context.svp.svp_memory, initial_value.data(), initial_value.size(),
                        &offsets, 1, client(), ta_uuid()) != SA_STATUS_OK) {
                ERROR("ta_sa_svp_write failed");
                return nullptr;
            }

            buffer->context.svp.offset = 0;
        }

        return buffer;
    }
} // namespace ta_test_helpers
