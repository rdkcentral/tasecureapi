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

#include "object_store.h" // NOLINT
#include "log.h"
#include "ta_test_helpers.h"
#include "gtest/gtest.h"

using namespace ta_test_helpers;

namespace {
    void noop(void* obj) {
        DEBUG("Releasing %p", obj);
    }

    TEST(ObjectStoreInit, nominal) {
        size_t const num = 128;
        std::shared_ptr<object_store_t> const store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);
    }

    TEST(ObjectStoreInit, failsOnInvalidNumSlots) {
        size_t const num = 129;
        std::shared_ptr<object_store_t> const store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_EQ(store, nullptr);
    }

    TEST(ObjectStoreShutdown, noThrowOnNull) {
        EXPECT_NO_THROW(object_store_shutdown(nullptr)); // NOLINT
    }

    TEST(ObjectStoreAdd, nominal) {
        size_t num = 128;
        std::shared_ptr<object_store_t> const store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);

        slot_t slot = SLOT_INVALID;
        sa_status const status = object_store_add(&slot, store.get(), &num, ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(slot, SLOT_INVALID);
    }

    TEST(ObjectStoreAdd, failsWhenFull) {
        size_t num = 128;
        std::shared_ptr<object_store_t> const store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);

        slot_t slot = SLOT_INVALID;
        for (size_t i = 0; i < num; ++i) {
            sa_status const status = object_store_add(&slot, store.get(), &num, ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
        }

        // allocate one past the limit
        ASSERT_EQ(object_store_add(&slot, store.get(), &num, ta_uuid()),
                SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT);
    }

    TEST(ObjectStoreAcquire, nominal) {
        size_t num = 128;
        std::shared_ptr<object_store_t> store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);

        slot_t slot = SLOT_INVALID;
        sa_status status = object_store_add(&slot, store.get(), &num, ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(slot, SLOT_INVALID);

        void* object = nullptr;
        status = object_store_acquire(&object, store.get(), slot, ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);
        std::shared_ptr<void> const obj(object, [&](void* object) {
            sa_status const status = object_store_release(store.get(), slot, object, ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
        });
        ASSERT_NE(object, nullptr);
    }

    TEST(ObjectStoreAcquire, failsWithInvalidUuid) {
        size_t num = 128;
        std::shared_ptr<object_store_t> store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);

        slot_t slot = SLOT_INVALID;
        sa_status status = object_store_add(&slot, store.get(), &num, ta_uuid());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(slot, SLOT_INVALID);

        sa_uuid wrong_uuid;
        memcpy(&wrong_uuid, ta_uuid(), sizeof(sa_uuid));
        wrong_uuid.id[0] = ~wrong_uuid.id[0];
        void* object = nullptr;
        status = object_store_acquire(&object, store.get(), slot, &wrong_uuid);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
        std::shared_ptr<void> const obj(object, [&](void* object) {
            object_store_release(store.get(), slot, object, ta_uuid());
        });
        ASSERT_EQ(object, nullptr);
    }

    TEST(ObjectStoreRemove, nominal) {
        size_t num = 128;
        std::shared_ptr<object_store_t> const store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);

        std::vector<slot_t> allocated;
        for (size_t i = 0; i < num; ++i) {
            slot_t slot = SLOT_INVALID;
            sa_status const status = object_store_add(&slot, store.get(), &num, ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
            allocated.push_back(slot);
        }

        for (unsigned int const i : allocated) {
            sa_status const status = object_store_remove(store.get(), i, ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
        }

        std::vector<slot_t> allocated2;
        for (size_t i = 0; i < num; ++i) {
            slot_t slot = SLOT_INVALID;
            sa_status const status = object_store_add(&slot, store.get(), &num, ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
            allocated2.push_back(slot);
        }

        for (size_t i = 0; i < allocated2.size(); ++i) {
            sa_status const status = object_store_remove(store.get(), allocated[i], ta_uuid());
            ASSERT_EQ(status, SA_STATUS_OK);
        }
    }

    TEST(ObjectStoreSize, nominal) {
        size_t const num = 128;
        std::shared_ptr<object_store_t> const store(object_store_init(noop, num, "TEST"), object_store_shutdown);
        ASSERT_NE(store, nullptr);

        ASSERT_EQ(num, object_store_size(store.get()));
    }
} // namespace
