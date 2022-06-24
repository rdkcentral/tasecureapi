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

#include "slots.h"
#include "gtest/gtest.h"

namespace {
    TEST(SlotsInit, nominal) {
        size_t number_of_slots = 128;
        std::shared_ptr<slots_t> slots(slots_init(number_of_slots), slots_shutdown);
        ASSERT_NE(slots, nullptr);
    }

    TEST(SlotsInit, invalidnumberOfSlots) {
        size_t number_of_slots = 129;
        std::shared_ptr<slots_t> slots(slots_init(number_of_slots), slots_shutdown);
        ASSERT_EQ(slots, nullptr);
    }

    TEST(SlotsShutdown, null) {
        EXPECT_NO_THROW(slots_shutdown(nullptr)); // NOLINT
    }

    TEST(SlotsAllocate, nominal) {
        size_t number_of_slots = 128;
        std::shared_ptr<slots_t> slots(slots_init(number_of_slots), slots_shutdown);
        ASSERT_NE(slots, nullptr);

        size_t slot = slots_allocate(slots.get());
        EXPECT_NE(slot, SLOT_INVALID);
        slots_free(slots.get(), slot);
    }

    TEST(SlotsAllocate, failonmaxplusone) {
        size_t number_of_slots = 128;
        std::shared_ptr<slots_t> slots(slots_init(number_of_slots), slots_shutdown);
        ASSERT_NE(slots, nullptr);

        std::vector<slot_t> allocated;
        for (size_t i = 0; i < number_of_slots; ++i) {
            size_t slot = slots_allocate(slots.get());
            EXPECT_NE(slot, SLOT_INVALID);
            allocated.push_back(slot);
        }

        // allocate one past the limit
        size_t slot = slots_allocate(slots.get());
        EXPECT_EQ(slot, SLOT_INVALID);
        slots_free(slots.get(), slot);

        for (unsigned int i : allocated) {
            slots_free(slots.get(), i);
        }
    }

    TEST(SlotsFree, doublemax) {
        size_t number_of_slots = 128;
        std::shared_ptr<slots_t> slots(slots_init(number_of_slots), slots_shutdown);
        ASSERT_NE(slots, nullptr);

        std::vector<slot_t> allocated;
        for (size_t i = 0; i < number_of_slots; ++i) {
            size_t slot = slots_allocate(slots.get());
            EXPECT_NE(slot, SLOT_INVALID);
            allocated.push_back(slot);
        }

        for (unsigned int i : allocated) {
            slots_free(slots.get(), i);
        }

        std::vector<slot_t> allocated2;
        for (size_t i = 0; i < number_of_slots; ++i) {
            size_t slot = slots_allocate(slots.get());
            EXPECT_NE(slot, SLOT_INVALID);
            allocated2.push_back(slot);
        }

        for (unsigned int i : allocated2) {
            slots_free(slots.get(), i);
        }
    }
} // namespace
