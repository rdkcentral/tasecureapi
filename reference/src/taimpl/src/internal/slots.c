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

#include "slots.h" // NOLINT
#include "log.h"
#include "porting/memory.h"
#include <inttypes.h>
#include <memory.h>

#define BLOCK_IDX(slot) ((slot) / (sizeof(int) * 8))
#define BLOCK_BIT(slot) ((slot) % (sizeof(int) * 8))
#define BLOCK_BITMASK(slot) (1 << (sizeof(int) * 8 - BLOCK_BIT(slot) - 1))

struct slots_s {
    int* bitfield;
    size_t slot_count;
    size_t block_count;
};

slots_t* slots_init(size_t count) {
    if (count % (sizeof(int) * 8)) {
        ERROR("Number of slots has to be a multiple of int bit length");
        return NULL;
    }

    bool status = false;
    slots_t* slots = NULL;
    int* bitfield = NULL;
    do {
        size_t block_count = count / (sizeof(int) * 8);

        bitfield = memory_internal_alloc(sizeof(int) * block_count);
        if (bitfield == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        memory_memset_unoptimizable(bitfield, 0, sizeof(int) * block_count);

        slots = memory_internal_alloc(sizeof(struct slots_s));
        if (slots == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        slots->slot_count = count;
        slots->block_count = block_count;
        slots->bitfield = bitfield;

        // bitfield is now owned by slots instance
        bitfield = NULL;

        status = true;
    } while (false);

    memory_internal_free(bitfield);

    if (!status) {
        memory_internal_free(slots);
        slots = NULL;
    }

    return slots;
}

void slots_shutdown(slots_t* slots) {
    if (slots == NULL) {
        return;
    }

    for (size_t i = 0; i < slots->slot_count; ++i) {
        if (slots->bitfield[BLOCK_IDX(i)] & BLOCK_BITMASK(i)) {
            ERROR("Slot %" PRIu32 " is still allocated on slots_shutdown for slots %p", i, slots);
        }
    }

    memory_internal_free(slots->bitfield);
    memory_internal_free(slots);
}

slot_t slots_allocate(slots_t* slots) {
    if (slots == NULL) {
        ERROR("NULL slots");
        return SLOT_INVALID;
    }

    slot_t slot = SLOT_INVALID;
    for (size_t i = 0; i < slots->block_count; ++i) {
        int least_significant_available = ffs(~slots->bitfield[i]);
        if (least_significant_available != 0) {
            int bitmask = (1 << (least_significant_available - 1));
            slots->bitfield[i] |= bitmask;
            slot = (i + 1) * sizeof(int) * 8 - least_significant_available;
            DEBUG("Allocated slot %" PRIu32 " on slots %p", slot, slots);
            break;
        }
    }

    if (slot == SLOT_INVALID) {
        ERROR("No available slots in slots %p", slots);
    } else {
        DEBUG("Allocated slot %" PRIu32 " on slots %p", slot, slots);
    }

    return slot;
}

void slots_free(
        slots_t* slots,
        slot_t slot) {

    if (slots == NULL) {
        ERROR("NULL slots");
        return;
    }

    if (slot == SLOT_INVALID) {
        // silent noop
        return;
    }

    if (slot >= slots->slot_count) {
        ERROR("Invalid slot");
        return;
    }

    do {
        if (!(slots->bitfield[BLOCK_IDX(slot)] & BLOCK_BITMASK(slot))) {
            WARN("Attempting to release a slot %" PRIu32 " that is not allocated on slots %p", slot, slots);
            break;
        }

        slots->bitfield[BLOCK_IDX(slot)] &= ~BLOCK_BITMASK(slot);

        DEBUG("Released slot %" PRIu32 " on slots %p", slot, slots);
    } while (false);
}
