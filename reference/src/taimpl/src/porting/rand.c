/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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

#include "porting/rand.h" // NOLINT
#include "log.h"
#include <openssl/rand.h>

bool rand_bytes(void* out, size_t out_length) {
    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (!RAND_bytes(out, (int) out_length)) {
        ERROR("RAND_bytes failed");
        return false;
    }

    return true;
}
