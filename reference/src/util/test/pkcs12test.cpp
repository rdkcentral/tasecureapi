/**
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

#include "pkcs12.h"
#include "common.h"
#include "gtest/gtest.h" // NOLINT
#include <cstdlib>

namespace {
    TEST(Pkcs12Test, parsePkcs12) {
        setenv("ROOT_KEYSTORE_PASSWORD", DEFAULT_ROOT_KEYSTORE_PASSWORD, 1);
        setenv("ROOT_KEYSTORE", "root_keystore.p12", 1);

        uint8_t key[SYM_256_KEY_SIZE];
        size_t key_length = SYM_256_KEY_SIZE;
        char name[MAX_SIGNATURE_LENGTH];
        size_t name_length = MAX_SIGNATURE_LENGTH;
        ASSERT_EQ(load_pkcs12_secret_key(key, &key_length, name, &name_length), true);
        ASSERT_EQ(key_length, SYM_128_KEY_SIZE);
        ASSERT_EQ(name_length, 16);
        ASSERT_EQ(memcmp(name, "fffffffffffffffe", 16), 0);
    }

    TEST(Pkcs12Test, parsePkcs12Common) {
        setenv("ROOT_KEYSTORE_PASSWORD", DEFAULT_ROOT_KEYSTORE_PASSWORD, 1);
        setenv("ROOT_KEYSTORE", "root_keystore.p12", 1);

        uint8_t key[SYM_256_KEY_SIZE];
        size_t key_length = SYM_256_KEY_SIZE;
        char name[MAX_SIGNATURE_LENGTH];
        size_t name_length = MAX_SIGNATURE_LENGTH;
        strcpy(name, COMMON_ROOT_NAME);
        ASSERT_EQ(load_pkcs12_secret_key(key, &key_length, name, &name_length), true);
        ASSERT_EQ(key_length, SYM_128_KEY_SIZE);
        ASSERT_EQ(name_length, 6);
        ASSERT_EQ(memcmp(name, "common", 6), 0);
    }
} // namespace
