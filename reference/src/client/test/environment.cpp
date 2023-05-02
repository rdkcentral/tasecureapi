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

#include "gtest/gtest.h"
#include <openssl/bio.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/err.h>
#include <openssl/evp.h>

#endif

class Environment : public ::testing::Environment {
public:
    ~Environment() override = default;

    // Override this to define how to set up the environment.
    void SetUp() override {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        OpenSSL_add_all_algorithms();
#endif
    }

    // Override this to define how to tear down the environment.
    void TearDown() override {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
        ERR_remove_state(0);
#endif
    }
};

static const ::testing::Environment* const env =
        ::testing::AddGlobalTestEnvironment(new Environment);
