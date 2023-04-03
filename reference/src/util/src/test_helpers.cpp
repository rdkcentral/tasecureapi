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

#include "test_helpers.h"
#include "digest_util.h"
#include "log.h"
#include "sa.h"
#include <openssl/rand.h>

namespace test_helpers {
    std::vector<uint8_t> random(size_t size) {
        std::vector<uint8_t> data(size);

        if (RAND_bytes(data.data(), static_cast<int>(data.size())) != 1) {
            ERROR("RAND_bytes failed");
            return {};
        }

        return data;
    }

    bool digest_openssl(
            std::vector<uint8_t>& out,
            sa_digest_algorithm digest_algorithm,
            const std::vector<uint8_t>& in1,
            const std::vector<uint8_t>& in2,
            const std::vector<uint8_t>& in3) {

        size_t required_length = digest_length(digest_algorithm);

        bool status = false;
        EVP_MD_CTX* context;
        do {
            context = EVP_MD_CTX_create();
            if (context == nullptr) {
                ERROR("EVP_MD_CTX_create failed");
                break;
            }

            const EVP_MD* md = digest_mechanism(digest_algorithm);
            if (md == nullptr) {
                ERROR("digest_mechanism failed");
                break;
            }

            if (EVP_DigestInit_ex(context, md, nullptr) != 1) {
                ERROR("EVP_DigestInit_ex failed");
                break;
            }

            if (!in1.empty()) {
                if (EVP_DigestUpdate(context, in1.data(), in1.size()) != 1) {
                    ERROR("EVP_DigestUpdate failed");
                    break;
                }
            }

            if (!in2.empty()) {
                if (EVP_DigestUpdate(context, in2.data(), in2.size()) != 1) {
                    ERROR("EVP_DigestUpdate failed");
                    break;
                }
            }

            if (!in3.empty()) {
                if (EVP_DigestUpdate(context, in3.data(), in3.size()) != 1) {
                    ERROR("EVP_DigestUpdate failed");
                    break;
                }
            }

            unsigned int length = required_length;
            out.resize(required_length);
            if (EVP_DigestFinal_ex(context, out.data(), &length) != 1) {
                ERROR("EVP_DigestFinal_ex failed");
                break;
            }

            status = true;

        } while (false);

        EVP_MD_CTX_destroy(context);

        return status;
    }
} // namespace test_helpers
