/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
#include "sa.h"
#include <cstdio>
#include <cstring>
#include <openssl/rand.h>

#define ERROR(msg) printf("%s:%d %s\n", __FILE__, __LINE__, msg);

namespace test_helpers {
    std::vector<uint8_t> random(size_t size) {
        std::vector<uint8_t> data(size);

        if (RAND_bytes(data.data(), static_cast<int>(data.size())) != 1) {
            ERROR("RAND_bytes failed");
            return {};
        }

        return data;
    }

    const EVP_MD* digest_mechanism(sa_digest_algorithm digest_algorithm) {
        switch (digest_algorithm) {
            case SA_DIGEST_ALGORITHM_SHA1:
                return EVP_sha1();

            case SA_DIGEST_ALGORITHM_SHA256:
                return EVP_sha256();

            case SA_DIGEST_ALGORITHM_SHA384:
                return EVP_sha384();

            case SA_DIGEST_ALGORITHM_SHA512:
                return EVP_sha512();

            default:
                ERROR("Unknown digest_algorithm encountered");
                return nullptr;
        }
    }

    size_t digest_length(sa_digest_algorithm digest_algorithm) {
        switch (digest_algorithm) {
            case SA_DIGEST_ALGORITHM_SHA1:
                return SHA1_DIGEST_LENGTH;

            case SA_DIGEST_ALGORITHM_SHA256:
                return SHA256_DIGEST_LENGTH;

            case SA_DIGEST_ALGORITHM_SHA384:
                return SHA384_DIGEST_LENGTH;

            case SA_DIGEST_ALGORITHM_SHA512:
                return SHA512_DIGEST_LENGTH;

            default:
                ERROR("Unknown digest_algorithm encountered");
                break;
        }

        return 0;
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
