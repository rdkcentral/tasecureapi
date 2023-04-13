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

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include "common.h"
#include "sa_rights.h"
#include <memory>
#include <openssl/evp.h>
#include <vector>

#define UNSUPPORTED_KEY static_cast<sa_key>(INVALID_HANDLE - 1)
#define UNSUPPORTED_CIPHER (sa_crypto_cipher_context)(INVALID_HANDLE - 1)

namespace test_helpers {
    /**
     * Compute SHA digest value over inputs.
     *
     * @param[out] out output buffer for computed digest value.
     * @param[in] digest_algorithm the algorithm to use in the digest.
     * @param[in] in1 first input buffer.
     * @param[in] in2 second input buffer.
     * @param[in] in3 third input buffer.
     * @return status of the operation
     */
    bool digest_openssl(
            std::vector<uint8_t>& out,
            sa_digest_algorithm digest_algorithm,
            const std::vector<uint8_t>& in1,
            const std::vector<uint8_t>& in2,
            const std::vector<uint8_t>& in3);

    /**
     * Generate a vector of random data.
     *
     * @param[in] size size of the generated vector.
     * @return generated vector.
     */
    std::vector<uint8_t> random(size_t size);
} // namespace test_helpers

#endif // TEST_HELPERS_H
