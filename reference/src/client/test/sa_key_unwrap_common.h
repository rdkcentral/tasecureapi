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
#ifndef SA_KEY_UNWRAP_COMMON_H
#define SA_KEY_UNWRAP_COMMON_H

#include "sa.h"
#include "sa_key_common.h"
#include "gtest/gtest.h"
#include <memory>
#include <vector>

class SaKeyUnwrapBase : public SaKeyBase {
protected:
    /**
     * Wraps a key.
     * @param[out] wrapping_key returns the wrapping key.
     * @param[out] clear_wrapping_key returns the clear wrapping key.
     * @param[out] wrapped_key returns the wrapped key.
     * @param[out] wrapping_parameters returns the key wrapping parameters.
     * @param[in] wrapping_key_size the size of the wrapping key.
     * @param[in] clear_key the key to wrap.
     * @param[in] wrapping_algorithm the wrapping algorithm to use.
     * @return the status of the operation.
     */
    static sa_status wrap_key(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key,
            sa_cipher_algorithm wrapping_algorithm,
            sa_digest_algorithm oaep_digest_algorithm,
            sa_digest_algorithm oaep_mgf1_digest_algorithm,
            size_t oaep_label_length);

private:
    static sa_status wrap_key_aes_cbc(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key,
            sa_cipher_algorithm wrapping_algorithm);

    static sa_status wrap_key_aes_ecb(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key,
            sa_cipher_algorithm wrapping_algorithm);

    static sa_status wrap_key_aes_ctr(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key);

    static sa_status wrap_key_aes_gcm(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key);

    static sa_status wrap_key_chacha20(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key);

    static sa_status wrap_key_chacha20_poly1305(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key);

    static sa_status wrap_key_rsa(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key,
            sa_cipher_algorithm wrapping_algorithm,
            sa_digest_algorithm digest_algorithm,
            sa_digest_algorithm mgf1_digest_algorithm,
            size_t label_length);

    static sa_status wrap_key_el_gamal(
            std::shared_ptr<sa_key>& wrapping_key,
            std::vector<uint8_t>& clear_wrapping_key,
            std::vector<uint8_t>& wrapped_key,
            std::shared_ptr<void>& wrapping_parameters,
            size_t wrapping_key_size,
            const std::vector<uint8_t>& clear_key,
            sa_elliptic_curve curve);
};

using SaKeyUnwrapNominalTestType = std::tuple<std::tuple<size_t, sa_key_type>,
        std::tuple<sa_cipher_algorithm, size_t, sa_digest_algorithm, sa_digest_algorithm, size_t>>;

class SaKeyUnwrapTest : public ::testing::TestWithParam<SaKeyUnwrapNominalTestType>, public SaKeyUnwrapBase {};

class SaKeyUnwrapAesCbcTest : public ::testing::TestWithParam<sa_cipher_algorithm>, public SaKeyUnwrapBase {};

class SaKeyUnwrapAesEcbTest : public ::testing::TestWithParam<sa_cipher_algorithm>, public SaKeyUnwrapBase {};

class SaKeyUnwrapAesCtrTest : public ::testing::Test, public SaKeyUnwrapBase {};

class SaKeyUnwrapAesGcmTest : public ::testing::Test, public SaKeyUnwrapBase {};

class SaKeyUnwrapChacha20Test : public ::testing::Test, public SaKeyUnwrapBase {};

class SaKeyUnwrapChacha20Poly1305Test : public ::testing::Test, public SaKeyUnwrapBase {};

class SaKeyUnwrapRsaTest : public ::testing::TestWithParam<sa_cipher_algorithm>, public SaKeyUnwrapBase {};

class SaKeyUnwrapEcTest : public ::testing::Test, public SaKeyUnwrapBase {};

#endif // SA_KEY_UNWRAP_COMMON_H
