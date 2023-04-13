/**
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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

#include "sa_engine_common.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/evp.h>

using namespace client_test_helpers;

bool SaEngineTest::verifyEncrypt(
        std::vector<uint8_t>& encrypted,
        std::vector<uint8_t>& clear,
        std::vector<uint8_t>& clear_key,
        std::vector<uint8_t>& iv,
        std::vector<uint8_t>& aad,
        std::vector<uint8_t>& tag,
        const EVP_CIPHER* cipher,
        int padded) {
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit(cipher_ctx.get(), cipher, clear_key.data(), iv.data()) != 1) {
        fprintf(stderr, "EVP_DecryptInit failed");
        return false;
    }

    if (EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_set_padding failed");
        return false;
    }

    std::vector<uint8_t> decrypted(encrypted.size());
    int length;
    int total_length = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), static_cast<int>(aad.size())) != 1) {
            fprintf(stderr, "EVP_DecryptUpdate failed");
            return false;
        }
    }

    if (EVP_DecryptUpdate(cipher_ctx.get(), decrypted.data(), &length, encrypted.data(),
                static_cast<int>(encrypted.size())) != 1) {
        fprintf(stderr, "EVP_DecryptUpdate failed");
        return false;
    }

    total_length += length;
    if (!tag.empty()) {
        if (EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                    static_cast<void*>(tag.data())) != 1) {
            fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed");
            return false;
        }
    }

    if (EVP_DecryptFinal(cipher_ctx.get(), decrypted.data() + total_length, &length) != 1) {
        fprintf(stderr, "EVP_DecryptFinal failed");
        return false;
    }

    total_length += length;
    decrypted.resize(total_length);
    return clear == decrypted;
}

bool SaEngineTest::doEncrypt(
        std::vector<uint8_t>& encrypted,
        std::vector<uint8_t>& clear,
        std::vector<uint8_t>& clear_key,
        std::vector<uint8_t>& iv,
        std::vector<uint8_t>& aad,
        std::vector<uint8_t>& tag,
        const EVP_CIPHER* cipher,
        int padded) {
    encrypted.resize(clear.size() + 16);
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (EVP_EncryptInit(cipher_ctx.get(), cipher, clear_key.data(), iv.data()) != 1) {
        fprintf(stderr, "EVP_EncryptInit failed");
        return false;
    }

    if (EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_set_padding failed");
        return false;
    }

    int length;
    int total_length = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), static_cast<int>(aad.size())) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed");
            return false;
        }
    }

    if (EVP_EncryptUpdate(cipher_ctx.get(), encrypted.data(), &length, clear.data(),
                static_cast<int>(clear.size())) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed");
        return false;
    }

    total_length += length;
    if (EVP_EncryptFinal(cipher_ctx.get(), encrypted.data() + total_length, &length) != 1) {
        fprintf(stderr, "EVP_EncryptFinal failed");
        return false;
    }

    total_length += length;
    if (!tag.empty()) {
        if (EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()),
                    tag.data()) != 1) {
            fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed");
            return false;
        }
    }

    encrypted.resize(total_length);
    return true;
}

#endif
