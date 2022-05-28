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

#include "sa_crypto_cipher_common.h" // NOLINT
#include "client_test_helpers.h"
#include <openssl/evp.h>

using namespace client_test_helpers;

bool SaCipherCryptoBase::import_key(
        cipher_parameters& parameters,
        sa_key_type key_type,
        size_t key_size) {

    if (key_type == SA_KEY_TYPE_SYMMETRIC) {
        parameters.clear_key = random(key_size);

        sa_rights rights;
        rights_set_allow_all(&rights);

        parameters.key = create_sa_key_symmetric(&rights, parameters.clear_key);
        if (parameters.key == nullptr) {
            ERROR("Invalid key");
            return false;
        }
    } else if (key_type == SA_KEY_TYPE_RSA) {
        parameters.clear_key = get_rsa_private_key(key_size);

        sa_rights rights;
        rights_set_allow_all(&rights);

        parameters.key = create_sa_key_rsa(&rights, parameters.clear_key);
        if (parameters.key == nullptr) {
            ERROR("Invalid key");
            return false;
        }
    } else if (key_type == SA_KEY_TYPE_EC) {
        sa_elliptic_curve curve;
        if (key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P256))
            curve = SA_ELLIPTIC_CURVE_NIST_P256;
        else if (key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P384))
            curve = SA_ELLIPTIC_CURVE_NIST_P384;
        else if (key_size == ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P521))
            curve = SA_ELLIPTIC_CURVE_NIST_P521;
        else
            return false;

        parameters.clear_key = random_ec(key_size);
        parameters.curve = curve;

        sa_rights rights;
        rights_set_allow_all(&rights);

        parameters.key = create_sa_key_ec(&rights, curve, parameters.clear_key);
        if (parameters.key == nullptr) {
            ERROR("Invalid key");
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool SaCipherCryptoBase::get_cipher_parameters(cipher_parameters& parameters) {
    switch (parameters.cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7: {
            parameters.iv = random(AES_BLOCK_SIZE);
            auto* cipher_parameters_aes_cbc = new sa_cipher_parameters_aes_cbc;
            cipher_parameters_aes_cbc->iv = parameters.iv.data();
            cipher_parameters_aes_cbc->iv_length = parameters.iv.size();
            parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_cbc>(cipher_parameters_aes_cbc);
            parameters.end_parameters = nullptr;
            break;
        }
        case SA_CIPHER_ALGORITHM_AES_CTR: {
            parameters.iv = random(AES_BLOCK_SIZE);
            auto* cipher_parameters_aes_ctr = new sa_cipher_parameters_aes_ctr;
            cipher_parameters_aes_ctr->ctr = parameters.iv.data();
            cipher_parameters_aes_ctr->ctr_length = parameters.iv.size();
            parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_ctr>(cipher_parameters_aes_ctr);
            parameters.end_parameters = nullptr;
            break;
        }
        case SA_CIPHER_ALGORITHM_AES_GCM: {
            parameters.iv = random(GCM_IV_LENGTH);
            parameters.aad = random(1024);
            parameters.tag.resize(AES_BLOCK_SIZE);
            auto* cipher_parameters_aes_gcm = new sa_cipher_parameters_aes_gcm;
            cipher_parameters_aes_gcm->iv = parameters.iv.data();
            cipher_parameters_aes_gcm->iv_length = parameters.iv.size();
            cipher_parameters_aes_gcm->aad = parameters.aad.data();
            cipher_parameters_aes_gcm->aad_length = parameters.aad.size();
            parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_gcm>(cipher_parameters_aes_gcm);
            auto* cipher_end_parameters_aes_gcm = new sa_cipher_end_parameters_aes_gcm;
            cipher_end_parameters_aes_gcm->tag = parameters.tag.data();
            cipher_end_parameters_aes_gcm->tag_length = parameters.tag.size();
            parameters.end_parameters = std::shared_ptr<sa_cipher_end_parameters_aes_gcm>(
                    cipher_end_parameters_aes_gcm);
            break;
        }
        case SA_CIPHER_ALGORITHM_CHACHA20: {
            parameters.iv = random(CHACHA20_NONCE_LENGTH);
            parameters.tag = {1, 0, 0, 0};
            auto* cipher_parameters_chacha20 = new sa_cipher_parameters_chacha20;
            cipher_parameters_chacha20->nonce = parameters.iv.data();
            cipher_parameters_chacha20->nonce_length = parameters.iv.size();
            cipher_parameters_chacha20->counter = parameters.tag.data();
            cipher_parameters_chacha20->counter_length = parameters.tag.size();
            parameters.parameters = std::shared_ptr<sa_cipher_parameters_chacha20>(cipher_parameters_chacha20);
            parameters.end_parameters = nullptr;
            break;
        }
        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305: {
            parameters.iv = random(CHACHA20_NONCE_LENGTH);
            parameters.aad = random(1024);
            parameters.tag.resize(AES_BLOCK_SIZE);
            auto* cipher_parameters_chacha20_poly1305 = new sa_cipher_parameters_chacha20_poly1305;
            cipher_parameters_chacha20_poly1305->nonce = parameters.iv.data();
            cipher_parameters_chacha20_poly1305->nonce_length = parameters.iv.size();
            cipher_parameters_chacha20_poly1305->aad = parameters.aad.data();
            cipher_parameters_chacha20_poly1305->aad_length = parameters.aad.size();
            parameters.parameters =
                    std::shared_ptr<sa_cipher_parameters_chacha20_poly1305>(cipher_parameters_chacha20_poly1305);
            auto* cipher_end_parameters_chacha20_poly1305 = new sa_cipher_end_parameters_chacha20_poly1305;
            cipher_end_parameters_chacha20_poly1305->tag = parameters.tag.data();
            cipher_end_parameters_chacha20_poly1305->tag_length = parameters.tag.size();
            parameters.end_parameters = std::shared_ptr<sa_cipher_end_parameters_chacha20_poly1305>(
                    cipher_end_parameters_chacha20_poly1305);
            break;
        }
        default:
            parameters.parameters = nullptr;
    }

    return true;
}

bool SaCipherCryptoBase::verify_encrypt(
        sa_buffer* encrypted,
        std::vector<uint8_t>& clear,
        cipher_parameters& parameters,
        bool padded) {

    if (encrypted->buffer_type == SA_BUFFER_TYPE_CLEAR) {
        std::vector<uint8_t> encrypted_data = {static_cast<uint8_t*>(encrypted->context.clear.buffer),
                static_cast<uint8_t*>(encrypted->context.clear.buffer) + clear.size()};

        // Since we are not calling sa_crypto_cipher_process_last, the padding/tag is not added. Change the mode so that
        // openssl doesn't expect the padding to be there.
        if (!padded) {
            if (parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7)
                parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
            else if (parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7)
                parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
            else if (parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM ||
                     parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305)
                parameters.tag.resize(0);
        }

        auto decrypted = decrypt_openssl(encrypted_data, parameters);
        if (decrypted.empty())
            return false;

        return decrypted == clear;
    }

    // encrypt using OpenSSL
    auto encrypted_data = encrypt_openssl(clear, parameters);
    if (encrypted_data.empty())
        return false;

    // Exclude the padding block since we are not calling sa_crypto_cipher_process_last.
    bool pkcs7 = parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                 parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
    size_t checked_length = !padded && pkcs7 ? encrypted_data.size() - AES_BLOCK_SIZE : encrypted_data.size();
    encrypted_data.resize(checked_length);
    std::vector<uint8_t> hash;
    if (!digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, encrypted_data, {}, {}))
        return false;

    return sa_svp_buffer_check(encrypted->context.svp.buffer, 0, checked_length, SA_DIGEST_ALGORITHM_SHA256,
                   hash.data(), hash.size()) == SA_STATUS_OK;
}

bool SaCipherCryptoBase::verify_decrypt(
        sa_buffer* decrypted,
        std::vector<uint8_t>& clear) {

    if (decrypted->buffer_type == SA_BUFFER_TYPE_CLEAR) {
        std::vector<uint8_t> decrypted_data = {static_cast<uint8_t*>(decrypted->context.clear.buffer),
                static_cast<uint8_t*>(decrypted->context.clear.buffer) + clear.size()};

        return decrypted_data == clear;
    }

    std::vector<uint8_t> hash;
    if (!digest_openssl(hash, SA_DIGEST_ALGORITHM_SHA256, clear, {}, {}))
        return false;

    return sa_svp_buffer_check(decrypted->context.svp.buffer, 0, clear.size(), SA_DIGEST_ALGORITHM_SHA256,
                   hash.data(), hash.size()) == SA_STATUS_OK;
}

std::shared_ptr<sa_crypto_cipher_context> SaCipherCryptoBase::initialize_cipher(
        sa_cipher_mode cipher_mode,
        sa_key_type key_type,
        size_t key_size,
        cipher_parameters& parameters) {

    if (!import_key(parameters, key_type, key_size)) {
        ERROR("import_key failed");
        return nullptr;
    }

    auto cipher = create_uninitialized_sa_crypto_cipher_context();
    if (cipher == nullptr) {
        ERROR("import_key failed");
        return nullptr;
    }

    if (!get_cipher_parameters(parameters)) {
        ERROR("get_cipher_parameters failed");
        return nullptr;
    }

    sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, cipher_mode, *parameters.key,
            parameters.parameters.get());
    if (status == SA_STATUS_OPERATION_NOT_SUPPORTED) {
        *cipher = UNSUPPORTED_CIPHER;
    } else if (status != SA_STATUS_OK) {
        ERROR("sa_crypto_cipher_init failed");
        return nullptr;
    }

    return cipher;
}

std::vector<uint8_t> SaCipherCryptoBase::encrypt_openssl(
        std::vector<uint8_t>& clear,
        cipher_parameters& parameters) {

    std::vector<uint8_t> encrypted;
    bool status;
    switch (parameters.cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC: {
            status = encrypt_aes_cbc_openssl(encrypted, clear, parameters.iv, parameters.clear_key, false);
            break;
        }
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            status = encrypt_aes_cbc_openssl(encrypted, clear, parameters.iv, parameters.clear_key, true);
            break;

        case SA_CIPHER_ALGORITHM_AES_ECB:
            status = encrypt_aes_ecb_openssl(encrypted, clear, parameters.clear_key, false);
            break;

        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            status = encrypt_aes_ecb_openssl(encrypted, clear, parameters.clear_key, true);
            break;

        case SA_CIPHER_ALGORITHM_AES_CTR:
            status = encrypt_aes_ctr_openssl(encrypted, clear, parameters.iv, parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_AES_GCM:
            status = encrypt_aes_gcm_openssl(encrypted, clear, parameters.iv, parameters.aad, parameters.tag,
                    parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20:
            status = encrypt_chacha20_openssl(encrypted, clear, parameters.tag, parameters.iv, parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            status = encrypt_chacha20_poly1305_openssl(encrypted, clear, parameters.iv, parameters.aad, parameters.tag,
                    parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_RSA_PKCS1V15: {
            auto rsa_key = rsa_import_pkcs8(parameters.clear_key);
            if (rsa_key == nullptr) {
                status = false;
                break;
            }

            status = encrypt_rsa_pkcs1v15_openssl(encrypted, clear, rsa_key);
            break;
        }
        case SA_CIPHER_ALGORITHM_RSA_OAEP: {
            auto rsa_key = rsa_import_pkcs8(parameters.clear_key);
            if (rsa_key == nullptr) {
                status = false;
                break;
            }

            status = encrypt_rsa_oaep_openssl(encrypted, clear, rsa_key);
            break;
        }
        case SA_CIPHER_ALGORITHM_EC_ELGAMAL: {
            auto evp_pkey = ec_import_private(parameters.curve, parameters.clear_key);
            if (evp_pkey == nullptr) {
                ERROR("ec_import_private failed");
                status = false;
                break;
            }

            status = encrypt_ec_elgamal_openssl(encrypted, clear, parameters.curve, evp_pkey);
            break;
        }
        default:
            status = false;
    }

    if (!status) {
        ERROR("encrypt_openssl failed");
        return {};
    }

    return encrypted;
}

std::vector<uint8_t> SaCipherCryptoBase::decrypt_openssl(
        std::vector<uint8_t>& encrypted,
        cipher_parameters& parameters) {

    std::vector<uint8_t> decrypted;
    bool status;
    switch (parameters.cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
            status = decrypt_aes_cbc_openssl(decrypted, encrypted, parameters.iv, parameters.clear_key, false);
            break;

        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            status = decrypt_aes_cbc_openssl(decrypted, encrypted, parameters.iv, parameters.clear_key, true);
            break;

        case SA_CIPHER_ALGORITHM_AES_ECB:
            status = decrypt_aes_ecb_openssl(decrypted, encrypted, parameters.clear_key, false);
            break;

        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            status = decrypt_aes_ecb_openssl(decrypted, encrypted, parameters.clear_key, true);
            break;

        case SA_CIPHER_ALGORITHM_AES_CTR:
            status = decrypt_aes_ctr_openssl(decrypted, encrypted, parameters.iv, parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_AES_GCM:
            status = decrypt_aes_gcm_openssl(decrypted, encrypted, parameters.iv, parameters.aad, parameters.tag,
                    parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20:
            status = decrypt_chacha20_openssl(decrypted, encrypted, parameters.tag, parameters.iv,
                    parameters.clear_key);
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            status = decrypt_chacha20_poly1305_openssl(decrypted, encrypted, parameters.iv, parameters.aad,
                    parameters.tag, parameters.clear_key);
            break;

        default:
            status = false;
    }

    if (!status) {
        ERROR("decrypt_openssl failed");
        return {};
    }

    return decrypted;
}

size_t SaCipherCryptoBase::get_required_length(
        sa_cipher_algorithm cipher_algorithm,
        size_t key_length,
        size_t bytes_to_process,
        bool apply_pad) {

    switch (cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CTR:
        case SA_CIPHER_ALGORITHM_AES_ECB:
        case SA_CIPHER_ALGORITHM_AES_GCM:
        case SA_CIPHER_ALGORITHM_CHACHA20:
        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            return bytes_to_process;

        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            return bytes_to_process + (apply_pad ? AES_BLOCK_SIZE : 0);

        case SA_CIPHER_ALGORITHM_RSA_PKCS1V15: {
            return key_length - RSA_PKCS1_PADDING_SIZE;
        }
        case SA_CIPHER_ALGORITHM_RSA_OAEP: {
            return key_length - RSA_OAEP_PADDING_SIZE;
        }
        case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
            return key_length;

        default:
            return 0;
    }
}

bool SaCipherCryptoBase::ec_is_valid_x_coordinate(
        std::shared_ptr<EC_GROUP>& ec_group,
        const std::vector<uint8_t>& coordinate) {

    if (coordinate.size() != static_cast<size_t>(EC_KEY_SIZE(ec_group.get()))) {
        ERROR("Bad coordinate_length");
        return false;
    }

    std::shared_ptr<BIGNUM> x_bignum(BN_new(), BN_free);
    if (x_bignum == nullptr) {
        ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(coordinate.data(), static_cast<int>(coordinate.size()), x_bignum.get()) == nullptr) {
        ERROR("BN_bin2bn failed.");
        return false;
    }

    std::shared_ptr<BN_CTX> context(BN_CTX_new(), BN_CTX_free);
    if (context == nullptr) {
        ERROR("BN_CTX_new failed");
        return false;
    }

    std::shared_ptr<EC_POINT> ec_point(EC_POINT_new(ec_group.get()), EC_POINT_free);
    if (ec_point == nullptr) {
        ERROR("EC_POINT_new failed");
        return false;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    return EC_POINT_set_compressed_coordinates(ec_group.get(), ec_point.get(), x_bignum.get(), 0, context.get()) == 1;
#else
    return EC_POINT_set_compressed_coordinates_GFp(ec_group.get(), ec_point.get(), x_bignum.get(), 0,
                   context.get()) == 1;
#endif
}

void SaCryptoCipherDecryptTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED && std::get<3>(GetParam()) == SA_BUFFER_TYPE_SVP)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

void SaCryptoCipherEncryptTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED && std::get<3>(GetParam()) == SA_BUFFER_TYPE_SVP)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

void SaCryptoCipherProcessLastTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED && std::get<3>(GetParam()) == SA_BUFFER_TYPE_SVP)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

void SaCryptoCipherWithSvpTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED && std::get<0>(GetParam()) == SA_BUFFER_TYPE_SVP)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

void SaCryptoCipherSvpOnlyTest::SetUp() {
    if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaCryptoCipherEncryptTests,
        SaCryptoCipherEncryptTest,
        ::testing::Values(
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoCipherDecryptTests,
        SaCryptoCipherDecryptTest,
        ::testing::Values(
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_KEY_TYPE_RSA, RSA_1024_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_KEY_TYPE_RSA, RSA_2048_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_KEY_TYPE_RSA, RSA_3072_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_KEY_TYPE_RSA, RSA_4096_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),

            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_OAEP, SA_KEY_TYPE_RSA, RSA_1024_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_OAEP, SA_KEY_TYPE_RSA, RSA_2048_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_OAEP, SA_KEY_TYPE_RSA, RSA_3072_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_RSA_OAEP, SA_KEY_TYPE_RSA, RSA_4096_BYTE_LENGTH, SA_BUFFER_TYPE_CLEAR),

            std::make_tuple(SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_KEY_TYPE_EC, ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P256), SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_KEY_TYPE_EC, ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P384), SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_EC_ELGAMAL, SA_KEY_TYPE_EC, ec_get_key_size(SA_ELLIPTIC_CURVE_NIST_P521), SA_BUFFER_TYPE_CLEAR)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoCipherProcessLastTests,
        SaCryptoCipherProcessLastTest,
        ::testing::Values(
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_CTR, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, SA_BUFFER_TYPE_SVP),
            std::make_tuple(SA_CIPHER_ALGORITHM_AES_GCM, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP),

            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_CLEAR),
            std::make_tuple(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE, SA_BUFFER_TYPE_SVP)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoCipherWithSvpTests,
        SaCryptoCipherWithSvpTest,
        ::testing::Values(
            std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_CIPHER_MODE_ENCRYPT),
            std::make_tuple(SA_BUFFER_TYPE_SVP, SA_CIPHER_MODE_ENCRYPT),
            std::make_tuple(SA_BUFFER_TYPE_CLEAR, SA_CIPHER_MODE_DECRYPT),
            std::make_tuple(SA_BUFFER_TYPE_SVP, SA_CIPHER_MODE_DECRYPT)));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoCipherElGamalTests,
        SaCryptoCipherElGamalTest,
        ::testing::Values(
            SA_ELLIPTIC_CURVE_NIST_P256,
            SA_ELLIPTIC_CURVE_NIST_P384,
            SA_ELLIPTIC_CURVE_NIST_P521));

INSTANTIATE_TEST_SUITE_P(
        SaCryptoCipherElGamalFailTests,
        SaCryptoCipherElGamalFailTest,
        ::testing::Values(
            SA_ELLIPTIC_CURVE_ED25519,
            SA_ELLIPTIC_CURVE_X25519,
            SA_ELLIPTIC_CURVE_ED448,
            SA_ELLIPTIC_CURVE_X448));
// clang-format on
