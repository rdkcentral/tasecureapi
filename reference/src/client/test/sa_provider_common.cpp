/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

#include "sa_provider_common.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#include <openssl/evp.h>

using namespace client_test_helpers;

const char* SaProviderTest::get_key_name(
        sa_key_type key_type,
        sa_elliptic_curve curve) {
    switch (key_type) {
        case SA_KEY_TYPE_RSA:
            return "RSA";

        case SA_KEY_TYPE_EC:
            if (is_pcurve(curve))
                return "EC";
            else if (curve == SA_ELLIPTIC_CURVE_ED25519)
                return "ED25519";
            else if (curve == SA_ELLIPTIC_CURVE_ED448)
                return "ED448";
            else if (curve == SA_ELLIPTIC_CURVE_X25519)
                return "X25519";
            else if (curve == SA_ELLIPTIC_CURVE_X448)
                return "X448";
            else
                return "";

        default:
            return "";
    }
}

bool SaProviderTest::verifyEncrypt(
        std::vector<uint8_t>& encrypted,
        std::vector<uint8_t>& clear,
        std::vector<uint8_t>& clear_key,
        std::vector<uint8_t>& iv,
        std::vector<uint8_t>& aad,
        std::vector<uint8_t>& tag,
        const char* algorithm_name,
        int padded) {
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::shared_ptr<EVP_CIPHER> cipher = {EVP_CIPHER_fetch(nullptr, algorithm_name, nullptr), EVP_CIPHER_free};

    if (EVP_DecryptInit(cipher_ctx.get(), cipher.get(), clear_key.data(), iv.data()) != 1) {
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

bool SaProviderTest::doEncrypt(
        std::vector<uint8_t>& encrypted,
        std::vector<uint8_t>& clear,
        std::vector<uint8_t>& clear_key,
        std::vector<uint8_t>& iv,
        std::vector<uint8_t>& aad,
        std::vector<uint8_t>& tag,
        const char* algorithm_name,
        int padded) {
    encrypted.resize(clear.size() + 16);
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::shared_ptr<EVP_CIPHER> cipher = {EVP_CIPHER_fetch(nullptr, algorithm_name, nullptr), EVP_CIPHER_free};

    if (EVP_EncryptInit(cipher_ctx.get(), cipher.get(), clear_key.data(), iv.data()) != 1) {
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

std::shared_ptr<EVP_PKEY> SaProviderTest::generate_sa_key(
        OSSL_LIB_CTX* lib_ctx,
        sa_key_type key_type,
        size_t& key_length,
        sa_elliptic_curve& curve) {

    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_ctx;
    EVP_PKEY* evp_pkey = nullptr;
    do {
        if (key_type == SA_KEY_TYPE_RSA) {
            evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_from_name(lib_ctx, "RSA", nullptr),
                    EVP_PKEY_CTX_free);
            if (evp_pkey_ctx == nullptr) {
                ERROR("EVP_PKEY_CTX_new_from_name failed");
                break;
            }
        } else if (key_type == SA_KEY_TYPE_EC) {
            curve = static_cast<sa_elliptic_curve>(key_length);
            int type = ec_get_nid(curve);
            if (type == 0) {
                ERROR("ec_get_nid failed");
                break;
            }

            if (is_pcurve(curve)) {
                EVP_PKEY_CTX* temp = EVP_PKEY_CTX_new_from_name(lib_ctx, "EC", nullptr);
                auto evp_pkey_param_ctx = std::shared_ptr<EVP_PKEY_CTX>(temp, EVP_PKEY_CTX_free);
                if (evp_pkey_param_ctx == nullptr) {
                    ERROR("EVP_PKEY_CTX_new_from_name failed");
                    break;
                }

                if (EVP_PKEY_paramgen_init(evp_pkey_param_ctx.get()) != 1) {
                    ERROR("EVP_PKEY_paramgen_init failed");
                    break;
                }

                if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_pkey_param_ctx.get(), type) != 1) {
                    ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
                    break;
                }

                if (EVP_PKEY_CTX_set_ec_param_enc(evp_pkey_param_ctx.get(), OPENSSL_EC_NAMED_CURVE) != 1) {
                    ERROR("EVP_PKEY_CTX_set_ec_param_enc failed");
                    break;
                }

                EVP_PKEY* evp_pkey_params = nullptr;
                if (EVP_PKEY_paramgen(evp_pkey_param_ctx.get(), &evp_pkey_params) <= 0) {
                    ERROR("EVP_PKEY_paramgen failed");
                    break;
                }

                evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(evp_pkey_params, nullptr),
                        EVP_PKEY_CTX_free);
                EVP_PKEY_free(evp_pkey_params);
                if (evp_pkey_ctx == nullptr) {
                    ERROR("EVP_PKEY_CTX_new failed");
                    break;
                }
            } else {
                const char* name;
                if (type == EVP_PKEY_X25519) {
                    name = "X25519";
                } else if (type == EVP_PKEY_X448) {
                    name = "X448";
                } else if (type == EVP_PKEY_ED25519) {
                    name = "ED25519";
                } else if (type == EVP_PKEY_ED448) {
                    name = "ED448";
                } else {
                    ERROR("Unknown key type");
                    break;
                }

                evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_from_name(lib_ctx, name, nullptr),
                        EVP_PKEY_CTX_free);
            }
        } else if (key_type == SA_KEY_TYPE_DH) {
            auto dh_parameters = get_dh_parameters(key_length);
            auto p = std::get<0>(dh_parameters);
            auto g = std::get<1>(dh_parameters);

            std::vector<uint8_t> p_buf(p.size());
            std::vector<uint8_t> g_buf(g.size());
            OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p_buf.data(), p_buf.size()),
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, g_buf.data(), g_buf.size()),
                    OSSL_PARAM_construct_end()};
            auto p_bn = std::shared_ptr<BIGNUM>(BN_native2bn(p.data(), static_cast<int>(p.size()), nullptr), BN_free);
            if (p_bn == nullptr) {
                ERROR("BN_native2bn failed");
                break;
            }

            auto g_bn = std::shared_ptr<BIGNUM>(BN_native2bn(g.data(), static_cast<int>(g.size()), nullptr), BN_free);
            if (g_bn == nullptr) {
                ERROR("BN_native2bn failed");
                break;
            }

            if (OSSL_PARAM_set_BN(&params[0], p_bn.get()) != 1) {
                ERROR("OSSL_PARAM_set_BN failed");
                break;
            }

            if (OSSL_PARAM_set_BN(&params[1], g_bn.get()) != 1) {
                ERROR("OSSL_PARAM_set_BN failed");
                break;
            }

            auto evp_pkey_param_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_from_name(lib_ctx, "DH", nullptr),
                    EVP_PKEY_CTX_free);
            if (evp_pkey_param_ctx == nullptr) {
                ERROR("EVP_PKEY_CTX_new_from_name failed");
                break;
            }

            if (EVP_PKEY_fromdata_init(evp_pkey_param_ctx.get()) != 1) {
                ERROR("EVP_PKEY_fromdata_init failed");
                break;
            }

            EVP_PKEY* evp_pkey_params = nullptr;
            if (EVP_PKEY_fromdata(evp_pkey_param_ctx.get(), &evp_pkey_params, EVP_PKEY_KEY_PARAMETERS, params) != 1) {
                ERROR("EVP_PKEY_fromdata failed");
                break;
            }

            evp_pkey_ctx = std::shared_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(evp_pkey_params, nullptr), EVP_PKEY_CTX_free);
            EVP_PKEY_free(evp_pkey_params);
            if (evp_pkey_ctx == nullptr) {
                ERROR("EVP_PKEY_CTX_new failed");
                break;
            }
        }

        if (EVP_PKEY_keygen_init(evp_pkey_ctx.get()) != 1) {
            ERROR("EVP_PKEY_keygen_init failed");
            break;
        }

        if (key_type == SA_KEY_TYPE_RSA) {
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(evp_pkey_ctx.get(), static_cast<int>(key_length * 8)) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
                break;
            }
        }

        if (EVP_PKEY_keygen(evp_pkey_ctx.get(), &evp_pkey) != 1) {
            ERROR("EVP_PKEY_keygen failed");
            break;
        }
    } while (false);

    return std::shared_ptr<EVP_PKEY>(evp_pkey, EVP_PKEY_free);
}

#endif
