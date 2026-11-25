/*
 * Copyright 2020-2026 Comcast Cable Communications Management, LLC
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
#include <gtest/gtest.h>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <vector>

namespace {
    // Imports DH domain parameters, and a public key if pub is not NULL, through the SecApi provider's DH key
    // management. Returns the result of EVP_PKEY_fromdata, or -1 if the test setup failed.
    int import_dh(
            const BIGNUM* p,
            const BIGNUM* g,
            const BIGNUM* pub,
            int selection) {

        OSSL_LIB_CTX* lib_ctx = sa_get_provider();
        if (lib_ctx == nullptr)
            return -1;

        std::shared_ptr<OSSL_PARAM_BLD> const bld(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
        if (bld == nullptr ||
                OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_FFC_P, p) != 1 ||
                OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_FFC_G, g) != 1)
            return -1;

        if (pub != nullptr && OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub) != 1)
            return -1;

        std::shared_ptr<OSSL_PARAM> const params(OSSL_PARAM_BLD_to_param(bld.get()), OSSL_PARAM_free);
        if (params == nullptr)
            return -1;

        std::shared_ptr<EVP_PKEY_CTX> const ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, "DH", nullptr),
                EVP_PKEY_CTX_free);
        if (ctx == nullptr || EVP_PKEY_fromdata_init(ctx.get()) != 1)
            return -1;

        EVP_PKEY* evp_pkey = nullptr;
        int const result = EVP_PKEY_fromdata(ctx.get(), &evp_pkey, selection, params.get());
        EVP_PKEY_free(evp_pkey);
        return result;
    }

    // Returns a random odd number of exactly bits bits.
    std::shared_ptr<BIGNUM> odd_bn(int bits) {
        std::shared_ptr<BIGNUM> bn(BN_new(), BN_free);
        if (bn == nullptr || BN_rand(bn.get(), bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) != 1)
            return nullptr;

        return bn;
    }

    std::shared_ptr<BIGNUM> word_bn(BN_ULONG value) {
        std::shared_ptr<BIGNUM> bn(BN_new(), BN_free);
        if (bn == nullptr || BN_set_word(bn.get(), value) != 1)
            return nullptr;

        return bn;
    }

    class SaProviderKeymgmtDhImportTest : public ::testing::TestWithParam<int> {};

    TEST_P(SaProviderKeymgmtDhImportTest, importDhParameters) {
        auto p = odd_bn(GetParam());
        auto g = word_bn(2);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 1);
    }

    // DH_MAX_MOD_SIZE (4096 bits) is the largest p the TA supports.
    INSTANTIATE_TEST_SUITE_P(
            SaProviderKeymgmtDhImportTests,
            SaProviderKeymgmtDhImportTest,
            ::testing::Values(2048, 3072, DH_MAX_MOD_SIZE * 8));

    class SaProviderKeymgmtDhImportOversizeTest : public ::testing::TestWithParam<int> {};

    TEST_P(SaProviderKeymgmtDhImportOversizeTest, importDhParametersFailsOversizeP) {
        auto p = odd_bn(GetParam());
        auto g = word_bn(2);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 0);
    }

    // One byte over DH_MAX_MOD_SIZE, and 8192 bits.
    INSTANTIATE_TEST_SUITE_P(
            SaProviderKeymgmtDhImportOversizeTests,
            SaProviderKeymgmtDhImportOversizeTest,
            ::testing::Values(DH_MAX_MOD_SIZE * 8 + 8, 8192));

    TEST(SaProviderKeymgmtDhImportFailTest, importDhParametersFailsHugeP) {
        auto p = odd_bn(65536 * 8);
        auto g = word_bn(2);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 0);
    }

    TEST(SaProviderKeymgmtDhImportFailTest, importDhParametersFailsOversizeG) {
        auto p = odd_bn(2048);
        auto g = odd_bn(8192);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 0);
    }

    TEST(SaProviderKeymgmtDhImportFailTest, importDhParametersFailsGLongerThanP) {
        // g fits in the header but is longer than p.
        auto p = odd_bn(2048);
        auto g = odd_bn(3072);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 0);
    }

    TEST(SaProviderKeymgmtDhImportFailTest, importDhParametersFailsZeroP) {
        auto p = word_bn(0);
        auto g = word_bn(2);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 0);
    }

    TEST(SaProviderKeymgmtDhImportFailTest, importDhParametersFailsZeroG) {
        auto p = odd_bn(2048);
        auto g = word_bn(0);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), nullptr, EVP_PKEY_KEY_PARAMETERS), 0);
    }

    TEST(SaProviderKeymgmtDhImportFailTest, importDhParametersFailsNonIntegerG) {
        OSSL_LIB_CTX* lib_ctx = sa_get_provider();
        ASSERT_NE(lib_ctx, nullptr);
        auto p = odd_bn(2048);
        ASSERT_NE(p, nullptr);
        std::shared_ptr<OSSL_PARAM_BLD> const bld(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
        ASSERT_NE(bld, nullptr);
        ASSERT_EQ(OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_FFC_P, p.get()), 1);
        ASSERT_EQ(OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_FFC_G, "2", 0), 1);
        std::shared_ptr<OSSL_PARAM> const params(OSSL_PARAM_BLD_to_param(bld.get()), OSSL_PARAM_free);
        ASSERT_NE(params, nullptr);

        std::shared_ptr<EVP_PKEY_CTX> const ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, "DH", nullptr),
                EVP_PKEY_CTX_free);
        ASSERT_NE(ctx, nullptr);
        ASSERT_EQ(EVP_PKEY_fromdata_init(ctx.get()), 1);
        EVP_PKEY* evp_pkey = nullptr;
        ASSERT_EQ(EVP_PKEY_fromdata(ctx.get(), &evp_pkey, EVP_PKEY_KEY_PARAMETERS, params.get()), 0);
        EVP_PKEY_free(evp_pkey);
    }

    TEST(SaProviderKeymgmtDhPublicKeyTest, importDhPublicKey) {
        auto p = odd_bn(2048);
        auto g = word_bn(2);
        auto pub = word_bn(3);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_NE(pub, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), pub.get(), EVP_PKEY_PUBLIC_KEY), 1);
    }

    TEST(SaProviderKeymgmtDhPublicKeyTest, importDhPublicKeyFailsOversizeP) {
        // A public key import also copies p and g into the key header.
        auto p = odd_bn(8192);
        auto g = word_bn(2);
        auto pub = word_bn(3);
        ASSERT_NE(p, nullptr);
        ASSERT_NE(g, nullptr);
        ASSERT_NE(pub, nullptr);
        ASSERT_EQ(import_dh(p.get(), g.get(), pub.get(), EVP_PKEY_PUBLIC_KEY), 0);
    }
} // namespace
#endif
