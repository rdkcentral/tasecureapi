/*
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
#include "client_test_helpers.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>

using namespace client_test_helpers;

TEST_P(SaProviderPkcs7Test, pkcs7Test) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    const auto* digest_name = std::get<2>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp_evp_pkey = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp_evp_pkey, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp_evp_pkey, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp_evp_pkey, EVP_PKEY_free);

    auto x509 = std::shared_ptr<X509>(X509_new_ex(lib_ctx, nullptr), X509_free);
    ASSERT_NE(x509, nullptr);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1), 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L);
    ASSERT_EQ(X509_set_pubkey(x509.get(), evp_pkey.get()), 1);
    auto x509_name = std::shared_ptr<X509_NAME>(X509_NAME_new(), X509_NAME_free);
    ASSERT_NE(x509_name, nullptr);
    int result = X509_NAME_add_entry_by_txt(x509_name.get(), "C", MBSTRING_ASC,
            (unsigned char*) "US", -1, -1, 0); // NOLINT
    ASSERT_EQ(result, 1);
    result = X509_NAME_add_entry_by_txt(x509_name.get(), "O", MBSTRING_ASC,
            (unsigned char*) "RDKCentral", -1, -1, 0); // NOLINT
    ASSERT_EQ(result, 1);
    result = X509_NAME_add_entry_by_txt(x509_name.get(), "CN", MBSTRING_ASC,
            (unsigned char*) "test.rdkcentral.com", -1, -1, 0); // NOLINT
    ASSERT_EQ(result, 1);
    ASSERT_EQ(X509_set_subject_name(x509.get(), x509_name.get()), 1);
    ASSERT_EQ(X509_set_issuer_name(x509.get(), x509_name.get()), 1);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, digest_name, nullptr), EVP_MD_free);
    ASSERT_GT(X509_sign(x509.get(), evp_pkey.get(), evp_md.get()), 1);

    auto bio = std::shared_ptr<BIO>(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())), BIO_free);
    ASSERT_NE(bio, nullptr);

    PKCS7* temp_pkcs7 = PKCS7_sign_ex(x509.get(), evp_pkey.get(), nullptr, bio.get(), PKCS7_BINARY, lib_ctx, nullptr);
    auto pkcs7 = std::shared_ptr<PKCS7>(temp_pkcs7, PKCS7_free);
    ASSERT_NE(pkcs7, nullptr);

    int message_length = i2d_PKCS7(pkcs7.get(), nullptr);
    ASSERT_GT(message_length, 0);
    std::vector<uint8_t> pkcs7_message(message_length);
    uint8_t* p_pkcs7_message = pkcs7_message.data();
    message_length = i2d_PKCS7(pkcs7.get(), &p_pkcs7_message);
    ASSERT_GT(message_length, 0);

    const uint8_t* p_pkcs7_message2 = pkcs7_message.data();
    temp_pkcs7 = d2i_PKCS7(nullptr, &p_pkcs7_message2, static_cast<long>(pkcs7_message.size())); // NOLINT
    auto pkcs7_verify = std::shared_ptr<PKCS7>(temp_pkcs7, PKCS7_free);

    auto out = std::shared_ptr<BIO>(BIO_new(BIO_s_mem()), BIO_free);
    ASSERT_EQ(PKCS7_verify(pkcs7_verify.get(), nullptr, nullptr, nullptr, out.get(), PKCS7_NOVERIFY), 1);

    BUF_MEM* bptr;
    BIO_ctrl(out.get(), BIO_C_GET_BUF_MEM_PTR, 0, &bptr);
    ASSERT_EQ(memcmp(bptr->data, data.data(), data.size()), 0);
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProviderPkcs7RsaTest,
        SaProviderPkcs7Test,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values("SHA1", "SHA256", "SHA384", "SHA512")));

INSTANTIATE_TEST_SUITE_P(
        SaProviderPkcs7EcTests,
        SaProviderPkcs7Test,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224, SA_ELLIPTIC_CURVE_NIST_P256,
                    SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521),
                ::testing::Values("SHA1", "SHA256", "SHA384", "SHA512")));
// clang-format on

#endif
