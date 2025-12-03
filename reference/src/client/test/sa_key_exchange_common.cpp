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

#include "sa_key_exchange_common.h" // NOLINT
#include "client_test_helpers.h"

using namespace client_test_helpers;

bool SaKeyExchangeNetflixTest::netflix_compute_secret(
        std::vector<uint8_t>& kenc,
        std::vector<uint8_t>& khmac,
        std::vector<uint8_t>& kwrap,
        const std::vector<uint8_t>& kd,
        const std::vector<uint8_t>& shared_secret) {

    std::vector<uint8_t> temp_key;
    if (!digest(temp_key, SA_DIGEST_ALGORITHM_SHA384, kd, {}, {})) {
        ERROR("digest");
        return false;
    }

    std::vector<uint8_t> temp_data(shared_secret);
    if (temp_data[0] != 0)
        temp_data.insert(temp_data.begin(), 0);

    std::vector<uint8_t> temp;
    if (!hmac_openssl(temp, temp_key, temp_data, SA_DIGEST_ALGORITHM_SHA384)) {
        ERROR("digest");
        return false;
    }

    kenc.insert(kenc.begin(), temp.begin(), temp.begin() + 16);
    kenc.resize(SYM_128_KEY_SIZE);
    khmac.insert(khmac.begin(), temp.begin() + 16, temp.begin() + 48);
    khmac.resize(SYM_256_KEY_SIZE);
    netflix_wrapping_key_kdf(kwrap, kenc, khmac);
    return true;
}

bool SaKeyExchangeNetflixTest::setup_key_exchange(
        std::shared_ptr<sa_key>& kd,
        std::vector<uint8_t>& clear_kd,
        std::shared_ptr<sa_key>& dh_key,
        std::shared_ptr<EVP_PKEY>& dh_public_key,
        std::shared_ptr<EVP_PKEY>& other_dh,
        std::vector<uint8_t>& other_public_key,
        const std::vector<uint8_t>& dhp,
        const std::vector<uint8_t>& dhg) {
    sa_rights rights;
    sa_rights_set_allow_all(&rights);

    // Generate a DH key.
    dh_key = create_uninitialized_sa_key();
    sa_generate_parameters_dh dh_parameters = {
            .p = dhp.data(),
            .p_length = dhp.size(),
            .g = dhg.data(),
            .g_length = dhg.size()};
    if (sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &dh_parameters) != SA_STATUS_OK) {
        ERROR("sa_key_generate failed");
        return false;
    }

    EVP_PKEY* temp = sa_get_public_key(*dh_key);
    if (temp == nullptr) {
        ERROR("sa_get_public_key failed");
        return false;
    }

    dh_public_key = std::shared_ptr<EVP_PKEY>(temp, EVP_PKEY_free);

    // Generate the other DH key.
    if (!dh_generate_key(other_dh, other_public_key, dhp, dhg)) {
        ERROR("dh_generate_key failed");
        return false;
    }

    // Generate a kd.
    clear_kd = random(SYM_128_KEY_SIZE);
    sa_import_parameters_symmetric symmetric_parameters = {
            .rights = &rights};
    kd = create_uninitialized_sa_key();
    if (kd == nullptr) {
        ERROR("create_uninitialized_sa_key failed");
        return false;
    }

    if (sa_key_import(kd.get(), SA_KEY_FORMAT_SYMMETRIC_BYTES, clear_kd.data(),
                clear_kd.size(), &symmetric_parameters) != SA_STATUS_OK) {
        ERROR("sa_key_import failed");
        return false;
    }

    return true;
}

INSTANTIATE_TEST_SUITE_P(
        SaKeyExchangeDhTests,
        SaKeyExchangeDhTest,
        ::testing::Values(
                std::make_tuple(sample_dh_p_768(), sample_dh_g_768()),
                std::make_tuple(sample_dh_p_1024(), sample_dh_g_1024()),
                std::make_tuple(sample_dh_p_1536(), sample_dh_g_1536()),
                std::make_tuple(sample_dh_p_2048(), sample_dh_g_2048()),
                std::make_tuple(sample_dh_p_3072(), sample_dh_g_3072()),
                std::make_tuple(sample_dh_p_4096(), sample_dh_g_4096())));

INSTANTIATE_TEST_SUITE_P(
        SaKeyExchangeEcdhTests,
        SaKeyExchangeEcdhTest,
        ::testing::Values(
                SA_ELLIPTIC_CURVE_NIST_P192,
                SA_ELLIPTIC_CURVE_NIST_P224,
                SA_ELLIPTIC_CURVE_NIST_P256,
                SA_ELLIPTIC_CURVE_NIST_P384,
                SA_ELLIPTIC_CURVE_NIST_P521,
                SA_ELLIPTIC_CURVE_X25519,
                SA_ELLIPTIC_CURVE_X448));

INSTANTIATE_TEST_SUITE_P(
        SaKeyExchangeNetflixTests,
        SaKeyExchangeNetflixTest,
        ::testing::Values(
                std::make_tuple(sample_dh_p_768(), sample_dh_g_768()),
                std::make_tuple(sample_dh_p_1024(), sample_dh_g_1024()),
                std::make_tuple(sample_dh_p_1536(), sample_dh_g_1536()),
                std::make_tuple(sample_dh_p_2048(), sample_dh_g_2048()),
                std::make_tuple(sample_dh_p_3072(), sample_dh_g_3072()),
                std::make_tuple(sample_dh_p_4096(), sample_dh_g_4096())));
