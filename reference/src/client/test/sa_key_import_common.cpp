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

#include "sa_key_import_common.h"
#include "client_test_helpers.h"

using namespace client_test_helpers;

std::shared_ptr<std::vector<uint8_t>> SaKeyImportBase::export_key(
        std::vector<uint8_t>& mixin,
        sa_key key) {
    size_t required_length = 0;

    if (sa_key_export(nullptr, &required_length, mixin.empty() ? nullptr : mixin.data(), mixin.size(), key) !=
            SA_STATUS_OK) {
        return nullptr;
    }

    std::shared_ptr<std::vector<uint8_t>> result(new std::vector<uint8_t>(required_length));
    if (sa_key_export(result->data(), &required_length, mixin.empty() ? nullptr : mixin.data(), mixin.size(),
                key) != SA_STATUS_OK) {
        return nullptr;
    }

    return result;
}

bool SaKeyImportBase::convert_uuid(
        std::string uuid_str,
        sa_uuid* uuid) {

    if (uuid_str.size() != 36) {
        ERROR("Invalid UUID");
        return false;
    }

    for (size_t i = 0, j = 0; i < uuid_str.size() && j < sizeof(uuid->id); i++, j++) {
        if (uuid_str[i] == '-')
            i++;

        if (i >= uuid_str.size()) {
            ERROR("Invalid UUID");
            return false;
        }

        char c1 = uuid_str[i++];
        if ('A' <= c1 && c1 <= 'Z')
            c1 += 32;

        if (i >= uuid_str.size() || ((c1 < '0' || c1 > '9') && (c1 < 'a' || c1 > 'f'))) {
            ERROR("Invalid UUID");
            return false;
        }

        char c2 = uuid_str[i];
        if ('A' <= c2 && c2 <= 'Z')
            c2 += 32;

        if ((c2 < '0' || c2 > '9') && (c2 < 'a' || c2 > 'f')) {
            ERROR("Invalid UUID");
            return false;
        }

        uuid->id[j] = (('0' <= c1 && c1 <= '9') ? c1 - '0' : c1 - 'a' + 10) * 16 +
                      (('0' <= c2 && c2 <= '9') ? c2 - '0' : c2 - 'a' + 10);
    }

    return true;
}

std::string SaKeyImportTypejBase::generate_header() {
    std::string hdr = R"({"alg":"HS256","kid":"sessionid"})";
    return b64_encode(hdr.data(), hdr.size(), true);
}

std::string SaKeyImportTypejBase::generate_content_key(
        sa_cipher_algorithm cipher_algorithm,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& enckey) {

    std::vector<uint8_t> wrapped(512);

    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB) {
        if (!encrypt_aes_ecb_openssl(wrapped, key, enckey, false)) {
            ERROR("encrypt_aes_ecb_openssl failed");
            throw;
        }
    } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        if (!encrypt_aes_ecb_openssl(wrapped, key, enckey, true)) {
            ERROR("encrypt_aes_ecb_openssl failed");
            throw;
        }
    } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
        if (!encrypt_aes_cbc_openssl(wrapped, key, iv, enckey, false)) {
            ERROR("encrypt_aes_cbc_openssl failed");
            throw;
        }
    } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
        if (!encrypt_aes_cbc_openssl(wrapped, key, iv, enckey, true)) {
            ERROR("encrypt_aes_cbc_openssl failed");
            throw;
        }
    } else {
        // not a valid cipher_algorithm
        ERROR("Invalid cipher_algorithm");
        throw;
    }

    return b64_encode(wrapped.data(), wrapped.size(), false);
}

std::string SaKeyImportTypejBase::generate_content_key_rights(const sa_rights* rights) {
    std::vector<uint8_t> bytes(AES_BLOCK_SIZE);
    memset(bytes.data(), RIGHT_NOT_SET, bytes.size());

    size_t idx = 0;

    if (SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED)) {
        // invalid configuration for Type-J containers
        ERROR("Invalid usage_flags");
        throw;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL)) {
        bytes[idx++] = RIGHT_SVP_REQUIRED;
    }

    if (SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP)) {
        bytes[idx++] = RIGHT_DIGITAL_OPL_DTCP_ALLOWED;
    }

    if (SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14)) {
        bytes[idx++] = RIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    }

    if (SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22)) {
        bytes[idx++] = RIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    }

    if (SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED) ||
            SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA)) {
        bytes[idx++] = RIGHT_ANALOG_OUTPUT_ALLOWED;
    }

    if (SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) &&
            !SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED)) {
        bytes[idx++] = RIGHT_CGMSA_REQUIRED;
    }

    return b64_encode(bytes.data(), bytes.size(), false);
}

size_t SaKeyImportTypejBase::generate_content_key_usage(const sa_rights* rights) {
    bool unwrap = SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_UNWRAP);
    bool decrypt = SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_DECRYPT);
    bool encrypt = SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ENCRYPT);
    bool derive = SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_DERIVE);
    bool sign = SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_SIGN);

    if ((decrypt && encrypt && sign && derive) != (decrypt || encrypt || sign || derive)) {
        // invalid set of flags for Type-J container
        ERROR("Invalid usage_flags");
        throw;
    }

    if (!unwrap && !decrypt) {
        // invalid set of flags for Type-J container
        ERROR("Invalid usage_flags");
        throw;
    }

    if (unwrap && decrypt) {
        return TYPEJ_DATA_AND_KEY;
    }

    if (decrypt) {
        return DATA_ONLY;
    }

    return KEY_ONLY;
}

std::string SaKeyImportTypejBase::generate_body_v1(
        const sa_rights* rights,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& enckey) {

    std::string format = "{"
                         "\"contentKey\": \"%s\","
                         "\"contentKeyId\": \"%s\","
                         "\"contentKeyRights\": \"%s\","
                         "\"contentKeyUsage\": %d,"
                         "\"contentKeyNotBefore\": \"%s\","
                         "\"contentKeyNotOnOrAfter\": \"%s\","
                         "\"contentKeyCacheable\": %s"
                         "}";

    auto contentKey = generate_content_key(SA_CIPHER_ALGORITHM_AES_ECB, key, {}, enckey);
    const auto* contentKeyId = rights->id;
    auto contentKeyRights = generate_content_key_rights(rights);
    auto contentKeyUsage = generate_content_key_usage(rights);
    auto contentKeyNotBefore = iso8601(rights->not_before);
    auto contentKeyNotOnOrAfter = iso8601(rights->not_on_or_after);
    const auto* contentKeyCacheable =
            SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE) ? "true" : "false";

    char body[64 * 1024];
    sprintf(body, format.c_str(), contentKey.c_str(), contentKeyId, contentKeyRights.c_str(),
            contentKeyUsage, contentKeyNotBefore.c_str(), contentKeyNotOnOrAfter.c_str(),
            contentKeyCacheable);

    return b64_encode(body, strlen(body), true);
}

const char* SaKeyImportTypejBase::typej_algorithm_string(sa_cipher_algorithm cipher_algorithm) {
    switch (cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_ECB:
            return "aesEcbNone";
        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            return "aesEcbPkcs5";
        case SA_CIPHER_ALGORITHM_AES_CBC:
            return "aesCbcNone";
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            return "aesCbcPkcs5";
        default:
            // invalid cipher_algorithm
            ERROR("Invalid cipher_algorithm");
            throw;
    }
}

std::string SaKeyImportTypejBase::generate_body_v2(
        sa_cipher_algorithm cipher_algorithm,
        const sa_rights* rights,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& enckey) {

    std::string formatECB = "{"
                            "\"contentKeyContainerVersion\": %d,"
                            "\"contentKeyTransportAlgorithm\": \"%s\","
                            "\"contentKeyLength\": %d,"
                            "\"contentKey\": \"%s\","
                            "\"contentKeyId\": \"%s\","
                            "\"contentKeyRights\": \"%s\","
                            "\"contentKeyUsage\": %d,"
                            "\"contentKeyNotBefore\": \"%s\","
                            "\"contentKeyNotOnOrAfter\": \"%s\","
                            "\"contentKeyCacheable\": %s"
                            "}";

    std::string formatCBC = "{"
                            "\"contentKeyContainerVersion\": %d,"
                            "\"contentKeyTransportAlgorithm\": \"%s\","
                            "\"contentKeyTransportIv\": \"%s\","
                            "\"contentKeyLength\": %d,"
                            "\"contentKey\": \"%s\","
                            "\"contentKeyId\": \"%s\","
                            "\"contentKeyRights\": \"%s\","
                            "\"contentKeyUsage\": %d,"
                            "\"contentKeyNotBefore\": \"%s\","
                            "\"contentKeyNotOnOrAfter\": \"%s\","
                            "\"contentKeyCacheable\": %s"
                            "}";

    auto contentKeyContainerVersion = 2;
    const auto* contentKeyTransportAlgorithm = typej_algorithm_string(cipher_algorithm);
    auto iv = random(AES_BLOCK_SIZE);
    auto contentKeyTransportIv = b64_encode(iv.data(), iv.size(), false);
    auto contentKeyLength = key.size();
    auto contentKey = generate_content_key(cipher_algorithm, key, iv, enckey);
    const auto* contentKeyId = rights->id;
    auto contentKeyRights = generate_content_key_rights(rights);
    auto contentKeyUsage = generate_content_key_usage(rights);
    auto contentKeyNotBefore = iso8601(rights->not_before);
    auto contentKeyNotOnOrAfter = iso8601(rights->not_on_or_after);
    const auto* contentKeyCacheable =
            SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE) ? "true" : "false";

    char body[64 * 1024];
    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
        sprintf(body, formatCBC.c_str(), contentKeyContainerVersion, contentKeyTransportAlgorithm,
                contentKeyTransportIv.c_str(), contentKeyLength, contentKey.c_str(), contentKeyId,
                contentKeyRights.c_str(), contentKeyUsage, contentKeyNotBefore.c_str(),
                contentKeyNotOnOrAfter.c_str(), contentKeyCacheable);
    } else {
        sprintf(body, formatECB.c_str(), contentKeyContainerVersion, contentKeyTransportAlgorithm,
                contentKeyLength, contentKey.c_str(), contentKeyId, contentKeyRights.c_str(),
                contentKeyUsage, contentKeyNotBefore.c_str(), contentKeyNotOnOrAfter.c_str(),
                contentKeyCacheable);
    }

    return b64_encode(body, strlen(body), true);
}

std::string SaKeyImportTypejBase::generate_body_v3(
        sa_cipher_algorithm cipher_algorithm,
        const sa_rights* rights,
        std::vector<std::string>& entitled_ta_ids,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& enckey) {

    std::string formatECB = "{"
                            "\"contentKeyContainerVersion\": %d,"
                            "\"contentKeyTransportAlgorithm\": \"%s\","
                            "\"contentKeyLength\": %d,"
                            "\"contentKey\": \"%s\","
                            "\"contentKeyId\": \"%s\","
                            "\"contentKeyRights\": \"%s\","
                            "\"contentKeyUsage\": %d,"
                            "\"contentKeyNotBefore\": \"%s\","
                            "\"contentKeyNotOnOrAfter\": \"%s\","
                            "\"contentKeyCacheable\": %s"
                            "%s"
                            "}";

    std::string formatCBC = "{"
                            "\"contentKeyContainerVersion\": %d,"
                            "\"contentKeyTransportAlgorithm\": \"%s\","
                            "\"contentKeyTransportIv\": \"%s\","
                            "\"contentKeyLength\": %d,"
                            "\"contentKey\": \"%s\","
                            "\"contentKeyId\": \"%s\","
                            "\"contentKeyRights\": \"%s\","
                            "\"contentKeyUsage\": %d,"
                            "\"contentKeyNotBefore\": \"%s\","
                            "\"contentKeyNotOnOrAfter\": \"%s\","
                            "\"contentKeyCacheable\": %s"
                            "%s"
                            "}";

    auto contentKeyContainerVersion = 3;
    const auto* contentKeyTransportAlgorithm = typej_algorithm_string(cipher_algorithm);
    auto iv = random(AES_BLOCK_SIZE);
    auto contentKeyTransportIv = b64_encode(iv.data(), iv.size(), false);
    auto contentKeyLength = key.size();
    auto contentKey = generate_content_key(cipher_algorithm, key, iv, enckey);
    const auto* contentKeyId = rights->id;
    auto contentKeyRights = generate_content_key_rights(rights);
    auto contentKeyUsage = generate_content_key_usage(rights);
    auto contentKeyNotBefore = iso8601(rights->not_before);
    auto contentKeyNotOnOrAfter = iso8601(rights->not_on_or_after);
    const auto* contentKeyCacheable =
            SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE) ? "true" : "false";

    std::string entitled_ta_ids_str;
    if (!entitled_ta_ids.empty()) {
        entitled_ta_ids_str += R"(, "entitledTaIds": [)";
        for (size_t i = 0; i < entitled_ta_ids.size(); i++) {
            if (i > 0)
                entitled_ta_ids_str += ", ";

            entitled_ta_ids_str += "\"" + entitled_ta_ids[i] + "\"";
        }

        entitled_ta_ids_str += "]";
    }

    char body[64 * 1024];
    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
        sprintf(body, formatCBC.c_str(), contentKeyContainerVersion, contentKeyTransportAlgorithm,
                contentKeyTransportIv.c_str(), contentKeyLength, contentKey.c_str(), contentKeyId,
                contentKeyRights.c_str(), contentKeyUsage, contentKeyNotBefore.c_str(),
                contentKeyNotOnOrAfter.c_str(), contentKeyCacheable, entitled_ta_ids_str.c_str());
    } else {
        sprintf(body, formatECB.c_str(), contentKeyContainerVersion, contentKeyTransportAlgorithm,
                contentKeyLength, contentKey.c_str(), contentKeyId, contentKeyRights.c_str(),
                contentKeyUsage, contentKeyNotBefore.c_str(), contentKeyNotOnOrAfter.c_str(),
                contentKeyCacheable, entitled_ta_ids_str.c_str());
    }

    return b64_encode(body, strlen(body), true);
}

std::string SaKeyImportTypejBase::generate_typej_v1(
        const sa_rights* rights,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& mackey,
        const std::vector<uint8_t>& enckey,
        bool valid_signature) {

    std::string hdr = generate_header();
    std::string body = generate_body_v1(rights, key, enckey);

    std::vector<uint8_t> mac_bytes(SHA256_DIGEST_LENGTH);
    if (valid_signature) {
        std::vector<uint8_t> payload(hdr.data(), hdr.data() + hdr.size());
        payload.push_back(static_cast<uint8_t>('.'));
        payload.insert(payload.end(), body.begin(), body.end());

        if (!hmac_openssl(mac_bytes, mackey, payload, SA_DIGEST_ALGORITHM_SHA256)) {
            ERROR("hmac_sha256_openssl failed");
            throw;
        }
    }
    std::string mac = b64_encode(mac_bytes.data(), mac_bytes.size(), true);

    return hdr + "." + body + "." + mac;
}

std::string SaKeyImportTypejBase::generate_typej_v2(
        sa_cipher_algorithm cipher_algorithm,
        const sa_rights* rights,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& mackey,
        const std::vector<uint8_t>& enckey,
        bool valid_signature) {

    std::string hdr = generate_header();
    std::string body = generate_body_v2(cipher_algorithm, rights, key, enckey);

    std::vector<uint8_t> mac_bytes(SHA256_DIGEST_LENGTH);
    if (valid_signature) {
        std::vector<uint8_t> payload(hdr.data(), hdr.data() + hdr.size());
        payload.push_back(static_cast<uint8_t>('.'));
        payload.insert(payload.end(), body.begin(), body.end());

        if (!hmac_openssl(mac_bytes, mackey, payload, SA_DIGEST_ALGORITHM_SHA256)) {
            ERROR("hmac_sha256_openssl failed");
            throw;
        }
    }
    std::string mac = b64_encode(mac_bytes.data(), mac_bytes.size(), true);

    return hdr + "." + body + "." + mac;
}

std::string SaKeyImportTypejBase::generate_typej_v3(
        sa_cipher_algorithm cipher_algorithm,
        const sa_rights* rights,
        std::vector<std::string>& entitled_ta_ids,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& mackey,
        const std::vector<uint8_t>& enckey,
        bool valid_signature) {

    std::string hdr = generate_header();
    std::string body = generate_body_v3(cipher_algorithm, rights, entitled_ta_ids, key, enckey);

    std::vector<uint8_t> mac_bytes(SHA256_DIGEST_LENGTH);
    if (valid_signature) {
        std::vector<uint8_t> payload(hdr.data(), hdr.data() + hdr.size());
        payload.push_back(static_cast<uint8_t>('.'));
        payload.insert(payload.end(), body.begin(), body.end());

        if (!hmac_openssl(mac_bytes, mackey, payload, SA_DIGEST_ALGORITHM_SHA256)) {
            ERROR("hmac_sha256_openssl failed");
            throw;
        }
    }
    std::string mac = b64_encode(mac_bytes.data(), mac_bytes.size(), true);

    return hdr + "." + body + "." + mac;
}

void SaKeyImportTypejBase::typej_rights_set_allow_all(sa_rights* rights) {
    sa_rights_set_allow_all(rights);

    // remove flags that cannot be expressed using Type-J rights
    SA_USAGE_BIT_CLEAR(rights->usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);
    SA_USAGE_BIT_CLEAR(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED);
}

std::vector<std::string> SaKeyImportSocBase::ENTITLED_TA_IDS = {
        "157f768f-bad0-470b-929d-0d7dec29d220",
        "157f768f-bad0-470b-929d-0d7dec29d221",
        "157f768f-bad0-470b-929d-0d7dec29d222",
        "157f768f-bad0-470b-929d-0d7dec29d223",
        "157f768f-bad0-470b-929d-0d7dec29d224",
        "157f768f-bad0-470b-929d-0d7dec29d225",
        "157f768f-bad0-470b-929d-0d7dec29d226",
        "00000000-0000-0000-0000-000000000001"};

std::string SaKeyImportSocBase::generate_encrypted_key(
        uint8_t container_version,
        std::string& key_type,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& iv,
        uint8_t key_usage,
        uint8_t decrypted_key_usage,
        std::vector<std::string>& entitled_ta_ids,
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3,
        std::vector<uint8_t>& tag) {

    std::string alg = "A128GCM";
    std::vector<uint8_t> aad;
    aad.insert(aad.end(), alg.begin(), alg.end());
    aad.insert(aad.end(), container_version);
    aad.insert(aad.end(), key_type.begin(), key_type.end());
    aad.insert(aad.end(), key_usage);
    if (container_version >= 3 && key_usage == KEY_ONLY)
        aad.insert(aad.end(), decrypted_key_usage);

    aad.insert(aad.end(), iv.begin(), iv.end());
    aad.insert(aad.end(), c1.begin(), c1.end());
    aad.insert(aad.end(), c2.begin(), c2.end());
    aad.insert(aad.end(), c3.begin(), c3.end());
    for (auto& ta_id : entitled_ta_ids) {
        aad.insert(aad.end(), ta_id.begin(), ta_id.end());
    }

    std::vector<uint8_t> encrypted_key(key.size());
    tag.resize(AES_BLOCK_SIZE);

    std::vector<uint8_t> empty;
    std::vector<uint8_t> root_key;
    if(!get_root_key(root_key))
        return "";

    auto derived_key = derive_test_key_ladder(root_key, c1, c2, c3, empty);
    if (derived_key == nullptr)
        return "";

    if (!encrypt_aes_gcm_openssl(encrypted_key, key, iv, aad, tag, *derived_key))
        return "";

    return b64_encode(encrypted_key.data(), encrypted_key.size(), false);
}

std::string SaKeyImportSocBase::generate_header() {
    std::string hdr = R"({"alg": "A128GCM"})";
    return b64_encode(hdr.data(), hdr.size(), true);
}

std::string SaKeyImportSocBase::generate_payload(
        uint8_t container_version,
        std::string& key_type,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& iv,
        uint8_t key_usage,
        uint8_t decrypted_key_usage,
        std::vector<std::string>& entitled_ta_ids,
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3,
        std::vector<uint8_t>& tag) {

    std::ostringstream oss;

    oss << R"({"containerVersion": )" << static_cast<int>(container_version);
    if (!key_type.empty())
        oss << R"(, "keyType": ")" << key_type << "\"";

    std::string encrypted_key = generate_encrypted_key(container_version, key_type, key, iv, key_usage,
            decrypted_key_usage, entitled_ta_ids, c1, c2, c3, tag);
    if (encrypted_key.empty())
        return "";

    oss << R"(, "encryptedKey": ")" << encrypted_key << "\"";

    if (!iv.empty())
        oss << R"(, "iv": ")" << b64_encode(iv.data(), iv.size(), false) << "\"";

    oss << R"(, "keyUsage": )" << static_cast<int>(key_usage);

    if (container_version >= 3 && key_usage == KEY_ONLY)
        oss << R"(, "decryptedKeyUsage": )" << static_cast<int>(decrypted_key_usage);

    if (!entitled_ta_ids.empty()) {
        oss << R"(, "entitledTaIds": [)";
        for (size_t i = 0; i < entitled_ta_ids.size(); i++) {
            if (i > 0)
                oss << ", ";

            oss << "\"" << entitled_ta_ids[i] << "\"";
        }

        oss << "]";
    }

    if (!c1.empty())
        oss << R"(, "c1": ")" << b64_encode(c1.data(), c1.size(), false) << "\"";

    if (!c2.empty())
        oss << R"(, "c2": ")" << b64_encode(c2.data(), c2.size(), false) << "\"";

    if (!c3.empty())
        oss << R"(, "c3": ")" << b64_encode(c3.data(), c3.size(), false) << "\"";

    oss << "}";

    return b64_encode(oss.str().data(), oss.str().size(), true);
}

void SaKeyImportSocBase::set_key_usage_flags(
        uint8_t key_usage,
        uint8_t decrypted_key_usage,
        sa_rights& rights,
        sa_key_type key_type,
        bool hmac) {
    uint64_t usage_flags = 0;
    switch (key_usage) {
        case DATA_ONLY:
            if (key_type == SA_KEY_TYPE_DH || key_type == SA_KEY_TYPE_EC)
                SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

            if (!hmac) {
                SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_DECRYPT);
                SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_ENCRYPT);
            }

            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        case KEY_ONLY:
            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_UNWRAP);
            break;

        case SOC_DATA_AND_KEY:
            if (key_type == SA_KEY_TYPE_DH || key_type == SA_KEY_TYPE_EC)
                SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_UNWRAP);
            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_DECRYPT);
            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_ENCRYPT);
            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        default:
            break;
    }

    SA_USAGE_BIT_SET(usage_flags, SA_USAGE_FLAG_CACHEABLE);
    usage_flags |= SA_USAGE_OUTPUT_PROTECTIONS_MASK;
    rights.usage_flags = usage_flags;

    if (key_usage != KEY_ONLY || decrypted_key_usage == 0)
        rights.child_usage_flags = 0;

    uint64_t child_usage_flags = 0;
    switch (decrypted_key_usage) {
        case DATA_ONLY:
            if (key_type == SA_KEY_TYPE_DH || key_type == SA_KEY_TYPE_EC)
                SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_DECRYPT);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_ENCRYPT);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        case KEY_ONLY:
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_UNWRAP);
            break;

        case SOC_DATA_AND_KEY:
            if (key_type == SA_KEY_TYPE_DH || key_type == SA_KEY_TYPE_EC)
                SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_UNWRAP);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_DECRYPT);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_ENCRYPT);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(child_usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        default:
            break;
    }

    rights.child_usage_flags = child_usage_flags;
}

sa_status SaKeyImportSocBase::import_key(
        sa_key* key,
        uint8_t container_version,
        std::string& key_type,
        sa_key_type clear_key_type,
        uint8_t secapi_version,
        std::vector<uint8_t>& clear_key,
        std::vector<uint8_t>& iv,
        uint8_t key_usage,
        uint8_t decrypted_key_usage,
        std::vector<std::string>& entitled_ta_ids,
        sa_rights& key_rights,
        std::vector<uint8_t>& c1,
        std::vector<uint8_t>& c2,
        std::vector<uint8_t>& c3) {

    std::vector<uint8_t> tag;
    auto jwt_header = generate_header();
    auto jwt_payload = generate_payload(container_version, key_type, clear_key, iv, key_usage, decrypted_key_usage,
            entitled_ta_ids, c1, c2, c3, tag);
    std::string key_container = jwt_header + "." + jwt_payload + "." + b64_encode(tag.data(), tag.size(), true);

    bool hmac = memcmp(key_type.data(), "HMAC", 4) == 0;
    sa_rights_set_allow_all(&key_rights);
    set_key_usage_flags(key_usage, decrypted_key_usage, key_rights, clear_key_type, hmac);
    int i = 0;
    for (auto& entitled_ta_id : entitled_ta_ids) {
        if (i < MAX_NUM_ALLOWED_TA_IDS)
            convert_uuid(entitled_ta_id, &key_rights.allowed_tas[i++]);
    }

    sa_import_parameters_soc parameters_soc;
    void* parameters = nullptr;
    if (secapi_version != 0) {
        parameters_soc.length[0] = sizeof(sa_import_parameters_soc) >> 8 & 0xff;
        parameters_soc.length[1] = sizeof(sa_import_parameters_soc) & 0xff;
        parameters_soc.version = secapi_version;
        memset(&parameters_soc.default_rights, 0, sizeof(sa_rights));
        parameters_soc.object_id = 0x123456789abcdef0;
        key_rights.id[0] = parameters_soc.object_id >> 56 & 0xff;
        key_rights.id[1] = parameters_soc.object_id >> 48 & 0xff;
        key_rights.id[2] = parameters_soc.object_id >> 40 & 0xff;
        key_rights.id[3] = parameters_soc.object_id >> 32 & 0xff;
        key_rights.id[4] = parameters_soc.object_id >> 24 & 0xff;
        key_rights.id[5] = parameters_soc.object_id >> 16 & 0xff;
        key_rights.id[6] = parameters_soc.object_id >> 8 & 0xff;
        key_rights.id[7] = parameters_soc.object_id & 0xff;
        parameters = &parameters_soc;
    }

    return sa_key_import(key, SA_KEY_FORMAT_SOC, key_container.data(), key_container.size(), parameters);
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaKeyImportTests,
        SaKeyImportTest,
        ::testing::Values(
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_160_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_SYMMETRIC, SYM_MAX_KEY_SIZE),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P192),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P224),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P384),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P521),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X25519),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_ED448),
                std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_X448),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_1024_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_2048_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_3072_BYTE_LENGTH),
                std::make_tuple(SA_KEY_TYPE_RSA, RSA_4096_BYTE_LENGTH)));

INSTANTIATE_TEST_SUITE_P(
        SaKeyImportTypejTest,
        SaKeyImportTypejTest,
        ::testing::Values(
                // DATA AND KEY usage tests
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, DATA_AND_KEY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, DATA_AND_KEY_MASK),
                // DATA only usage tests
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, DATA_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, DATA_ONLY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, DATA_ONLY_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, DATA_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, DATA_ONLY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, DATA_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, DATA_ONLY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, DATA_ONLY_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, DATA_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, DATA_ONLY_MASK),
                // KEY ONLY usage tests
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, KEY_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, KEY_ONLY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, KEY_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, KEY_ONLY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, KEY_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, KEY_ONLY_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, KEY_ONLY_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, KEY_ONLY_MASK),
                // NO_ALLOWED_OUTPUTS usage tests
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, NO_ALLOWED_OUTPUTS_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, NO_ALLOWED_OUTPUTS_MASK),
                // NOT_CACHEABLE usage tests
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, NOT_CACHEABLE_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, NOT_CACHEABLE_MASK),
                // SVP_REQUIRED usage tests
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_128_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_160_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SVP_REQUIRED_MASK),
                std::make_tuple(SYM_256_KEY_SIZE, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, SVP_REQUIRED_MASK)));

INSTANTIATE_TEST_SUITE_P(SaKeyImportTypejTest, SaKeyImportTypejTaIdRangeTest,
    ::testing::Range(0, MAX_NUM_ALLOWED_TA_IDS + 1));

#ifdef ENABLE_SOC_KEY_TESTS

INSTANTIATE_TEST_SUITE_P(
        SaKeyImportSocTest,
        SaKeyImportSocAllKeyCombosTest,
        ::testing::Combine(
            ::testing::Values(
                std::make_tuple("AES-128", SYM_128_KEY_SIZE, SA_KEY_TYPE_SYMMETRIC),
                std::make_tuple("AES-256", SYM_256_KEY_SIZE, SA_KEY_TYPE_SYMMETRIC),
                std::make_tuple("CHACHA20-256", SYM_256_KEY_SIZE, SA_KEY_TYPE_SYMMETRIC),
                std::make_tuple("HMAC-128", SYM_128_KEY_SIZE, SA_KEY_TYPE_SYMMETRIC),
                std::make_tuple("HMAC-160", SYM_160_KEY_SIZE, SA_KEY_TYPE_SYMMETRIC),
                std::make_tuple("HMAC-256", SYM_256_KEY_SIZE, SA_KEY_TYPE_SYMMETRIC),
                std::make_tuple("RSA-1024", RSA_1024_BYTE_LENGTH, SA_KEY_TYPE_RSA),
                std::make_tuple("RSA-2048", RSA_2048_BYTE_LENGTH, SA_KEY_TYPE_RSA),
                std::make_tuple("RSA-3072", RSA_3072_BYTE_LENGTH, SA_KEY_TYPE_RSA),
                std::make_tuple("RSA-4096", RSA_4096_BYTE_LENGTH, SA_KEY_TYPE_RSA),
                std::make_tuple("ECC-P192", SA_ELLIPTIC_CURVE_NIST_P192, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-P224", SA_ELLIPTIC_CURVE_NIST_P224, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-P256", SA_ELLIPTIC_CURVE_NIST_P256, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-P384", SA_ELLIPTIC_CURVE_NIST_P384, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-P521", SA_ELLIPTIC_CURVE_NIST_P521, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-ED25519", SA_ELLIPTIC_CURVE_ED25519, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-ED448", SA_ELLIPTIC_CURVE_ED448, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-X25519", SA_ELLIPTIC_CURVE_X25519, SA_KEY_TYPE_EC),
                std::make_tuple("ECC-X448", SA_ELLIPTIC_CURVE_X448, SA_KEY_TYPE_EC)),
            ::testing::Values(
                std::make_tuple(DATA_ONLY, 0),
                std::make_tuple(KEY_ONLY, DATA_ONLY),
                std::make_tuple(KEY_ONLY, KEY_ONLY),
                std::make_tuple(KEY_ONLY, SOC_DATA_AND_KEY),
                std::make_tuple(SOC_DATA_AND_KEY, 0)),
            ::testing::Values(0, 2, 3)));

INSTANTIATE_TEST_SUITE_P(SaKeyImportSocTest, SaKeyImportSocTaIdRangeTest,
    ::testing::Range(0, MAX_NUM_ALLOWED_TA_IDS + 1));

// clang-format on
#endif
