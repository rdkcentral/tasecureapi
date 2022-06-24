/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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

#include "typej.h" // NOLINT
#include "common.h"
#include "hmac_context.h"
#include "json.h"
#include "log.h"
#include "porting/memory.h"
#include "rights.h"
#include "sa_types.h"
#include "unwrap.h"
#include <memory.h>
#include <openssl/evp.h>
#include <stored_key_internal.h>

#define AES_ECB_NONE "aesEcbNone"
#define AES_ECB_PKCS5 "aesEcbPkcs5"
#define AES_CBC_NONE "aesCbcNone"
#define AES_CBC_PKCS5 "aesCbcPkcs5"

typedef enum {
    TYPEJ_RIGHT_NOT_SET = 0x00,
    TYPEJ_RIGHT_SVP_REQUIRED = 0x01,
    TYPEJ_RIGHT_DIGITAL_OPL_DTCP_ALLOWED = 0x02,
    TYPEJ_RIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED = 0x03,
    TYPEJ_RIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED = 0x04,
    TYPEJ_RIGHT_ANALOG_OUTPUT_ALLOWED = 0x05,
    TYPEJ_RIGHT_CGMSA_REQUIRED = 0x08
} typej_right_e;

typedef struct {
    const void* in;
    size_t in_length;
    const char* header_b64;
    size_t header_b64_length;
    const char* payload_b64;
    size_t payload_b64_length;
    const char* mac_b64;
    size_t mac_b64_length;
    void* header;
    size_t header_length;
    void* payload;
    size_t payload_length;
    void* mac;
    size_t mac_length;
} typej_unpacked_t;

static typej_unpacked_t* typej_unpacked_create() {
    typej_unpacked_t* unpacked = memory_internal_alloc(sizeof(typej_unpacked_t));
    if (unpacked == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }

    memory_memset_unoptimizable(unpacked, 0, sizeof(typej_unpacked_t));
    return unpacked;
}

static void typej_unpacked_free(typej_unpacked_t* unpacked) {
    if (unpacked == NULL) {
        return;
    }

    memory_internal_free(unpacked->header);
    memory_internal_free(unpacked->payload);
    memory_internal_free(unpacked->mac);

    memory_internal_free(unpacked);
}

static bool iso8601_to_epoch_time(
        uint64_t* epoch_time,
        const char* iso8601,
        size_t iso8601_size) {

    if (epoch_time == NULL) {
        ERROR("NULL epoch_time");
        return false;
    }

    if (iso8601 == NULL) {
        ERROR("NULL iso8601");
        return false;
    }

    if (iso8601_size != 20) {
        ERROR("Invalid iso8601_size");
        return false;
    }

    static const char* ISO_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S";

    struct tm tm_value = {0};
    char* strptime_result = strptime(iso8601, ISO_TIME_FORMAT, &tm_value);
    if (strptime_result == NULL || *strptime_result != 'Z') {
        ERROR("strptime failed for iso time '%s'", iso8601);
        return false;
    }

    time_t temp_time = timegm(&tm_value);

    if (temp_time < 0 && temp_time != -1)
        return false;

    *epoch_time = temp_time;
    return true;
}

static typej_unpacked_t* unpack_typej(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return NULL;
    }

    bool status = false;
    typej_unpacked_t* unpacked = NULL;
    do {
        unpacked = typej_unpacked_create();

        unpacked->in = in;
        unpacked->in_length = in_length;

        const char* in_string = (const char*) in;
        const char* in_string_end = in_string + in_length;

        unpacked->header_b64 = in_string;
        const char* header_b64_end = memchr(unpacked->header_b64, '.', in_string_end - unpacked->header_b64);
        if (header_b64_end == NULL) {
            ERROR("Invalid JWT structure encountered");
            break;
        }

        unpacked->header_b64_length = header_b64_end - unpacked->header_b64;
        unpacked->payload_b64 = header_b64_end + 1;
        if (unpacked->payload_b64 >= in_string_end) {
            ERROR("Invalid JWT structure encountered");
            break;
        }

        const char* payload_b64_end = memchr(unpacked->payload_b64, '.', in_string_end - unpacked->payload_b64);
        if (payload_b64_end == NULL) {
            ERROR("Invalid JWT structure encountered");
            break;
        }

        unpacked->payload_b64_length = payload_b64_end - unpacked->payload_b64;
        unpacked->mac_b64 = payload_b64_end + 1;
        if (unpacked->mac_b64 >= in_string_end) {
            ERROR("Invalid JWT structure encountered");
            break;
        }

        const char* mac_b64_end = in_string_end;
        unpacked->mac_b64_length = mac_b64_end - unpacked->mac_b64;
        unpacked->header_length = b64_decoded_length(unpacked->header_b64_length);
        unpacked->header = memory_internal_alloc(unpacked->header_length);
        if (!b64_decode(unpacked->header, &unpacked->header_length, unpacked->header_b64,
                    unpacked->header_b64_length)) {
            ERROR("b64_decode failed");
            break;
        }

        unpacked->payload_length = b64_decoded_length(unpacked->payload_b64_length);
        unpacked->payload = memory_internal_alloc(unpacked->payload_length);
        if (!b64_decode(unpacked->payload, &unpacked->payload_length, unpacked->payload_b64,
                    unpacked->payload_b64_length)) {
            ERROR("b64_decode failed");
            break;
        }

        unpacked->mac_length = b64_decoded_length(unpacked->mac_b64_length);
        unpacked->mac = memory_internal_alloc(unpacked->mac_length);
        if (!b64_decode(unpacked->mac, &unpacked->mac_length, unpacked->mac_b64, unpacked->mac_b64_length)) {
            ERROR("b64_decode failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        typej_unpacked_free(unpacked);
        unpacked = NULL;
    }

    return unpacked;
}

static bool verify_mac(
        const void* header,
        size_t header_length,
        const void* payload,
        size_t payload_length,
        const void* mac,
        size_t mac_length,
        const stored_key_t* stored_key) {

    if (header == NULL) {
        ERROR("NULL header");
        return false;
    }

    if (payload == NULL) {
        ERROR("NULL payload");
        return false;
    }

    if (mac == NULL) {
        ERROR("NULL mac");
        return false;
    }

    if (mac_length != SHA256_DIGEST_LENGTH) {
        ERROR("Invalid mac_length");
        return false;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    uint8_t computed_mac[SHA256_DIGEST_LENGTH];
    size_t computed_mac_length = sizeof(computed_mac);

    if (!hmac(computed_mac, &computed_mac_length, SA_DIGEST_ALGORITHM_SHA256, header, header_length, ".", 1, payload,
                payload_length, stored_key)) {
        ERROR("hmac failed");
        return false;
    }

    if (memory_memcmp_constant(computed_mac, mac, mac_length) != 0) {
        ERROR("mac does not match");
        return false;
    }

    return true;
}

static sa_status content_key_rights_to_usage_flags(
        uint64_t* usage_flags,
        const uint8_t* content_key_rights_bytes,
        size_t content_key_rights_count) {

    if (usage_flags == NULL) {
        ERROR("NULL usage_flags");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (content_key_rights_bytes == NULL) {
        ERROR("NULL content_key_rights_bytes");
        return SA_STATUS_NULL_PARAMETER;
    }

    // clear all output protection flags
    *usage_flags &= ~SA_USAGE_OUTPUT_PROTECTIONS_MASK;

    SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

    bool cgmsa_required = false;
    bool analog_allowed = false;
    for (size_t i = 0; i < content_key_rights_count; ++i) {
        switch (content_key_rights_bytes[i]) {
            case TYPEJ_RIGHT_NOT_SET:
                break;

            case TYPEJ_RIGHT_SVP_REQUIRED:
                SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);
                break;

            case TYPEJ_RIGHT_DIGITAL_OPL_DTCP_ALLOWED:
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_DTCP);
                break;

            case TYPEJ_RIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED:
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14);
                break;

            case TYPEJ_RIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED:
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22);
                break;

            case TYPEJ_RIGHT_ANALOG_OUTPUT_ALLOWED:
                analog_allowed = true;
                if (cgmsa_required)
                    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED);
                else
                    SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED);

                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA);
                break;

            case TYPEJ_RIGHT_CGMSA_REQUIRED:
                cgmsa_required = true;
                if (analog_allowed) {
                    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED);
                    SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA);
                }

                break;

            default:
                ERROR("Unknown right encountered: %d", content_key_rights_bytes[i]);
                return SA_STATUS_INVALID_KEY_FORMAT;
        }
    }

    return SA_STATUS_OK;
}

static sa_status fields_to_rights(
        sa_rights* rights,
        const json_key_value_t* fields,
        size_t fields_count) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (fields == NULL) {
        ERROR("NULL fields");
        return SA_STATUS_NULL_PARAMETER;
    }

    memory_memset_unoptimizable(rights, 0, sizeof(sa_rights));

    // read contentKeyId
    const json_key_value_t* key_id_field = json_key_value_find("contentKeyId", fields, fields_count);
    if (key_id_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t key_id_field_size = 0;
    const char* key_id_field_string = json_value_as_string(&key_id_field_size, key_id_field->value);
    if (key_id_field_string == NULL) {
        ERROR("json_value_as_string failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (key_id_field_size > (sizeof(rights->id) - 1)) {
        ERROR("Invalid contentKeyId length");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    strncpy(rights->id, key_id_field_string, sizeof(rights->id));

    // read contentKeyRights
    const json_key_value_t* rights_field = json_key_value_find("contentKeyRights", fields, fields_count);
    if (rights_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t rights_field_size = 0;
    const char* rights_field_string = json_value_as_string(&rights_field_size, rights_field->value);
    if (rights_field_string == NULL) {
        ERROR("json_value_as_string failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t rights_count = b64_decoded_length(rights_field_size);
    uint8_t* rights_bytes = memory_internal_alloc(rights_count);
    if (!b64_decode(rights_bytes, &rights_count, rights_field_string, rights_field_size)) {
        ERROR("Invalid contentKeyRights");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    sa_status status = content_key_rights_to_usage_flags(&rights->usage_flags, rights_bytes, rights_count);
    memory_internal_free(rights_bytes);
    if (status != SA_STATUS_OK) {
        ERROR("content_key_rights_to_usage_flags failed");
        return status;
    }

    // read contentKeyUsage
    const json_key_value_t* usage_field = json_key_value_find("contentKeyUsage", fields, fields_count);
    if (usage_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    long long usage = json_value_as_integer(usage_field->value);
    status = key_usage_to_usage_flags(&rights->usage_flags, usage, SA_KEY_TYPE_SYMMETRIC);
    if (status != SA_STATUS_OK) {
        ERROR("content_key_usage_to_usage_flags failed");
        return status;
    }

    // read contentKeyNotBefore
    const json_key_value_t* not_before_field = json_key_value_find("contentKeyNotBefore", fields, fields_count);
    if (not_before_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t not_before_field_size = 0;
    const char* not_before_field_string = json_value_as_string(&not_before_field_size, not_before_field->value);
    if (not_before_field_string == NULL) {
        ERROR("json_value_as_string failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (!iso8601_to_epoch_time(&rights->not_before, not_before_field_string, not_before_field_size)) {
        ERROR("iso8601_to_epoch_time failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read contentKeyNotOnOrAfter
    const json_key_value_t* not_on_or_after_field = json_key_value_find("contentKeyNotOnOrAfter", fields, fields_count);
    if (not_on_or_after_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t not_on_or_after_field_size = 0;
    const char* not_on_or_after_field_string = json_value_as_string(&not_on_or_after_field_size,
            not_on_or_after_field->value);
    if (not_on_or_after_field_string == NULL) {
        ERROR("json_value_as_string failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (!iso8601_to_epoch_time(&rights->not_on_or_after, not_on_or_after_field_string, not_on_or_after_field_size)) {
        ERROR("iso8601_to_epoch_time failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read contentKeyCacheable
    const json_key_value_t* cacheable_field = json_key_value_find("contentKeyCacheable", fields, fields_count);
    if (cacheable_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (json_value_as_bool(cacheable_field->value)) {
        SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE);
    }

    // Populate allowed TA UUIDs

    // read entitled TA IDs
    json_value_t** entitled_ta_ids = NULL;
    const json_key_value_t* entitled_ta_ids_field = json_key_value_find("entitledTaIds", fields, fields_count);
    if (entitled_ta_ids_field == NULL) {
        // Versions 1 and 2 of Type-J container have no assertions about allowed TAs. All caller UUIDs are allowed for
        // those version. If omitted in a version 3 key container, the all caller UUIDS are allowed.
        memcpy(&rights->allowed_tas[0], &ALL_MATCH, sizeof(sa_uuid));
    } else {
        size_t entitled_ta_ids_length;
        entitled_ta_ids = json_value_as_array(&entitled_ta_ids_length, entitled_ta_ids_field->value);
        if (entitled_ta_ids_length > MAX_NUM_ALLOWED_TA_IDS) {
            memory_internal_free(entitled_ta_ids);
            ERROR("Invalid entitled_ta_ids_length");
            return SA_STATUS_INVALID_KEY_FORMAT;
        }

        for (size_t i = 0; i < entitled_ta_ids_length; i++) {
            size_t ta_id_length;
            const char* ta_id = json_value_as_string(&ta_id_length, entitled_ta_ids[i]);
            if (ta_id_length != UUID_LENGTH) {
                memory_internal_free(entitled_ta_ids);
                ERROR("Invalid ta_id");
                return SA_STATUS_INVALID_KEY_FORMAT;
            }

            convert_uuid(ta_id, ta_id_length, &rights->allowed_tas[i]);
        }

        memory_internal_free(entitled_ta_ids);
    }

    return SA_STATUS_OK;
}

static sa_status unwrap_key_v1(
        stored_key_t** stored_key,
        const json_key_value_t* fields,
        size_t fields_count,
        const sa_rights* rights,
        const stored_key_t* stored_key_encryption) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key1");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (fields == NULL) {
        ERROR("NULL fields");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_encryption == NULL) {
        ERROR("NULL stored_key_encryption");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    uint8_t* content_key = NULL;
    do {
        const json_key_value_t* content_key_field = json_key_value_find("contentKey", fields, fields_count);
        if (content_key_field == NULL) {
            ERROR("json_key_value_find failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t content_key_b64_size = 0;
        const char* content_key_b64 = json_value_as_string(&content_key_b64_size, content_key_field->value);
        if (content_key_b64 == NULL) {
            ERROR("json_value_as_string failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t content_key_size = b64_decoded_length(content_key_b64_size);
        content_key = memory_internal_alloc(content_key_size);
        if (!b64_decode(content_key, &content_key_size, content_key_b64, content_key_b64_size)) {
            ERROR("Invalid contentKey");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        if (content_key_size % SYM_128_KEY_SIZE) {
            ERROR("Invalid content_key_size");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        status = unwrap_aes_ecb(stored_key, content_key, content_key_size, rights, SA_KEY_TYPE_SYMMETRIC, NULL,
                SA_CIPHER_ALGORITHM_AES_ECB, stored_key_encryption);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb failed");
            break;
        }
    } while (false);

    memory_internal_free(content_key);

    return status;
}

static sa_cipher_algorithm parse_cipher_algorithm(const char* algorithm, size_t algorithm_length) {
    if (algorithm == NULL) {
        ERROR("NULL algorithm");
        return -1;
    }

    const size_t aesEcbNone_length = strlen(AES_ECB_NONE);
    const size_t aesEcbPkcs5_length = strlen(AES_ECB_PKCS5);
    const size_t aesCbcNone_length = strlen(AES_CBC_NONE);
    const size_t aesCbcPkcs5_length = strlen(AES_CBC_PKCS5);

    if (algorithm_length == aesEcbNone_length && 0 == strncmp(algorithm, AES_ECB_NONE, algorithm_length))
        return SA_CIPHER_ALGORITHM_AES_ECB;

    if (algorithm_length == aesEcbPkcs5_length && 0 == strncmp(algorithm, AES_ECB_PKCS5, algorithm_length))
        return SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;

    if (algorithm_length == aesCbcNone_length && 0 == strncmp(algorithm, AES_CBC_NONE, algorithm_length))
        return SA_CIPHER_ALGORITHM_AES_CBC;

    if (algorithm_length == aesCbcPkcs5_length && 0 == strncmp(algorithm, AES_CBC_PKCS5, algorithm_length))
        return SA_CIPHER_ALGORITHM_AES_CBC_PKCS7;

    ERROR("Unknown algorithm %s", algorithm);
    return -1;
}

static sa_status unwrap_key_v2(
        stored_key_t** stored_key,
        const json_key_value_t* fields,
        size_t fields_count,
        const sa_rights* rights,
        const stored_key_t* stored_key_encryption) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (fields == NULL) {
        ERROR("NULL fields");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_encryption == NULL) {
        ERROR("NULL stored_key_encryption");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    uint8_t* content_key = NULL;
    uint8_t* iv = NULL;
    do {
        const json_key_value_t* algorithm_field = json_key_value_find("contentKeyTransportAlgorithm", fields,
                fields_count);
        if (algorithm_field == NULL) {
            ERROR("json_key_value_find failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t algorithm_size = 0;
        const char* algorithm = json_value_as_string(&algorithm_size, algorithm_field->value);
        sa_cipher_algorithm cipher_algorithm = parse_cipher_algorithm(algorithm, algorithm_size);

        const json_key_value_t* content_key_field = json_key_value_find("contentKey", fields, fields_count);
        if (content_key_field == NULL) {
            ERROR("json_key_value_find failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t content_key_b64_size = 0;
        const char* content_key_b64 = json_value_as_string(&content_key_b64_size, content_key_field->value);
        if (content_key_b64 == NULL) {
            ERROR("json_value_as_string failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t content_key_size = b64_decoded_length(content_key_b64_size);
        content_key = memory_internal_alloc(content_key_size);
        if (!b64_decode(content_key, &content_key_size, content_key_b64, content_key_b64_size)) {
            ERROR("json_key_value_find failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        const json_key_value_t* content_key_length_field = json_key_value_find("contentKeyLength",
                fields, fields_count);
        if (content_key_length_field == NULL) {
            ERROR("json_key_value_find failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t content_key_length = json_value_as_integer(content_key_length_field->value);

        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
            status = unwrap_aes_ecb(stored_key, content_key, content_key_size, rights, SA_KEY_TYPE_SYMMETRIC, NULL,
                    cipher_algorithm, stored_key_encryption);
            if (status != SA_STATUS_OK) {
                ERROR("unwrap_aes_ecb failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
                   cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
            const json_key_value_t* iv_field = json_key_value_find("contentKeyTransportIv", fields, fields_count);
            if (iv_field == NULL) {
                ERROR("json_key_value_find failed");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }

            size_t iv_b64_size = 0;
            const char* iv_b64 = json_value_as_string(&iv_b64_size, iv_field->value);
            if (iv_b64 == NULL) {
                ERROR("json_value_as_string failed");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }

            size_t iv_size = b64_decoded_length(iv_b64_size);
            iv = memory_internal_alloc(iv_size);
            if (!b64_decode(iv, &iv_size, iv_b64, iv_b64_size) || iv_size != SYM_128_KEY_SIZE) {
                ERROR("Invalid contentKeyTransportIv");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }

            status = unwrap_aes_cbc(stored_key, content_key, content_key_size, rights, SA_KEY_TYPE_SYMMETRIC, NULL,
                    cipher_algorithm, iv, stored_key_encryption);
            if (status != SA_STATUS_OK) {
                ERROR("unwrap_aes_cbc failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Invalid cipher_algorithm");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        if (stored_key_get_length(*stored_key) != content_key_length) {
            ERROR("Invalid key length");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    memory_internal_free(content_key);
    memory_internal_free(iv);

    return status;
}

static sa_status unwrap_key_v3(
        stored_key_t** stored_key,
        const json_key_value_t* fields,
        size_t fields_count,
        const sa_rights* rights,
        const stored_key_t* stored_key_encryption) {

    // No difference between unwrapping a v2 and v3 key.
    return unwrap_key_v2(stored_key, fields, fields_count, rights, stored_key_encryption);
}

sa_status typej_unwrap(
        stored_key_t** stored_key,
        const void* in,
        size_t in_length,
        const stored_key_t* stored_key_mac,
        const stored_key_t* stored_key_encryption) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_mac == NULL) {
        ERROR("NULL stored_key_mac");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_encryption == NULL) {
        ERROR("NULL stored_key_encryption");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    typej_unpacked_t* unpacked = NULL;
    json_value_t* json_value = NULL;
    json_key_value_t* fields = NULL;
    do {
        unpacked = unpack_typej(in, in_length);
        if (unpacked == NULL) {
            ERROR("unpack_typej failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        if (!verify_mac(unpacked->header_b64, unpacked->header_b64_length, unpacked->payload_b64,
                    unpacked->payload_b64_length, unpacked->mac, unpacked->mac_length, stored_key_mac)) {
            ERROR("verify_mac failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        json_value = json_parse_bytes(unpacked->payload, unpacked->payload_length);
        if (json_value == NULL) {
            ERROR("json_parse_string failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t fields_count;
        fields = json_value_as_map(&fields_count, json_value);
        if (fields == NULL) {
            ERROR("json_value_as_map failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        sa_rights rights;
        status = fields_to_rights(&rights, fields, fields_count);
        if (status != SA_STATUS_OK) {
            ERROR("fields_to_rights failed");
            break;
        }

        const json_key_value_t* version_field = json_key_value_find("contentKeyContainerVersion", fields, fields_count);
        long long version = version_field ? json_value_as_integer(version_field->value) : 1;
        if (version == 1) {
            status = unwrap_key_v1(stored_key, fields, fields_count, &rights, stored_key_encryption);
            if (status != SA_STATUS_OK) {
                ERROR("unwrap_key_v1 failed");
                break;
            }
        } else if (version == 2) {
            status = unwrap_key_v2(stored_key, fields, fields_count, &rights, stored_key_encryption);
            if (status != SA_STATUS_OK) {
                ERROR("unwrap_key_v2 failed");
                break;
            }
        } else if (version == 3) {
            status = unwrap_key_v3(stored_key, fields, fields_count, &rights, stored_key_encryption);
            if (status != SA_STATUS_OK) {
                ERROR("unwrap_key_v2 failed");
                break;
            }
        } else {
            ERROR("Invalid contentKeyContainerVersion encountered: %lld",
                    version);
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    typej_unpacked_free(unpacked);
    json_value_free(json_value);
    memory_internal_free(fields);

    return status;
}
