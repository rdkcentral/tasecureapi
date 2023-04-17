/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

#include "soc_key_container.h" // NOLINT
#include "common.h"
#include "ec.h"
#include "json.h"
#include "log.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "rights.h"
#include "rsa.h"
#include "sa_types.h"
#include <memory.h>
#include <stored_key_internal.h>

#define AES_128_GCM "A128GCM"
#define MAX_AAD_SIZE 1300
#define SOC_CONTAINER_VERSION 4

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
    uint8_t mac[AES_BLOCK_SIZE];
    size_t mac_length;
} soc_kc_unpacked_t;

typedef struct {
    size_t alg_size;
    const char* alg;
} soc_kc_header_t;

typedef struct {
    char ta_id[UUID_LENGTH];
} entitled_ta_id;

typedef struct {
    uint8_t container_version;
    size_t key_type_string_length;
    const char* key_type_string;
    size_t encrypted_key_length;
    char* encrypted_key;
    uint8_t iv[GCM_IV_LENGTH];
    uint8_t key_usage;
    uint8_t decrypted_key_usage;
    size_t entitled_ta_ids_length;
    entitled_ta_id entitled_ta_ids[MAX_NUM_ALLOWED_TA_IDS];
    key_ladder_inputs_t key_ladder_inputs;
} soc_kc_payload_t;

static soc_kc_unpacked_t* soc_kc_unpacked_create() {
    soc_kc_unpacked_t* unpacked = memory_internal_alloc(sizeof(soc_kc_unpacked_t));
    if (unpacked == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }

    memory_memset_unoptimizable(unpacked, 0, sizeof(soc_kc_unpacked_t));
    return unpacked;
}

static void soc_kc_unpacked_free(soc_kc_unpacked_t* unpacked) {
    if (unpacked == NULL) {
        return;
    }

    memory_internal_free(unpacked->header);
    memory_internal_free(unpacked->payload);
    memory_internal_free(unpacked);
}

static soc_kc_unpacked_t* unpack_soc_kc(
        const void* in,
        size_t in_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return NULL;
    }

    bool status = false;
    soc_kc_unpacked_t* unpacked = NULL;
    do {
        unpacked = soc_kc_unpacked_create();

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
        if (unpacked->header == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        if (!b64_decode(unpacked->header, &unpacked->header_length, unpacked->header_b64,
                    unpacked->header_b64_length, true)) {
            ERROR("b64_decode failed");
            break;
        }

        unpacked->payload_length = b64_decoded_length(unpacked->payload_b64_length);
        unpacked->payload = memory_internal_alloc(unpacked->payload_length);
        if (unpacked->payload == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        if (!b64_decode(unpacked->payload, &unpacked->payload_length, unpacked->payload_b64,
                    unpacked->payload_b64_length, true)) {
            ERROR("b64_decode failed");
            break;
        }

        unpacked->mac_length = b64_decoded_length(unpacked->mac_b64_length);
        if (!b64_decode(unpacked->mac, &unpacked->mac_length, unpacked->mac_b64, unpacked->mac_b64_length, true) &&
                unpacked->mac_length != AES_BLOCK_SIZE) {
            ERROR("b64_decode failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        soc_kc_unpacked_free(unpacked);
        unpacked = NULL;
    }

    return unpacked;
}

static sa_status fields_to_rights(
        sa_rights* rights,
        sa_key_type key_type,
        key_subtype subtype,
        soc_kc_payload_t* payload,
        void* parameters) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (payload == NULL) {
        ERROR("NULL payload");
        return SA_STATUS_NULL_PARAMETER;
    }

    memory_memset_unoptimizable(rights, 0, sizeof(sa_rights));
    if (parameters != NULL) {
        size_t param2_size = ((size_t) ((uint8_t*) parameters)[0] << 8) + (size_t) ((uint8_t*) parameters)[1];
        if (param2_size != sizeof(sa_import_parameters_soc)) {
            ERROR("Unknown parameter type");
            return SA_STATUS_INVALID_PARAMETER;
        }

        sa_import_parameters_soc* parameters_soc = (sa_import_parameters_soc*) parameters;
        if (parameters_soc->version != 2 && parameters_soc->version != 3) {
            ERROR("Invalid SOC key version");
            return SA_STATUS_INVALID_PARAMETER;
        }

        rights->id[0] = parameters_soc->object_id >> 56 & 0xff;
        rights->id[1] = parameters_soc->object_id >> 48 & 0xff;
        rights->id[2] = parameters_soc->object_id >> 40 & 0xff;
        rights->id[3] = parameters_soc->object_id >> 32 & 0xff;
        rights->id[4] = parameters_soc->object_id >> 24 & 0xff;
        rights->id[5] = parameters_soc->object_id >> 16 & 0xff;
        rights->id[6] = parameters_soc->object_id >> 8 & 0xff;
        rights->id[7] = parameters_soc->object_id & 0xff;
    }

    rights->not_on_or_after = UINT64_MAX;
    SA_USAGE_BIT_SET(rights->usage_flags, SA_USAGE_FLAG_CACHEABLE);
    rights->usage_flags |= SA_USAGE_OUTPUT_PROTECTIONS_MASK;

    sa_status status = key_usage_to_usage_flags(&rights->usage_flags, payload->key_usage, key_type, subtype);
    if (status != SA_STATUS_OK) {
        ERROR("key_usage_to_usage_flags failed");
        return status;
    }

    if (payload->key_usage == KEY_ONLY) {
        status = key_usage_to_usage_flags(&rights->child_usage_flags, payload->decrypted_key_usage, key_type, subtype);
        if (status != SA_STATUS_OK) {
            ERROR("key_usage_to_usage_flags failed");
            return status;
        }
    }

    // Populate allowed TA UUIDs
    if (payload->entitled_ta_ids_length > MAX_NUM_ALLOWED_TA_IDS) {
        ERROR("Invalid entitled_ta_ids_length");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (payload->entitled_ta_ids_length == 0) {
        memcpy(&rights->allowed_tas[0], &ALL_MATCH, sizeof(sa_uuid));
    } else {
        for (size_t i = 0; i < payload->entitled_ta_ids_length; i++) {
            convert_uuid(payload->entitled_ta_ids[i].ta_id, sizeof(payload->entitled_ta_ids[i].ta_id),
                    &rights->allowed_tas[i]);
        }
    }

    return SA_STATUS_OK;
}

static sa_status parse_header(
        json_key_value_t* fields,
        size_t fields_count,
        soc_kc_header_t* header) {

    if (fields == NULL) {
        ERROR("fields NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (header == NULL) {
        ERROR("header NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read alg
    const json_key_value_t* alg_field = json_key_value_find("alg", fields, fields_count);
    if (alg_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    header->alg = json_value_as_string(&header->alg_size, alg_field->value);
    if (header->alg == NULL) {
        ERROR("Invalid alg value value");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    return SA_STATUS_OK;
}

static sa_status parse_payload(
        json_key_value_t* fields,
        size_t fields_count,
        soc_kc_payload_t* payload) {

    if (fields == NULL) {
        ERROR("fields NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (payload == NULL) {
        ERROR("payload NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read container version
    const json_key_value_t* container_version_field = json_key_value_find("containerVersion", fields, fields_count);
    if (container_version_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    payload->container_version = json_value_as_integer(container_version_field->value);

    // read key type
    const json_key_value_t* key_type_field = json_key_value_find("keyType", fields, fields_count);
    if (key_type_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    payload->key_type_string = json_value_as_string(&payload->key_type_string_length, key_type_field->value);
    if (payload->key_type_string == NULL) {
        ERROR("Missing keyType");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read encrypted key
    const json_key_value_t* encrypted_key_field = json_key_value_find("encryptedKey", fields, fields_count);
    if (encrypted_key_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t b64_encrypted_key_length;
    const char* encrypted_key = json_value_as_string(&b64_encrypted_key_length, encrypted_key_field->value);
    payload->encrypted_key_length = b64_decoded_length(b64_encrypted_key_length);
    payload->encrypted_key = memory_internal_alloc(payload->encrypted_key_length);
    if (payload->encrypted_key == NULL) {
        ERROR("memory_internal_alloc failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (!b64_decode(payload->encrypted_key, &payload->encrypted_key_length, encrypted_key, b64_encrypted_key_length,
                false)) {
        ERROR("b64_decode failed");
        memory_internal_free(payload->encrypted_key);
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read iv
    const json_key_value_t* iv_field = json_key_value_find("iv", fields, fields_count);
    if (iv_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t b64_iv_length;
    const char* iv = json_value_as_string(&b64_iv_length, iv_field->value);
    size_t iv_length = b64_decoded_length(b64_iv_length);
    if (!b64_decode(payload->iv, &iv_length, iv, b64_iv_length, false) && iv_length != GCM_IV_LENGTH) {
        ERROR("b64_decode failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read key usage
    const json_key_value_t* key_usage_field = json_key_value_find("keyUsage", fields, fields_count);
    if (key_usage_field == NULL) {
        ERROR("json_key_value_find failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    payload->key_usage = json_value_as_integer(key_usage_field->value);

    if (payload->key_usage == KEY_ONLY) {
        // read decrypted key usage
        const json_key_value_t* decrypted_key_usage_field = json_key_value_find("decryptedKeyUsage", fields,
                fields_count);
        if (decrypted_key_usage_field == NULL) {
            ERROR("json_key_value_find failed");
            return SA_STATUS_INVALID_KEY_FORMAT;
        }

        payload->decrypted_key_usage = json_value_as_integer(decrypted_key_usage_field->value);
    } else {
        payload->decrypted_key_usage = 0;
    }

    // read entitled TA IDs
    json_value_t** entitled_ta_ids = NULL;
    const json_key_value_t* entitled_ta_ids_field = json_key_value_find("entitledTaIds", fields, fields_count);
    if (entitled_ta_ids_field == NULL) {
        payload->entitled_ta_ids_length = 0;
    } else {
        entitled_ta_ids = json_value_as_array(&payload->entitled_ta_ids_length, entitled_ta_ids_field->value);
        for (size_t i = 0; i < payload->entitled_ta_ids_length; i++) {
            size_t ta_id_length;
            const char* ta_id = json_value_as_string(&ta_id_length, entitled_ta_ids[i]);
            if (ta_id_length != UUID_LENGTH) {
                memory_internal_free(entitled_ta_ids);
                ERROR("Invalid ta_id");
                return SA_STATUS_INVALID_KEY_FORMAT;
            }

            memcpy(payload->entitled_ta_ids[i].ta_id, ta_id, ta_id_length);
        }

        memory_internal_free(entitled_ta_ids);
    }

    // read c1
    const json_key_value_t* c1_field = json_key_value_find("c1", fields, fields_count);
    if (c1_field == NULL) {
        ERROR("Missing c1");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t b64_c1_length;
    const char* c1 = json_value_as_string(&b64_c1_length, c1_field->value);
    size_t c1_length = b64_decoded_length(b64_c1_length);
    if (!b64_decode(payload->key_ladder_inputs.c1, &c1_length, c1, b64_c1_length, false) &&
            c1_length != AES_BLOCK_SIZE) {
        ERROR("b64_decode failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read c2
    const json_key_value_t* c2_field = json_key_value_find("c2", fields, fields_count);
    if (c2_field == NULL) {
        ERROR("Missing c2");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t b64_c2_length;
    const char* c2 = json_value_as_string(&b64_c2_length, c2_field->value);
    size_t c2_length = b64_decoded_length(b64_c2_length);
    if (!b64_decode(payload->key_ladder_inputs.c2, &c2_length, c2, b64_c2_length, true) &&
            c2_length != AES_BLOCK_SIZE) {
        ERROR("b64_decode failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // read c3
    const json_key_value_t* c3_field = json_key_value_find("c3", fields, fields_count);
    if (c3_field == NULL) {
        ERROR("Missing c3");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t b64_c3_length;
    const char* c3 = json_value_as_string(&b64_c3_length, c3_field->value);
    size_t c3_length = b64_decoded_length(b64_c3_length);
    if (!b64_decode(payload->key_ladder_inputs.c3, &c3_length, c3, b64_c3_length, false) &&
            c3_length != AES_BLOCK_SIZE) {
        ERROR("b64_decode failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    return SA_STATUS_OK;
}

static size_t build_aad(
        uint8_t* aad,
        soc_kc_header_t* header,
        soc_kc_payload_t* payload) {
    size_t length = 0;

    if (aad == NULL) {
        ERROR("aad NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (header == NULL) {
        ERROR("header NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (payload == NULL) {
        ERROR("payload NULL");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    // alg
    if (!header->alg || header->alg_size != strlen(AES_128_GCM) ||
            memcmp(header->alg, AES_128_GCM, header->alg_size) != 0) {
        ERROR("Invalid alg");
        return 0;
    }

    memcpy(aad, header->alg, header->alg_size);
    length += header->alg_size;

    // container version
    if (payload->container_version != SOC_CONTAINER_VERSION) {
        ERROR("Invalid container version");
        return 0;
    }

    *(aad + length) = payload->container_version;
    length++;

    // key type string
    if (!payload->key_type_string || payload->key_type_string_length <= 0) {
        ERROR("Invalid key_type_string");
        return 0;
    }

    memcpy(aad + length, payload->key_type_string, payload->key_type_string_length);
    length += payload->key_type_string_length;

    // key usage value
    if (payload->key_usage == 0 || payload->key_usage > SOC_DATA_AND_KEY) {
        ERROR("Invalid key_usage");
        return 0;
    }

    if (payload->key_usage == KEY_ONLY &&
            (memcmp(payload->key_type_string, "HMAC-128", payload->key_type_string_length) == 0 ||
                    memcmp(payload->key_type_string, "HMAC-160", payload->key_type_string_length) == 0 ||
                    memcmp(payload->key_type_string, "HMAC-256", payload->key_type_string_length) == 0)) {
        ERROR("Invalid key_usage for HMAC key");
        return 0;
    }

    *(aad + length) = payload->key_usage;
    length++;

    if (payload->key_usage == KEY_ONLY) {
        if (payload->decrypted_key_usage == 0 || payload->decrypted_key_usage > SOC_DATA_AND_KEY) {
            ERROR("Invalid decrypted_key_usage");
            return 0;
        }

        *(aad + length) = payload->decrypted_key_usage;
        length++;
    }

    // iv
    memcpy(aad + length, payload->iv, GCM_IV_LENGTH);
    length += GCM_IV_LENGTH;

    // c1
    memcpy(aad + length, payload->key_ladder_inputs.c1, AES_BLOCK_SIZE);
    length += AES_BLOCK_SIZE;

    // c2
    memcpy(aad + length, payload->key_ladder_inputs.c2, AES_BLOCK_SIZE);
    length += AES_BLOCK_SIZE;

    // c3
    memcpy(aad + length, payload->key_ladder_inputs.c3, AES_BLOCK_SIZE);
    length += AES_BLOCK_SIZE;

    // entitled ta ids
    if (payload->entitled_ta_ids_length > MAX_NUM_ALLOWED_TA_IDS) {
        ERROR("Too many entitled_ta_ids");
        return 0;
    }

    for (size_t i = 0; i < payload->entitled_ta_ids_length; i++) {
        memcpy(aad + length, payload->entitled_ta_ids[i].ta_id, UUID_LENGTH);
        string_to_lowercase(aad + length, UUID_LENGTH);
        length += UUID_LENGTH;
    }

    return length;
}

static bool get_key_type_and_size(
        const char* key_type_string,
        size_t key_type_string_length,
        sa_key_type* key_type,
        size_t* key_size,
        key_subtype* subtype,
        sa_elliptic_curve* curve) {

    if (key_type_string == NULL) {
        ERROR("key_type_string NULL");
        return false;
    }

    if (key_type == NULL) {
        ERROR("key_type NULL");
        return false;
    }

    if (key_size == NULL) {
        ERROR("key_size NULL");
        return false;
    }

    if (memcmp(key_type_string, "AES-128", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = SYM_128_KEY_SIZE;
        *subtype = AES_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "HMAC-128", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = SYM_128_KEY_SIZE;
        *subtype = HMAC_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "AES-256", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = SYM_256_KEY_SIZE;
        *subtype = AES_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "CHACHA20-256", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = SYM_256_KEY_SIZE;
        *subtype = CHACHA20_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "HMAC-256", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = SYM_256_KEY_SIZE;
        *subtype = HMAC_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "HMAC-160", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = SYM_160_KEY_SIZE;
        *subtype = HMAC_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "RSA-1024", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_RSA;
        *key_size = RSA_1024_BYTE_LENGTH;
        *subtype = PRIVATE_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "RSA-2048", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_RSA;
        *key_size = RSA_2048_BYTE_LENGTH;
        *subtype = PRIVATE_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "RSA-3072", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_RSA;
        *key_size = RSA_3072_BYTE_LENGTH;
        *subtype = PRIVATE_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "RSA-4096", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_RSA;
        *key_size = RSA_4096_BYTE_LENGTH;
        *subtype = PRIVATE_SUBTYPE;
        *curve = UINT32_MAX;
    } else if (memcmp(key_type_string, "ECC-P192", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_P192_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_NIST_P192;
    } else if (memcmp(key_type_string, "ECC-P224", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_P224_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_NIST_P224;
    } else if (memcmp(key_type_string, "ECC-P256", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_P256_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_NIST_P256;
    } else if (memcmp(key_type_string, "ECC-P384", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_P384_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_NIST_P384;
    } else if (memcmp(key_type_string, "ECC-P521", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_P521_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_NIST_P521;
    } else if (memcmp(key_type_string, "ECC-ED25519", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_25519_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_ED25519;
    } else if (memcmp(key_type_string, "ECC-ED448", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_ED448_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_ED448;
    } else if (memcmp(key_type_string, "ECC-X25519", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_25519_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_X25519;
    } else if (memcmp(key_type_string, "ECC-X448", key_type_string_length) == 0) {
        *key_type = SA_KEY_TYPE_EC;
        *key_size = EC_X448_KEY_SIZE;
        *subtype = PRIVATE_SUBTYPE;
        *curve = SA_ELLIPTIC_CURVE_X448;
    } else {
        *key_type = SA_KEY_TYPE_SYMMETRIC;
        *key_size = 0;
        *subtype = AES_SUBTYPE;
        *curve = UINT32_MAX;
    }

    return true;
}

static sa_status decrypt_key_and_verify_mac(
        stored_key_t** stored_key,
        soc_kc_header_t* header,
        soc_kc_payload_t* payload,
        soc_kc_unpacked_t* unpacked,
        void* parameters) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (header == NULL) {
        ERROR("header NULL");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (payload == NULL) {
        ERROR("payload NULL");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (unpacked == NULL) {
        ERROR("unpacked NULL");
        return SA_STATUS_NULL_PARAMETER;
    }

    uint8_t aad[MAX_AAD_SIZE];
    size_t aad_length = build_aad(aad, header, payload);
    if (aad_length == 0) {
        ERROR("build_aad failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    sa_key_type key_type;
    size_t key_size;
    key_subtype subtype;
    sa_elliptic_curve curve;
    if (!get_key_type_and_size(payload->key_type_string, payload->key_type_string_length, &key_type, &key_size,
                &subtype, &curve)) {
        ERROR("get_key_type_and_size failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    void* key = NULL;
    sa_status status;
    do {
        key = memory_secure_alloc(payload->encrypted_key_length);
        if (key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = otp_unwrap_aes_gcm(key, &payload->key_ladder_inputs, payload->encrypted_key,
                payload->encrypted_key_length, payload->iv, GCM_IV_LENGTH, aad, aad_length, unpacked->mac,
                AES_BLOCK_SIZE);
        if (!status) {
            ERROR("otp_unwrap_aes_gcm failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        sa_rights rights;
        status = fields_to_rights(&rights, key_type, subtype, payload, parameters);
        if (status != SA_STATUS_OK) {
            ERROR("fields_to_rights failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        if (key_type == SA_KEY_TYPE_RSA) {
            size_t rsa_key_size = rsa_validate_private(key, payload->encrypted_key_length);
            if (rsa_key_size == 0) {
                ERROR("rsa_validate_private failed");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }

            if (rsa_key_size != key_size) {
                ERROR("Invalid RSA key size");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }
        } else if (key_type == SA_KEY_TYPE_EC) {
            size_t ec_key_size = ec_validate_private(curve, key, payload->encrypted_key_length);
            if (ec_key_size == 0) {
                ERROR("Invalid key size");
                break;
            }

            if (ec_key_size != key_size) {
                ERROR("Invalid EC key size");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }

            type_parameters.curve = curve;
        } else if (key_type == SA_KEY_TYPE_SYMMETRIC) {
            if (payload->encrypted_key_length != key_size) {
                ERROR("Invalid key size");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }
        } else {
            ERROR("Invalid key type");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        status = stored_key_create(stored_key, &rights, NULL, key_type, &type_parameters, key_size,
                key, payload->encrypted_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (key != NULL) {
        memory_memset_unoptimizable(key, 0, payload->encrypted_key_length);
        memory_secure_free(key);
    }

    return status;
}

sa_status soc_kc_unwrap(
        stored_key_t** stored_key,
        const void* in,
        size_t in_length,
        void* parameters) {

    if (stored_key == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    soc_kc_unpacked_t* unpacked = NULL;
    json_value_t* json_header_value = NULL;
    json_key_value_t* header_fields = NULL;
    json_value_t* json_payload_value = NULL;
    json_key_value_t* payload_fields = NULL;
    soc_kc_header_t header;
    soc_kc_payload_t payload;

    memset(&payload, 0, sizeof(soc_kc_unpacked_t));
    sa_status status = SA_STATUS_INVALID_KEY_FORMAT;
    do {
        unpacked = unpack_soc_kc(in, in_length);
        if (unpacked == NULL) {
            ERROR("unpack_soc_kc failed");
            break;
        }

        // parse the header
        json_header_value = json_parse_bytes(unpacked->header, unpacked->header_length);
        if (json_header_value == NULL) {
            ERROR("json_parse_bytes failed");
            break;
        }

        size_t header_fields_count;
        header_fields = json_value_as_map(&header_fields_count, json_header_value);
        if (header_fields == NULL) {
            ERROR("json_value_as_map failed");
            break;
        }

        status = parse_header(header_fields, header_fields_count, &header);
        if (status != SA_STATUS_OK) {
            ERROR("parse_header failed");
            break;
        }

        // parse the payload
        json_payload_value = json_parse_bytes(unpacked->payload, unpacked->payload_length);
        if (json_payload_value == NULL) {
            ERROR("json_parse_bytes failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        size_t payload_fields_count;
        payload_fields = json_value_as_map(&payload_fields_count, json_payload_value);
        if (payload_fields == NULL) {
            ERROR("json_value_as_map failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        status = parse_payload(payload_fields, payload_fields_count, &payload);
        if (status != SA_STATUS_OK) {
            ERROR("parse_payload failed");
            break;
        }

        status = decrypt_key_and_verify_mac(stored_key, &header, &payload, unpacked, parameters);
        if (status != SA_STATUS_OK) {
            ERROR("decrypt_key_and_verify_mac failed");
            break;
        }
    } while (false);

    soc_kc_unpacked_free(unpacked);
    if (json_header_value != NULL)
        json_value_free(json_header_value);
    if (header_fields != NULL)
        memory_internal_free(header_fields);
    if (json_payload_value != NULL)
        json_value_free(json_payload_value);
    if (payload_fields != NULL)
        memory_internal_free(payload_fields);
    if (payload.encrypted_key != NULL)
        memory_internal_free(payload.encrypted_key);
    return status;
}
