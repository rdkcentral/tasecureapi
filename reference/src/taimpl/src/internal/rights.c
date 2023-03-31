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

#include "rights.h" // NOLINT
#include "log.h"
#include "porting/memory.h"
#include <memory.h>
#include <time.h>

const sa_uuid NO_MATCH = {
        .id = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

const sa_uuid ALL_MATCH = {
        .id = {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static bool validate_video_output_state(const sa_rights* rights) {
    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    video_output_state_t video_output_state;
    if (!video_output_poll(&video_output_state)) {
        ERROR("video_output_poll failed");
        return false;
    }

    if (!rights_allowed_video_output_state(rights, &video_output_state)) {
        ERROR("rights_allowed_video_output_state failed");
        return false;
    }

    return true;
}

bool rights_validate_format(const sa_rights* rights) {
    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (strnlen(rights->id, sizeof(rights->id)) == sizeof(rights->id)) {
        ERROR("Invalid id");
        return false;
    }

    return true;
}

bool rights_allowed_derive(const sa_rights* rights) {
    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_DERIVE)) {
        ERROR("SA_USAGE_FLAG_DERIVE flag is not set");
        return false;
    }

    if (!rights_allowed_time(rights, time(NULL))) {
        ERROR("rights_allowed_time failed");
        return false;
    }

    return true;
}

bool rights_allowed_exchange(const sa_rights* rights) {
    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE)) {
        ERROR("SA_USAGE_FLAG_KEY_EXCHANGE flag is not set");
        return false;
    }

    if (!rights_allowed_time(rights, time(NULL))) {
        ERROR("rights_allowed_time failed");
        return false;
    }

    return true;
}

bool rights_allowed_unwrap(const sa_rights* rights) {
    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_UNWRAP)) {
        ERROR("SA_USAGE_FLAG_UNWRAP flag is not set");
        return false;
    }

    if (!rights_allowed_time(rights, time(NULL))) {
        ERROR("rights_allowed_time failed");
        return false;
    }

    return true;
}

bool rights_allowed_decrypt(
        const sa_rights* rights,
        sa_key_type key_type) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_DECRYPT)) {
        ERROR("SA_USAGE_FLAG_DECRYPT flag is not set");
        return false;
    }

    if (!rights_allowed_time(rights, time(NULL))) {
        ERROR("rights_allowed_time failed");
        return false;
    }

    if (key_type == SA_KEY_TYPE_SYMMETRIC) {
        if (!validate_video_output_state(rights)) {
            ERROR("validate_video_output_state failed");
            return false;
        }
    }

    return true;
}

bool rights_allowed_encrypt(
        const sa_rights* rights,
        sa_key_type key_type) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ENCRYPT)) {
        ERROR("SA_USAGE_FLAG_ENCRYPT flag is not set");
        return false;
    }

    if (!rights_allowed_time(rights, time(NULL))) {
        ERROR("rights_allowed_time failed");
        return false;
    }

    if (key_type == SA_KEY_TYPE_SYMMETRIC) {
        if (!validate_video_output_state(rights)) {
            ERROR("validate_video_output_state failed");
            return false;
        }
    }

    return true;
}

bool rights_allowed_clear(const sa_rights* rights) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    // If SVP is required then the decryption can only be done using sa_svp* calls
    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL)) {
        ERROR("SVP is required");
        return false;
    }

    return true;
}

bool rights_allowed_sign(const sa_rights* rights) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_SIGN)) {
        ERROR("SA_USAGE_FLAG_SIGN flag is not set");
        return false;
    }

    if (!rights_allowed_time(rights, time(NULL))) {
        ERROR("rights_allowed_time failed");
        return false;
    }

    return true;
}

bool rights_allowed_time(
        const sa_rights* rights,
        uint64_t time) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (time < rights->not_before) {
        ERROR("Current time is outside of key validity window");
        return false;
    }

    if (time >= rights->not_on_or_after) {
        ERROR("Current time is outside of key validity window");
        return false;
    }

    return true;
}

bool rights_allowed_video_output_state(
        const sa_rights* rights,
        const video_output_state_t* video_output_state) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (video_output_state == NULL) {
        ERROR("NULL video_output_state");
        return false;
    }

    // If SVP is required then the key MUST NOT be loaded if SVP is not engaged
    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL) && !video_output_state->svp_enabled) {
        ERROR("SVP is required and not enabled");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED) &&
            video_output_state->analog_unprotected_count > 0) {
        ERROR("Unprotected analog detected but not allowed");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA) &&
            video_output_state->analog_cgmsa_count > 0) {
        ERROR("CGMSA analog detected but not allowed");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED) &&
            video_output_state->digital_unprotected_count > 0) {
        ERROR("Unprotected digital detected but not allowed");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14) &&
            video_output_state->digital_hdcp14_count > 0) {
        ERROR("HDCP 1.4 digital detected but not allowed");
        return false;
    }

    if (!SA_USAGE_BIT_TEST(rights->usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22) &&
            video_output_state->digital_hdcp22_count > 0) {
        ERROR("HDCP 2.2 digital detected but not allowed");
        return false;
    }

    return true;
}

bool rights_allowed_uuid(
        const sa_rights* rights,
        const sa_uuid* caller_uuid) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return false;
    }

    for (size_t i = 0; i < MAX_NUM_ALLOWED_TA_IDS; ++i) {
        if (memory_memcmp_constant(&rights->allowed_tas[i], &NO_MATCH, sizeof(sa_uuid)) == 0) {
            continue;
        }

        if (memory_memcmp_constant(&rights->allowed_tas[i], &ALL_MATCH, sizeof(sa_uuid)) == 0) {
            return true;
        }

        if (memory_memcmp_constant(&rights->allowed_tas[i], caller_uuid, sizeof(sa_uuid)) == 0) {
            return true;
        }
    }

    return false;
}

sa_status key_usage_to_usage_flags(
        uint64_t* usage_flags,
        int64_t key_usage,
        sa_key_type key_type,
        key_subtype subtype) {

    if (usage_flags == NULL) {
        ERROR("NULL usage_flags");
        return SA_STATUS_NULL_PARAMETER;
    }

    // clear usage bits
    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);
    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_DERIVE);
    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_UNWRAP);
    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_DECRYPT);
    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_ENCRYPT);
    SA_USAGE_BIT_CLEAR(*usage_flags, SA_USAGE_FLAG_SIGN);

    switch (key_usage) {
        case TYPEJ_DATA_AND_KEY:
        case SOC_DATA_AND_KEY:
            if (key_type == SA_KEY_TYPE_DH || key_type == SA_KEY_TYPE_EC)
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_UNWRAP);
            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_DECRYPT);
            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ENCRYPT);
            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        case DATA_ONLY:
            if (key_type == SA_KEY_TYPE_DH || key_type == SA_KEY_TYPE_EC)
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

            if (subtype != HMAC_SUBTYPE) {
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_DECRYPT);
                SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_ENCRYPT);
            }

            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_SIGN);
            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_DERIVE);
            break;

        case KEY_ONLY:
            SA_USAGE_BIT_SET(*usage_flags, SA_USAGE_FLAG_UNWRAP);
            break;

        default:
            ERROR("Invalid usage: %lld", key_usage);
            return SA_STATUS_INVALID_KEY_FORMAT;
    }

    return SA_STATUS_OK;
}

bool convert_uuid(
        const char* uuid_str,
        size_t uuid_str_length,
        sa_uuid* uuid) {

    if (uuid_str_length != UUID_LENGTH) {
        ERROR("Invalid UUID");
        return false;
    }

    for (size_t i = 0, j = 0; i < uuid_str_length && j < sizeof(uuid->id); i++, j++) {
        if (uuid_str[i] == '-')
            i++;

        if (i >= uuid_str_length) {
            ERROR("Invalid UUID");
            return false;
        }

        char c1 = uuid_str[i++];
        if ('A' <= c1 && c1 <= 'Z')
            c1 += 32;

        if (i >= uuid_str_length || ((c1 < '0' || c1 > '9') && (c1 < 'a' || c1 > 'f'))) {
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
