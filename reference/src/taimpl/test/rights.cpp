/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#include "rights.h"
#include "test_helpers.h"
#include "gtest/gtest.h"

namespace {
    TEST(RightsAllowedTime, valid) {
        time_t now = time(nullptr);

        sa_rights rights;
        rights.not_before = now;
        rights.not_on_or_after = now + 1;

        EXPECT_TRUE(rights_allowed_time(&rights, now));
    }

    TEST(RightsAllowedTime, past) {
        time_t now = time(nullptr);

        sa_rights rights;
        rights.not_before = now - 1;
        rights.not_on_or_after = now;

        EXPECT_FALSE(rights_allowed_time(&rights, now));
    }

    TEST(RightsAllowedTime, future) {
        time_t now = time(nullptr);

        sa_rights rights;
        rights.not_before = now + 1;
        rights.not_on_or_after = now + 2;

        EXPECT_FALSE(rights_allowed_time(&rights, now));
    }

    TEST(RightsAllowedVideoOutputState, allowall) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = false;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, svprequiredok) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, svprequiredfail) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = false;

        EXPECT_FALSE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, analogunprotectedok) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 0;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, analogunprotectedfail) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_UNPROTECTED);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_FALSE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, analogcgmsaok) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 0;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, analogcgmsafail) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_ANALOG_CGMSA);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_FALSE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, digitalunprotectedok) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 0;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, digitalunprotectedfail) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_UNPROTECTED);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_FALSE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, digitalhdcp14ok) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 0;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, digitalhdcp14fail) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP14);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_FALSE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, digitalhdcp22ok) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 0;
        video_output_state.svp_enabled = true;

        EXPECT_TRUE(rights_allowed_video_output_state(&rights, &video_output_state));
    }

    TEST(RightsAllowedVideoOutputState, digitalhdcp22fail) {
        sa_rights rights;
        test_helpers::rights_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_ALLOWED_DIGITAL_HDCP22);

        video_output_state_t video_output_state;
        video_output_state.analog_unprotected_count = 1;
        video_output_state.analog_cgmsa_count = 1;
        video_output_state.digital_unprotected_count = 1;
        video_output_state.digital_hdcp14_count = 1;
        video_output_state.digital_hdcp22_count = 1;
        video_output_state.svp_enabled = true;

        EXPECT_FALSE(rights_allowed_video_output_state(&rights, &video_output_state));
    }
} // namespace
