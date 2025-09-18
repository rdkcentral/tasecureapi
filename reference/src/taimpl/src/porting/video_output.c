/*
 * Copyright 2019-2025 Comcast Cable Communications Management, LLC
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
#include "porting/video_output.h" // NOLINT
#include "log.h"
#include <memory.h>

static struct {
    video_output_state_t state;
} global_video_output = {
        .state = {
                .analog_unprotected_count = 0,
                .analog_cgmsa_count = 0,
                .digital_unprotected_count = 0,
                .digital_hdcp14_count = 0,
                .digital_hdcp22_count = 1,
#ifndef DISABLE_SVP
                .svp_enabled = true}};
#else
                .svp_enabled = false}};
#endif

bool video_output_poll(video_output_state_t* state) {

    if (state == NULL) {
        ERROR("NULL state");
        return false;
    }

    memcpy(state, &global_video_output.state, sizeof(video_output_state_t));

    return true;
}
