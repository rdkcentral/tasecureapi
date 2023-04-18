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

/** @section Description
 * @file video_output.h
 *
 * This file contains the functions and structures implementing querying of video output protection
 * levels. Implementors shall replace this functionality with platform dependent functions.
 */

#ifndef VIDEO_OUTPUT_H
#define VIDEO_OUTPUT_H

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

/**
 * State of the video outputs.
 */
typedef struct {
    /** Number of analog outputs with no output protections engaged. */
    int analog_unprotected_count;
    /** Number of analog outputs with CGMSA enabled. */
    int analog_cgmsa_count;
    /** Number of digital outputs with no output protections engaged. */
    int digital_unprotected_count;
    /** Number of digital outputs with HDCP 1.4 engaged. */
    int digital_hdcp14_count;
    /** Number of digital outputs with HDCP 2.2 engaged. */
    int digital_hdcp22_count;
    /** Is SVP pipeline enabled. */
    bool svp_enabled;
} video_output_state_t;

/**
 * Poll the state of the video outputs.
 *
 * @param[out] current state of the video outputs.
 * @return true if the call succeeded, false otherwise.
 */
bool video_output_poll(video_output_state_t* state);

#ifdef __cplusplus
}
#endif

#endif // VIDEO_OUTPUT_H
