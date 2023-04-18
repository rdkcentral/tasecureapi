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
 * @file otp.h
 *
 * This file contains the functions and structures simulating reading of OTP data as well as
 * performing the OTP rooted key ladder operations. Implementors shall replace this functionality
 * with hardened hardware based implementation.
 */

#ifndef OTP_INTERNAL_H
#define OTP_INTERNAL_H

#include "common.h"
#include "sa_types.h"
#include "stored_key.h"

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
 * The key ladder inputs.
 */
typedef struct {
    uint8_t c1[SYM_128_KEY_SIZE];
    uint8_t c2[SYM_128_KEY_SIZE];
    uint8_t c3[SYM_128_KEY_SIZE];
} key_ladder_inputs_t;

/**
 * Unwrap data using AES ECB mode.
 *
 * @param[out] out cleartext.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] key key.
 * @param[in] key_length key length.
 * @return status of the operation.
 */
bool unwrap_aes_ecb_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* key,
        size_t key_length);

/**
 * Unwrap data using AES CBC mode.
 *
 * @param[out] out cleartext.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] iv initialization vector.
 * @param[in] key key.
 * @param[in] key_length key length.
 * @return status of the operation.
 */
bool unwrap_aes_cbc_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        const void* key,
        size_t key_length);

/**
 * Unwrap data using AES GCM mode.
 *
 * @param[out] out cleartext.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length.
 * @param[in] aad additional authenticated data.
 * @param[in] aad_length additional authenticated data length.
 * @param[in] tag authentication tag.
 * @param[in] tag_length authentication tag length.
 * @param[in] key key.
 * @param[in] key_length key length.
 * @return status of the operation.
 */
bool unwrap_aes_gcm_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length,
        const void* tag,
        size_t tag_length,
        const void* key,
        size_t key_length);

/**
 * Wrap key material using the rewrap key derived using a 3 stage hardware key ladder. The 3 stage
 * hardware key ladder will only be usable by SecApi TA.
 *
 * @param[out] wrapped wrapped key with the same length as in_length.
 * @param[in] key_ladder_inputs the key ladder inputs.
 * @param[in] in input key data to wrap.
 * @param[in] in_length input key data length. Has to be a multiple of 16 bytes.
 * @param[in] iv initialization vector.
 * @return true if the call succeeded, false otherwise.
 */
bool otp_wrap_aes_cbc(
        void* wrapped,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* in,
        size_t in_length,
        const void* iv);

/**
 * Unwrap key material using the rewrap key derived using a 3 stage hardware key ladder. The 3 stage
 * hardware key ladder will only be usable by SecApi TA.
 *
 * @param[out] out unwrapped key with the same length as wrapped_length.
 * @param[in] key_ladder_inputs the key ladder inputs.
 * @param[in] wrapped wrapped key data.
 * @param[in] wrapped_length wrapped key data length. Has to be a multiple of 16 bytes.
 * @param[in] iv initialization vector.
 * @return true if the call succeeded, false otherwise.
 */
bool otp_unwrap_aes_cbc(
        void* out,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* wrapped,
        size_t wrapped_length,
        const void* iv);

/**
 * Compute the 32 byte authentication code over the input message using the macing key derived using
 * a 3 stage hardware key ladder. The 3 stage hardware key ladder will only be usable by SecApi TA.
 *
 * @param[out] mac computed 32 byte mac value.
 * @param[in] key_ladder_inputs the key ladder inputs.
 * @param[in] in1 first input block.
 * @param[in] in1_length first input block length.
 * @param[in] in2 second input block.
 * @param[in] in2_length second input block length.
 * @param[in] in3 third input block.
 * @param[in] in3_length third input block length.
 * @return true if the call succeeded, false otherwise.
 */
bool otp_hmac_sha256(
        void* mac,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length);

/**
 * Unwrap key material using the wrapping key derived using a 3 stage hardware key ladder. The 3 stage
 * hardware key ladder will only be usable by SecApi TA.
 *
 * @param[out] out unwrapped key with the same length as wrapped_length.
 * @param[in] key_ladder_inputs the key ladder inputs.
 * @param[in] wrapped wrapped key data.
 * @param[in] wrapped_length wrapped key data length. Has to be a multiple of 16 bytes.
 * @param[in] iv 16 byte initialization vector.
 * @param[in] iv_length the length of the iv.
 * @param[in] aad GCM additional authentication data.
 * @param[in] aad_length length of the GCM additional authentication data.
 * @param[in] tag 16 byte GCM tag.
 * @param[in] tag_length the legnth of the tag.
 * @return true if the call succeeded, false otherwise.
 */
bool otp_unwrap_aes_gcm(
        void* out,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* wrapped,
        size_t wrapped_length,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length,
        const void* tag,
        size_t tag_length);

#ifdef __cplusplus
}
#endif

#endif // OTP_INTERNAL_H
