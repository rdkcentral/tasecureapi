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

#include "key_type.h" // NOLINT
#include "common.h"
#include "ec.h"

static bool valid_aes_size(size_t size) {
    return size == SYM_128_KEY_SIZE || size == SYM_256_KEY_SIZE;
}

static bool valid_hmac_size(size_t size) {
    return size >= SYM_128_KEY_SIZE && size <= SYM_MAX_KEY_SIZE;
}

static bool valid_rsa_size(size_t size) {
    return size == RSA_1024_BYTE_LENGTH || size == RSA_2048_BYTE_LENGTH ||
           size == RSA_3072_BYTE_LENGTH || size == RSA_4096_BYTE_LENGTH;
}

static bool valid_ec_size(sa_elliptic_curve curve, size_t size) {
    return (curve == SA_ELLIPTIC_CURVE_NIST_P192 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_NIST_P192)) ||
           (curve == SA_ELLIPTIC_CURVE_NIST_P224 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_NIST_P224)) ||
           (curve == SA_ELLIPTIC_CURVE_NIST_P256 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_NIST_P256)) ||
           (curve == SA_ELLIPTIC_CURVE_NIST_P384 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_NIST_P384)) ||
           (curve == SA_ELLIPTIC_CURVE_NIST_P521 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_NIST_P521)) ||
           (curve == SA_ELLIPTIC_CURVE_ED25519 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_ED25519)) ||
           (curve == SA_ELLIPTIC_CURVE_X25519 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_X25519)) ||
           (curve == SA_ELLIPTIC_CURVE_ED448 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_ED448)) ||
           (curve == SA_ELLIPTIC_CURVE_X448 && size == ec_key_size_from_curve(SA_ELLIPTIC_CURVE_X448));
}

static bool valid_dh_size(size_t size) {
    return size <= DH_MAX_MOD_SIZE && size > 0;
}

bool key_type_supports_aes(sa_key_type key_type, size_t size) {
    return key_type == SA_KEY_TYPE_SYMMETRIC && valid_aes_size(size);
}

bool key_type_supports_hmac(sa_key_type key_type, size_t size) {
    return key_type == SA_KEY_TYPE_SYMMETRIC && valid_hmac_size(size);
}

bool key_type_supports_rsa(sa_key_type key_type, size_t size) {
    return key_type == SA_KEY_TYPE_RSA && valid_rsa_size(size);
}

bool key_type_supports_ec(sa_key_type key_type, sa_elliptic_curve curve, size_t size) {
    return key_type == SA_KEY_TYPE_EC && valid_ec_size(curve, size);
}

bool key_type_supports_dh(sa_key_type key_type, size_t size) {
    return key_type == SA_KEY_TYPE_DH && valid_dh_size(size);
}

bool key_type_supports_any(sa_key_type key_type, uint8_t ec_curve, size_t size) {
    return key_type_supports_aes(key_type, size) || key_type_supports_hmac(key_type, size) ||
           key_type_supports_rsa(key_type, size) || key_type_supports_ec(key_type, ec_curve, size) ||
           key_type_supports_dh(key_type, size);
}

bool key_type_supports_chacha20(sa_key_type key_type, size_t size) {
    return key_type == SA_KEY_TYPE_SYMMETRIC && size == SYM_256_KEY_SIZE;
}
