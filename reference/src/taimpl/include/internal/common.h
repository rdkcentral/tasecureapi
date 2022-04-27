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

#ifndef COMMON_H
#define COMMON_H

#include "ta_sa_types.h"

#define AES_BLOCK_SIZE 16
#define SYM_128_KEY_SIZE 16
#define SYM_160_KEY_SIZE 20
#define SYM_256_KEY_SIZE 32
#define SHA1_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#define RSA_1024_BYTE_LENGTH 128
#define RSA_2048_BYTE_LENGTH 256
#define RSA_3072_BYTE_LENGTH 384
#define RSA_4096_BYTE_LENGTH 512
#define EC_P256_KEY_SIZE 32
#define EC_P384_KEY_SIZE 48
#define EC_P521_KEY_SIZE 66
#define EC_25519_KEY_SIZE 32
#define EC_ED448_KEY_SIZE 57
#define EC_X448_KEY_SIZE 56
#define GCM_IV_LENGTH 12
#define DH_MAX_MOD_SIZE 512
#define RSA_PKCS1_PADDING_SIZE 11
#define RSA_OAEP_PADDING_SIZE 42
#define CHACHA20_NONCE_LENGTH 12
#define CHACHA20_COUNTER_LENGTH 4
#define CHACHA20_TAG_LENGTH 16

#endif // COMMON_H
