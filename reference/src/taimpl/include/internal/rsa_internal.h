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
 * @file rsa.h
 *
 * This file contains the functions implementing internal RSA cryptographic operations.
 */

#ifndef RSA_INTERNAL_H
#define RSA_INTERNAL_H

#include "sa_types.h"
#include "stored_key.h"
#include "mbedtls_header.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

/**
 * Imports an RSA PKCS8 private key.
 *
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @return the RSA key (mbedtls_rsa_context).
 */
mbedtls_rsa_context* rsa_import_pkcs8(
        const void* in,
        size_t in_length);

#ifdef __cplusplus
}
#endif

#endif // RSA_INTERNAL_H
