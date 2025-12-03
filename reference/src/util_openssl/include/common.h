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

#ifndef UTIL_OPENSSL_COMMON_H
#define UTIL_OPENSSL_COMMON_H

#include <openssl/opensslv.h>

// Include shared common definitions
#include "../../util/include/common.h"

// OpenSSL-specific constants
#if OPENSSL_VERSION_NUMBER < 0x10100000
#define RSA_PSS_SALTLEN_DIGEST (-1)
#define RSA_PSS_SALTLEN_AUTO (-2)
#define RSA_PSS_SALTLEN_MAX (-3)
#endif

#endif // UTIL_OPENSSL_COMMON_H
