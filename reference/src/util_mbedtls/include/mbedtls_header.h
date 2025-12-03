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

#ifndef MBEDTLS_H
#define MBEDTLS_H

/**
 * @file mbedtls.h
 * @brief Centralized mbedTLS header includes for util_mbedtls
 *
 * This header consolidates all mbedTLS library includes in one place.
 * Components that need mbedTLS functionality should include this header
 * instead of individual mbedTLS headers.
 */

/* ========== Core mbedTLS Headers ========== */

/* Platform and configuration */
#include <mbedtls/platform.h>
#include <mbedtls/error.h>

/* Random number generation */
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* ========== Cipher & Encryption ========== */

/* Symmetric ciphers */
#include <mbedtls/cipher.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/chachapoly.h>

/* MAC */
#include <mbedtls/cmac.h>

/* ========== Digest & Hash ========== */

#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

/* ========== Public Key Cryptography ========== */

/* RSA */
#include <mbedtls/rsa.h>

/* Elliptic Curve */
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>

/* Diffie-Hellman */
#include <mbedtls/dhm.h>

/* Generic Public Key layer */
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>

/* PEM encoding/decoding */
#include <mbedtls/pem.h>

/* ========== ASN.1 & Encoding ========== */

#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/base64.h>


/* ========== Math & Utilities ========== */

#include <mbedtls/bignum.h>

/* ========== Memory Management ========== */

/* Platform utilities - includes mbedtls_platform_zeroize() for secure memory clearing.
 * Used by custom RSA OAEP implementation in rsa.c for dual hash support. */
#include <mbedtls/platform_util.h>

/* ========== Version Info (replaces opensslv.h) ========== */

#include <mbedtls/version.h>

#endif /* MBEDTLS_H */
