/**
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
 * @file soc_key_container.h
 *
 * This file contains the functions and structures implementing SOC key container unwrapping.
 *
 * Here is the description of the SOC Key Container format:
 * ## Overview
 *
 * Key provisioning is the delivery of keys to a device such that the confidentiality and integrity of
 * the keys are preserved. Provisioned keys are encrypted to ensure confidentiality. Provisioned
 * keys are signed to ensure integrity and to authenticate the key source.
 *
 * Private asymmetric keys and secret symmetric keys are encrypted with a chip-unique key so that the
 * keys are bound to a specific device.
 *
 * Provisioned keys are delivered to the device in key containers. A key container includes information
 * that describes the key. Each provisioned key has its own key container.
 *
 * This document describes the general key container for SOC devices. Some SOCs may replace c1, c2, & c3
 * with other key derivation mechanisms. Other SOCs may replace AES128GCM with AES128CBC as the encryption
 * algorithm and HS256 as authentication mechanism and add c4 to produce the HMAC key.
 *
 * ## Key Container Format
 *
 * The key container is comprised of a header, a payload containing parameters and the encrypted key,
 * and an authentication tag.
 *
 * The parameters required to create the container are:
 *
 * * `algorithmString` a string indicating how the container is authenticated. Supported
 *   authentication algorithms are:
 *   * `"A128GCM"`
 * * `containerVersion` 1 for this version
 * * `keyTypeString` string that identifies key type. For ECC keys the key type also specifies the
 *   curve parameters. Current supported key types include:
 *
 *   * `"AES-128"`
 *   * `"AES-256"`
 *   * `"RSA-1024"`
 *   * `"RSA-2048"`
 *   * `"RSA-3072"`
 *   * `"RSA-4096"`
 *   * `"ECC-P256"`
 *   * `"HMAC-128"`
 *   * `"HMAC-160"`
 *   * `"HMAC-256"`
 *
 * * `encryptedKeyBytes` provisioned key encrypted with the container encryption key or the key
 *   protection key. The encrypted key bytes are encrypted using AES128-GCM.
 *   * For symmetric keys, `encryptedKeyBytes` contains the encrypted binary key data.
 *   * For RSA keys, `encryptedKeyBytes` contains an encrypted PrivateKeyInfo (RFC 5208).
 *   * For ECC keys, `encryptedKeyBytes` contains the encrypted private key.
 * * `ivBytes` = IV for key encryption. The IV must be 96 bits. A new random IV must be generated for
 *   each key container.
 * * `keyUsageValue` = user-defined number (1=data, 2=key only, 3=data and key). Data usage indicates
 *   the key can be used to encrypt or decrypt data, including signature generation. Key only usage
 *   indicates the key may only decrypt a key into the secure region.
 * * `entitledTaIds` Optional array of one or more `taId` string values. If omitted, then all TAs may
 *   use the provisioned key. If the array is included, then only TAs that are included in the array
 *   can use the provisioned key. If the array is included then the array must contain at least one
 *   taId. Lower case values "a" - "f" are used in all `taID` values in the array.
 *     * `taId` String representation of Trusted Application (TA) UUID for TA that is entitled to use
 *       the provisioned key. The UUID is compliant with RFC 4122 (e.g. "00112233-4455-6677-8899-
 *       aabbccddeeff").
 * * `c1Bytes` = first-stage key derivation parameter. Must be 16 bytes.
 * * `c2Bytes` = second-stage key derivation parameter. Must be 16 bytes.
 * * `c3Bytes` = third-stage key derivation parameter. Must be 16 bytes.
 *
 * The header is encoded as
 *
 * ```json
 * headerBytes := utf8(json(
 *   {
 *     "alg" : string(algorithmString)
 *   }
 * ))
 * ```
 *
 * The payload is encoded as
 *
 * ```json
 * payloadBytes := utf8(json(
 *   {
 *     "containerVersion" : number(containerVersion),
 *     "keyType" : string(keyTypeString),
 *     "encryptedKey" : base64(encryptedKeyBytes),
 *     "iv" : base64(ivBytes),
 *     "keyUsage" : number(keyUsageValue),
 *     "entitledTaIds" : array[taId],
 *     "c1" : base64(c1Bytes),
 *     "c2" : base64(c2Bytes),
 *     "c3" : base64(c3Bytes),
 *   }
 * ))
 * ```
 *
 * The order of the elements in the payload cannot be guaranteed and is not specified.
 *
 * The container contents are authenticated by the authentication tag, authTag.
 *
 * The container is
 *
 * ```json
 * container := base64Url(headerBytes)  || '.' ||
 *              base64Url(payloadBytes) || '.' ||
 *              base64Url(authTag)
 * ```
 *
 * where "||" indicates concatenation. Padding is omitted from the base64Url encoded values.
 *
 * ## Container Encryption Key
 *
 * The container encryption key K0 is derived from the model root key K3:
 *
 * ```c
 * K2 = AES128-ECB-NoPad-Dec(K3, C1)
 * K1 = AES128-ECB-NoPad-Dec(K2, C2)
 * K0 = AES128-ECB-NoPad-Dec(K1, C3)
 * ```
 *
 * ## Key Encryption
 *
 * The provisioned key is encrypted using AES128 GCM mode. The plain text is the provisioned key:
 *
 * ```
 * P := keyBytes
 * ```
 *
 * ## Authentication Tag
 *
 * The authentication tag is the GCM tag T (see NIST SP800-38D, Section 7) using the specified
 * additionalAuthenticatedData:
 *
 * ```c
 * additionalAuthenticatedData = algorithmString || containerVersion || keyTypeString || keyUsageValue
 * || ivBytes || c1Bytes || c2Bytes || c3Bytes || taId1 || taId2 || ... || taIdN ||
 * ```
 *
 * where
 *
 * * `algorithmString` is the UTF-8 algorithm string in the header (e.g. "A128GCM").
 * * `containerVersion` is the numeric value encoded as a single byte (i.e. 0x02).
 * * `keyTypeString` is a UTF-8 string.
 * * `keyUsageValue` is the numeric value encoded as single byte (i.e. 1 = 0x01, 2 = 0x02, 3 = 0x03).
 * * `ivBytes` is the binary key encryption IV value.
 * * `c1Bytes` if present is the 16-byte binary first-stage key derivation parameter value.
 * * `c2Bytes` if present is the 16-byte binary second-stage key derivation parameter value.
 * * `c3Bytes` if present is the 16-byte binary third-stage key derivation parameter value.
 * * `||` indicates concatenation.
 * * `taId1`, `taId2`, ... `taIdN` are the TA IDs in the `entitledTaIds` array (if included in the
 *   payload). Lower case characters are used in TA UUIDs when calculating the authentication tag
 *   (i.e. "A" - "F" characters are converted to "a" - "f").
 */

#ifndef SOC_KEY_CONTAINER_H
#define SOC_KEY_CONTAINER_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Unwrap SKB SOC key container
 *
 * @param[out] stored_key the stored key from the key container.
 * @param[in] in input data for Type-J container.
 * @param[in] in_length input data length.
 * @param[in] parameters parameters for the key container.
 *
 * @return status of the operation.
 */
sa_status soc_kc_unwrap(
        stored_key_t** stored_key,
        const void* in,
        size_t in_length,
        void* parameters);

#ifdef __cplusplus
}
#endif

#endif // SOC_KEY_CONTAINER_H
