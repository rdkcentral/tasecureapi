/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

#include "client_store.h"
#include "digest.h"
#include "ec.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "rights.h"
#include "rsa.h"
#include "ta_sa.h"

static sa_status ta_sa_crypto_sign_ecdsa(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        const sa_sign_parameters_ecdsa* parameters) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Unknown digest algorithm encountered");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    do {
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (header->type_parameters.curve != SA_ELLIPTIC_CURVE_NIST_P192 &&
                header->type_parameters.curve != SA_ELLIPTIC_CURVE_NIST_P224 &&
                header->type_parameters.curve != SA_ELLIPTIC_CURVE_NIST_P256 &&
                header->type_parameters.curve != SA_ELLIPTIC_CURVE_NIST_P384 &&
                header->type_parameters.curve != SA_ELLIPTIC_CURVE_NIST_P521) {
            ERROR("Invalid curve for ECDSA");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!key_type_supports_ec(header->type, header->type_parameters.curve, header->size)) {
            ERROR("key_type_supports_ec failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        if (out == NULL) {
            *out_length = header->size * 2;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < header->size * 2) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        status = ec_sign_ecdsa(out, out_length, parameters->digest_algorithm, stored_key, in, in_length,
                parameters->precomputed_digest);
        if (status != SA_STATUS_OK) {
            ERROR("ec_sign_ecdsa failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    return status;
}

static sa_status ta_sa_crypto_sign_eddsa(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key,
        const void* in,
        size_t in_length) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    do {
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (header->type_parameters.curve != SA_ELLIPTIC_CURVE_ED25519 &&
                header->type_parameters.curve != SA_ELLIPTIC_CURVE_ED448) {
            ERROR("Invalid curve for EDDSA");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!key_type_supports_ec(header->type, header->type_parameters.curve, header->size)) {
            ERROR("key_type_supports_ec failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        size_t key_size = ec_key_size_from_curve(header->type_parameters.curve) * 2;
        if (key_size == 0) {
            ERROR("Unexpected ec curve encountered");
            status = SA_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        if (out == NULL) {
            *out_length = key_size;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < key_size) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        status = ec_sign_eddsa(out, out_length, stored_key, in, in_length);
        if (status != SA_STATUS_OK) {
            ERROR("ec_sign_ecdsa failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    return status;
}

static sa_status ta_sa_crypto_sign_rsa_pss(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        const sa_sign_parameters_rsa_pss* parameters) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Unknown digest algorithm encountered");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (parameters->mgf1_digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->mgf1_digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->mgf1_digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->mgf1_digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Unknown mgf1 digest algorithm encountered");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    do {
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!key_type_supports_rsa(header->type, header->size)) {
            ERROR("key_type_supports_rsa failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        if (out == NULL) {
            *out_length = header->size;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < header->size) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        size_t digest_length_bytes = digest_length(parameters->digest_algorithm);
        if (digest_length_bytes == 0) {
            ERROR("Invalid digest");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        size_t max_salt_length = header->size - digest_length_bytes - 2;
        if (parameters->salt_length > max_salt_length) {
            ERROR("Invalid salt_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!rsa_sign_pss(out, out_length, parameters->digest_algorithm, stored_key, parameters->mgf1_digest_algorithm,
                    parameters->salt_length, in, in_length, parameters->precomputed_digest)) {
            ERROR("rsa_sign_pss failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    return status;
}

static sa_status ta_sa_crypto_sign_rsa_pkcs1v15(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        const sa_sign_parameters_rsa_pkcs1v15* parameters) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Unknown digest algorithm encountered");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    do {
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!key_type_supports_rsa(header->type, header->size)) {
            ERROR("key_type_supports_rsa failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        if (out == NULL) {
            *out_length = header->size;
            status = SA_STATUS_OK;
            break;
        }

        if (*out_length < header->size) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!rsa_sign_pkcs1v15(out, out_length, parameters->digest_algorithm, stored_key, in, in_length,
                    parameters->precomputed_digest)) {
            ERROR("rsa_sign_pkcs1v15 failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    return status;
}

sa_status ta_sa_crypto_sign(
        void* out,
        size_t* out_length,
        sa_signature_algorithm signature_algorithm,
        sa_key key,
        const void* in,
        size_t in_length,
        const void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (signature_algorithm != SA_SIGNATURE_ALGORITHM_ECDSA &&
            signature_algorithm != SA_SIGNATURE_ALGORITHM_EDDSA &&
            signature_algorithm != SA_SIGNATURE_ALGORITHM_RSA_PSS &&
            signature_algorithm != SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15) {
        ERROR("Invalid algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    stored_key_t* stored_key = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key, key_store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_sign(&header->rights)) {
            ERROR("rights_allowed_sign failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (signature_algorithm == SA_SIGNATURE_ALGORITHM_ECDSA) {
            status = ta_sa_crypto_sign_ecdsa(out, out_length, stored_key, in, in_length,
                    (const sa_sign_parameters_ecdsa*) parameters);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_sign_ecdsa failed");
                break;
            }
        } else if (signature_algorithm == SA_SIGNATURE_ALGORITHM_EDDSA) {
            status = ta_sa_crypto_sign_eddsa(out, out_length, stored_key, in, in_length);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_sign_eddsa failed");
                break;
            }
        } else if (signature_algorithm == SA_SIGNATURE_ALGORITHM_RSA_PSS) {
            status = ta_sa_crypto_sign_rsa_pss(out, out_length, stored_key, in, in_length,
                    (const sa_sign_parameters_rsa_pss*) parameters);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_sign_rsa_pss failed");
                break;
            }
        } else { // algorithm == SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15
            status = ta_sa_crypto_sign_rsa_pkcs1v15(out, out_length, stored_key, in, in_length,
                    (const sa_sign_parameters_rsa_pkcs1v15*) parameters);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_sign_rsa_pkcs1v15 failed");
                break;
            }
        }
    } while (false);

    stored_key_free(stored_key);
    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
