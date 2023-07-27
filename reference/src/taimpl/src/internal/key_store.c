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

#include "key_store.h" // NOLINT
#include "common.h"
#include "key_type.h"
#include "log.h"
#include "pad.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "porting/rand.h"
#include "rights.h"
#include "stored_key_internal.h"
#include <memory.h>
#include <time.h>

/**
 * Key ladder inputs for Kwrap (Key wrapping key) and Kint (Key integrity key). These keys are used
 * for confidentiality and integrity envelopes around exported key material.
 *
 * Key ladder inputs are NOT considered as sensitive material.
 */
typedef struct {
    key_ladder_inputs_t wrapping_key_inputs;
    key_ladder_inputs_t integrity_key_inputs;
} derivation_inputs_t;

struct {
    derivation_inputs_t export_derivation_inputs;
} global_key_store = {
    // These values are randomly generated.
    // clang-format off
    .export_derivation_inputs = {
        .wrapping_key_inputs = {
            {0x91, 0xa4, 0x5a, 0xc9, 0x2b, 0x5e, 0xd7, 0x40, 0x20, 0x33, 0x6e, 0x47, 0xad, 0x48, 0x56, 0xba},
            {0x82, 0x1b, 0x1f, 0x0c, 0x52, 0x04, 0x8b, 0x28, 0xbe, 0xa0, 0x59, 0x34, 0xb4, 0xd9, 0xa8, 0xae},
            {0x80, 0x46, 0xd8, 0xdc, 0xf3, 0xfb, 0xcd, 0xfb, 0x85, 0x05, 0x30, 0x6d, 0x07, 0x33, 0x5b, 0x8c}
        },
        .integrity_key_inputs = {
            {0xe5, 0x46, 0xb9, 0x91, 0xb5, 0x2c, 0x79, 0xf8, 0xab, 0x9f, 0x34, 0xb8, 0x85, 0x9a, 0xec, 0x19},
            {0x77, 0x48, 0xbf, 0xc6, 0x21, 0x6d, 0x89, 0x19, 0x7c, 0x51, 0xc9, 0xaf, 0x52, 0xe3, 0xed, 0x2a},
            {0x11, 0x5b, 0xb8, 0xf6, 0x1a, 0xe1, 0xbe, 0x28, 0x03, 0xb1, 0x98, 0x4a, 0xde, 0xff, 0x57, 0x08}
        }
    }
    // clang-format on
};

typedef struct {
    uint8_t iv[AES_BLOCK_SIZE];
    size_t ciphertext_length;
} cipher_parameters_t;

typedef struct {
    uint8_t mac[SHA256_DIGEST_LENGTH];
} signature_t;

/**
 * Keystore key
 */
typedef struct {
    sa_header header;
    cipher_parameters_t cipher_parameters;
    void* ciphertext;
    signature_t signature;
    derivation_inputs_t derivation_inputs;
} wrapped_key_t;

// clang-format off
static void xor(
        uint8_t *out,
        const uint8_t *in1,
        const uint8_t *in2,
        size_t size) {

    for (size_t i = 0; i < size; ++i) {
        out[i] = in1[i] ^ in2[i];
    }
}

static bool validate_header_format(const sa_header *hdr) {
    if (hdr == NULL) {
        WARN("NULL hdr");
        return false;
    }

    // check magic
    static const char MAGIC[NUM_MAGIC] = {'s', 'a', 'k', '0'};
    if (memory_memcmp_constant(hdr->magic, MAGIC, sizeof(MAGIC)) != 0) {
        WARN("Invalid magic detected");
        return false;
    }

    // check rights
    if (!rights_validate_format(&hdr->rights)) {
        WARN("Invalid rights detected");
        return false;
    }

    // check type
    if (!key_type_supports_any(hdr->type, hdr->type_parameters.curve, hdr->size)) {
        ERROR("key_type_supports_any failed");
        return false;
    }

    return true;
}
// clang-format on

static void* pad(
        size_t* padded_length,
        const void* in,
        size_t in_length) {

    if (padded_length == NULL) {
        ERROR("NULL padded_length");
        return NULL;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return NULL;
    }

    *padded_length = PADDED_SIZE(in_length);
    uint8_t* padded = memory_secure_alloc(*padded_length);
    if (padded == NULL) {
        ERROR("memory_secure_alloc failed");
        return NULL;
    }

    uint8_t pad_value = *padded_length - in_length;
    if (!pad_apply_pkcs7(padded + *padded_length - AES_BLOCK_SIZE, pad_value)) {
        ERROR("pad_apply_pkcs7 failed");
        memory_secure_free(padded);
        return NULL;
    }

    memcpy(padded, in, in_length);

    return padded;
}

static stored_key_t* unwrap(
        const derivation_inputs_t* derivation_inputs,
        const sa_header* header,
        const cipher_parameters_t* cipher_parameters,
        const void* ciphertext,
        const signature_t* signature) {

    if (derivation_inputs == NULL) {
        ERROR("NULL derivation_inputs");
        return NULL;
    }

    if (header == NULL) {
        ERROR("NULL header");
        return NULL;
    }

    if (cipher_parameters == NULL) {
        ERROR("NULL cipher_parameters");
        return NULL;
    }

    if (ciphertext == NULL) {
        ERROR("NULL ciphertext");
        return NULL;
    }

    if (signature == NULL) {
        ERROR("NULL signature");
        return NULL;
    }

    if (cipher_parameters->ciphertext_length < AES_BLOCK_SIZE ||
            cipher_parameters->ciphertext_length % AES_BLOCK_SIZE != 0) {
        ERROR("Invalid ciphertext_length");
        return NULL;
    }

    stored_key_t* stored_key = NULL;
    uint8_t* cleartext = NULL;
    do {
        // check signature
        uint8_t computed_mac[SHA256_DIGEST_LENGTH];
        if (otp_hmac_sha256(computed_mac, &derivation_inputs->integrity_key_inputs, header, sizeof(sa_header),
                    cipher_parameters, sizeof(cipher_parameters_t), ciphertext,
                    cipher_parameters->ciphertext_length) != SA_STATUS_OK) {
            ERROR("otp_hmac_sha256 failed");
            break;
        }

        if (memory_memcmp_constant(computed_mac, signature->mac, SHA256_DIGEST_LENGTH) != 0) {
            ERROR("signature does not match computed one");
            break;
        }

        // allocate cleartext
        cleartext = memory_secure_alloc(cipher_parameters->ciphertext_length);
        if (cleartext == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // decrypt key
        if (otp_unwrap_aes_cbc(cleartext, &derivation_inputs->wrapping_key_inputs, ciphertext,
                    cipher_parameters->ciphertext_length, cipher_parameters->iv) != SA_STATUS_OK) {
            ERROR("otp_unwrap_aes_cbc failed");
            break;
        }

        // check pad
        uint8_t pad_value = 0;
        if (!pad_check_pkcs7(&pad_value, cleartext + cipher_parameters->ciphertext_length - AES_BLOCK_SIZE)) {
            ERROR("pad_check_pkcs7 failed");
            break;
        }

        if (stored_key_create(&stored_key, &header->rights, NULL, header->type, &header->type_parameters,
                    header->size, cleartext, cipher_parameters->ciphertext_length - pad_value) != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (cleartext != NULL) {
        memory_memset_unoptimizable(cleartext, 0, cipher_parameters->ciphertext_length);
        memory_secure_free(cleartext);
    }

    return stored_key;
}

static void wrapped_key_free(void* obj) {
    if (obj == NULL) {
        return;
    }

    wrapped_key_t* wrapped_key = (wrapped_key_t*) obj;

    memory_memset_unoptimizable(wrapped_key->ciphertext, 0, wrapped_key->cipher_parameters.ciphertext_length);
    memory_secure_free(wrapped_key->ciphertext);

    memory_memset_unoptimizable(wrapped_key, 0, sizeof(wrapped_key_t));
    memory_secure_free(wrapped_key);
}

static wrapped_key_t* wrapped_key_create(
        const derivation_inputs_t* derivation_inputs,
        const stored_key_t* stored_key) {

    if (derivation_inputs == NULL) {
        ERROR("NULL derivation_inputs");
        return NULL;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    bool status = false;
    wrapped_key_t* wrapped_key = NULL;
    do {
        // allocate wrapped key struct
        wrapped_key = memory_secure_alloc(sizeof(wrapped_key_t));
        if (wrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(wrapped_key, 0, sizeof(wrapped_key_t));

        // copy key derivation inputs
        memcpy(&wrapped_key->derivation_inputs, derivation_inputs, sizeof(derivation_inputs_t));

        // pad input
        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        wrapped_key->ciphertext = pad(&wrapped_key->cipher_parameters.ciphertext_length, key, key_length);
        if (wrapped_key->ciphertext == NULL) {
            ERROR("pad failed");
            break;
        }

        // copy key_header
        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        memcpy(&wrapped_key->header, header, sizeof(sa_header));

        // setup cipher parameters
        if (!rand_bytes(wrapped_key->cipher_parameters.iv, AES_BLOCK_SIZE)) {
            ERROR("rand_bytes failed");
            break;
        }

        // encrypt in-place

        if (otp_wrap_aes_cbc(wrapped_key->ciphertext, &derivation_inputs->wrapping_key_inputs,
                    wrapped_key->ciphertext, wrapped_key->cipher_parameters.ciphertext_length,
                    wrapped_key->cipher_parameters.iv) != SA_STATUS_OK) {
            ERROR("otp_wrap_aes_cbc failed");
            break;
        }

        // generate signature
        if (otp_hmac_sha256(wrapped_key->signature.mac, &derivation_inputs->integrity_key_inputs,
                    &wrapped_key->header, sizeof(wrapped_key->header), &wrapped_key->cipher_parameters,
                    sizeof(wrapped_key->cipher_parameters), wrapped_key->ciphertext,
                    wrapped_key->cipher_parameters.ciphertext_length) != SA_STATUS_OK) {
            ERROR("otp_hmac_sha256 failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        wrapped_key_free(wrapped_key);
        wrapped_key = NULL;
    }

    return wrapped_key;
}

static stored_key_t* wrapped_key_unwrap(const wrapped_key_t* wrapped_key) {
    if (wrapped_key == NULL) {
        ERROR("NULL wrapped_key");
        return NULL;
    }

    stored_key_t* stored_key = unwrap(&wrapped_key->derivation_inputs, &wrapped_key->header,
            &wrapped_key->cipher_parameters, wrapped_key->ciphertext, &wrapped_key->signature);
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    return stored_key;
}

key_store_t* key_store_init(size_t size) {
    key_store_t* store = object_store_init(wrapped_key_free, size, "key");
    if (store == NULL) {
        ERROR("object_store_init failed");
        return NULL;
    }

    return store;
}

void key_store_shutdown(key_store_t* store) {
    object_store_shutdown(store);
}

sa_status key_store_import_stored_key(
        sa_key* key,
        key_store_t* store,
        stored_key_t* stored_key,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    if (!validate_header_format(header)) {
        ERROR("validate_header_format failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    wrapped_key_t* wrapped_key = NULL;
    derivation_inputs_t derivation_inputs;
    do {
        if (!rand_bytes(&derivation_inputs, sizeof(derivation_inputs))) {
            ERROR("rand_bytes failed");
            break;
        }

        wrapped_key = wrapped_key_create(&derivation_inputs, stored_key);
        if (wrapped_key == NULL) {
            ERROR("wrapped_key_create failed");
            break;
        }

        status = object_store_add(key, store, wrapped_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("object_store_add failed");
            break;
        }

        // wrapped_key is now owned by the store
        wrapped_key = NULL;
    } while (false);

    memory_memset_unoptimizable(&derivation_inputs, 0, sizeof(derivation_inputs));
    wrapped_key_free(wrapped_key);

    return status;
}

sa_status key_store_import_exported(
        sa_key* key,
        key_store_t* store,
        const void* exported,
        size_t exported_length,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (exported == NULL) {
        ERROR("NULL exported");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t min_exported_length = AES_BLOCK_SIZE + sizeof(sa_header) + sizeof(cipher_parameters_t) + AES_BLOCK_SIZE +
                                 sizeof(signature_t);
    if (exported_length < min_exported_length) {
        ERROR("Invalid exported_length");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    const uint8_t* exported_bytes = (const uint8_t*) exported;
    const uint8_t* mixin = exported_bytes;
    exported_bytes += AES_BLOCK_SIZE;
    const sa_header* header = (const sa_header*) exported_bytes;
    exported_bytes += sizeof(sa_header);

    if (!validate_header_format(header)) {
        ERROR("validate_header_format failed");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    const cipher_parameters_t* cipher_parameters = (const cipher_parameters_t*) (exported_bytes);
    exported_bytes += sizeof(cipher_parameters_t);

    if (cipher_parameters->ciphertext_length < AES_BLOCK_SIZE ||
            (cipher_parameters->ciphertext_length % AES_BLOCK_SIZE) != 0) {

        ERROR("Invalid ciphertext_length");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    size_t required_exported_length = AES_BLOCK_SIZE + sizeof(sa_header) + sizeof(cipher_parameters_t) +
                                      cipher_parameters->ciphertext_length + sizeof(signature_t);
    if (exported_length != required_exported_length) {
        ERROR("Invalid exported_length");
        return SA_STATUS_INVALID_KEY_FORMAT;
    }

    const void* ciphertext = exported_bytes;
    exported_bytes += cipher_parameters->ciphertext_length;

    const signature_t* signature = (const signature_t*) exported_bytes;

    sa_status status;
    stored_key_t* stored_key = NULL;
    derivation_inputs_t derivation_inputs;
    do {
        memcpy(&derivation_inputs, &global_key_store.export_derivation_inputs,
                sizeof(derivation_inputs_t));

        // apply mixin
        xor(derivation_inputs.wrapping_key_inputs.c3,
                global_key_store.export_derivation_inputs.wrapping_key_inputs.c3, mixin, AES_BLOCK_SIZE);
        xor(derivation_inputs.integrity_key_inputs.c3,
                global_key_store.export_derivation_inputs.integrity_key_inputs.c3, mixin, AES_BLOCK_SIZE);

        stored_key = unwrap(&derivation_inputs, header, cipher_parameters, ciphertext, signature);
        if (stored_key == NULL) {
            ERROR("unwrap failed");
            status = SA_STATUS_INVALID_KEY_FORMAT;
            break;
        }

        status = key_store_import_stored_key(key, store, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    memory_memset_unoptimizable(&derivation_inputs, 0, sizeof(derivation_inputs_t));
    stored_key_free(stored_key);

    return status;
}

sa_status key_store_unwrap(
        stored_key_t** stored_key,
        key_store_t* store,
        sa_key key,
        const sa_uuid* caller_uuid) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *stored_key = NULL;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key >= object_store_size(store)) {
        ERROR("Invalid id");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    wrapped_key_t* wrapped_key = NULL;
    do {
        void* object = NULL;
        status = object_store_acquire(&object, store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("object_store_acquire failed");
            break;
        }
        wrapped_key = object;

        if (!rights_allowed_uuid(&wrapped_key->header.rights, caller_uuid)) {
            ERROR("caller_uuid in not in the allowed TA list");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!rights_allowed_time(&wrapped_key->header.rights, time(NULL))) {
            ERROR("rights_allowed_time failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        video_output_state_t video_output_state;
        if (!video_output_poll(&video_output_state)) {
            ERROR("video_output_poll failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!rights_allowed_video_output_state(&wrapped_key->header.rights, &video_output_state)) {
            ERROR("rights_allowed_video_output_state failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        *stored_key = wrapped_key_unwrap(wrapped_key);
        if (!*stored_key) {
            ERROR("wrapped_key_unwrap failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    object_store_release(store, key, wrapped_key, caller_uuid);

    return status;
}

sa_status key_store_get_header(
        sa_header* header,
        key_store_t* store,
        sa_key key,
        const sa_uuid* caller_uuid) {

    if (header == NULL) {
        ERROR("NULL header");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key >= object_store_size(store)) {
        ERROR("Invalid id");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    wrapped_key_t* wrapped_key = NULL;
    do {
        void* object = NULL;
        status = object_store_acquire(&object, store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("object_store_acquire failed");
            break;
        }
        wrapped_key = object;

        memory_memset_unoptimizable(header, 0, sizeof(sa_header));

        // fill key_header
        static const char MAGIC[NUM_MAGIC] = {'s', 'a', 'k', '0'};
        memcpy(header->magic, MAGIC, sizeof(MAGIC));
        memcpy(&header->rights, &wrapped_key->header.rights, sizeof(sa_rights));
        header->type = wrapped_key->header.type;
        memcpy(&header->type_parameters, &wrapped_key->header.type_parameters, sizeof(sa_type_parameters));
        header->size = wrapped_key->header.size;

        status = SA_STATUS_OK;
    } while (false);

    object_store_release(store, key, wrapped_key, caller_uuid);

    return status;
}

sa_status key_store_export(
        void* out,
        size_t* out_length,
        key_store_t* store,
        sa_key key,
        const void* mixin,
        size_t mixin_length,
        const sa_uuid* caller_uuid) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key >= object_store_size(store)) {
        ERROR("Invalid key");
        return SA_STATUS_INVALID_PARAMETER;
    }

    static const uint8_t DEFAULT_MIXIN[AES_BLOCK_SIZE] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (mixin == NULL) {
        mixin = DEFAULT_MIXIN;
    } else if (mixin_length != AES_BLOCK_SIZE) {
        ERROR("Invalid mixin_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    wrapped_key_t* wrapped_key = NULL;
    stored_key_t* stored_key = NULL;
    wrapped_key_t* rewrapped_key = NULL;
    derivation_inputs_t derivation_inputs;
    do {
        void* object = NULL;
        status = object_store_acquire(&object, store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("object_store_acquire failed");
            break;
        }
        wrapped_key = object;

        if (!SA_USAGE_BIT_TEST(wrapped_key->header.rights.usage_flags, SA_USAGE_FLAG_CACHEABLE)) {
            WARN("Cannot export key that is not cacheable");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        size_t required_out_length = AES_BLOCK_SIZE + sizeof(sa_header) + sizeof(cipher_parameters_t) +
                                     wrapped_key->cipher_parameters.ciphertext_length + sizeof(signature_t);

        if (out == NULL) {
            // set the out_length to bytes required
            *out_length = required_out_length;
            status = SA_STATUS_OK;
            break;
        }

        if (required_out_length > *out_length) {
            ERROR("Invalid out_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // unwrap
        stored_key = wrapped_key_unwrap(wrapped_key);
        if (stored_key == NULL) {
            ERROR("wrapped_key_unwrap failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // setup derivation inputs
        memcpy(&derivation_inputs, &global_key_store.export_derivation_inputs, sizeof(derivation_inputs_t));

        // apply mixin
        xor(derivation_inputs.wrapping_key_inputs.c3,
                global_key_store.export_derivation_inputs.wrapping_key_inputs.c3, mixin, AES_BLOCK_SIZE);
        xor(derivation_inputs.integrity_key_inputs.c3,
                global_key_store.export_derivation_inputs.integrity_key_inputs.c3, mixin, AES_BLOCK_SIZE);

        // rewrap with export derivation inputs
        rewrapped_key = wrapped_key_create(&derivation_inputs, stored_key);
        if (rewrapped_key == NULL) {
            ERROR("wrapped_key_create failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // write out
        uint8_t* out_bytes = (uint8_t*) out;
        size_t offset = 0;
        memcpy(out_bytes + offset, mixin, AES_BLOCK_SIZE);
        offset += AES_BLOCK_SIZE;
        memcpy(out_bytes + offset, &rewrapped_key->header, sizeof(sa_header));
        offset += sizeof(sa_header);
        memcpy(out_bytes + offset, &rewrapped_key->cipher_parameters, sizeof(cipher_parameters_t));
        offset += sizeof(cipher_parameters_t);
        memcpy(out_bytes + offset, rewrapped_key->ciphertext, rewrapped_key->cipher_parameters.ciphertext_length);
        offset += rewrapped_key->cipher_parameters.ciphertext_length;
        memcpy(out_bytes + offset, &rewrapped_key->signature, sizeof(signature_t));

        *out_length = required_out_length;
        status = SA_STATUS_OK;
    } while (false);

    object_store_release(store, key, wrapped_key, caller_uuid);
    stored_key_free(stored_key);
    wrapped_key_free(rewrapped_key);
    memory_memset_unoptimizable(&derivation_inputs, 0, sizeof(derivation_inputs_t));

    return status;
}

sa_status key_store_remove(
        key_store_t* store,
        sa_key key,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = object_store_remove(store, key, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_remove failed");
        return status;
    }

    return SA_STATUS_OK;
}
