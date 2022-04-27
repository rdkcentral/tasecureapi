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

#include "symmetric.h" // NOLINT
#include "common.h"
#include "log.h"
#include "porting/memory.h"
#include "porting/rand.h"
#include "sa_types.h"
#include "stored_key_internal.h"
#include <openssl/evp.h>
#include <string.h>

struct symmetric_context_s {
    sa_cipher_algorithm cipher_algorithm;
    sa_cipher_mode cipher_mode;
    EVP_CIPHER_CTX* evp_cipher;
};

bool symmetric_generate_key(
        stored_key_t** stored_key_generated,
        const sa_rights* rights,
        sa_generate_parameters_symmetric* parameters) {

    if (stored_key_generated == NULL) {
        ERROR("NULL stored_key_generated");
        return false;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return false;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return false;
    }

    bool status = false;
    uint8_t* generated = NULL;
    do {
        generated = memory_secure_alloc(parameters->key_length);
        if (generated == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!rand_bytes(generated, parameters->key_length)) {
            ERROR("rand_bytes failed");
            break;
        }

        status = stored_key_create(stored_key_generated, rights, NULL, SA_KEY_TYPE_SYMMETRIC, 0, parameters->key_length,
                generated, parameters->key_length);
        if (!status) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (generated != NULL) {
        memory_memset_unoptimizable(generated, 0, parameters->key_length);
        memory_secure_free(generated);
    }

    return status;
}

sa_status symmetric_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key) {

    if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20 || cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        return SA_STATUS_OPERATION_NOT_SUPPORTED;
#else
        return SA_STATUS_OK;
#endif
    }

    return SA_STATUS_OK;
}

symmetric_context_t* symmetric_create_aes_ecb_encrypt_context(const stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_ecb();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_ecb();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ecb failed");
            break;
        }

        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, key, NULL) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_cbc_encrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != AES_BLOCK_SIZE) {
        ERROR("Bad iv_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_cbc();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_cbc();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_cbc failed");
            break;
        }

        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_ctr_encrypt_context(
        const stored_key_t* stored_key,
        const void* counter,
        size_t counter_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != AES_BLOCK_SIZE) {
        ERROR("Bad counter_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_ctr();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_ctr();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ctr failed");
            break;
        }

        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, key, counter) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_gcm_encrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != GCM_IV_LENGTH) {
        ERROR("Bad iv_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_gcm();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_gcm();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_counter failed");
            break;
        }

        // init cipher
        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, NULL, NULL) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // set iv length
        if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_GCM_SET_IVLEN, (int) iv_length, NULL) != 1) {
            ERROR("EVP_CIPHER_CTX_counterl failed");
            break;
        }

        // init key and iv
        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        // set aad
        if (aad) {
            int out_length = 0;
            if (EVP_EncryptUpdate(context->evp_cipher, NULL, &out_length, aad, (int) aad_length) != 1) {
                ERROR("EVP_EncryptUpdate failed");
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_chacha20_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* counter,
        size_t counter_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != CHACHA20_COUNTER_LENGTH) {
        ERROR("Bad counter_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Bad nonce_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = EVP_chacha20();
        if (cipher == NULL) {
            ERROR("EVP_chacha20 failed");
            break;
        }

        uint8_t iv[CHACHA20_COUNTER_LENGTH + CHACHA20_NONCE_LENGTH];
        memcpy(iv, counter, counter_length);
        memcpy(iv + CHACHA20_COUNTER_LENGTH, nonce, nonce_length);
        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

symmetric_context_t* symmetric_create_chacha20_poly1305_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* aad,
        size_t aad_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Bad nonce_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
        if (cipher == NULL) {
            ERROR("EVP_chacha20_poly1305 failed");
            break;
        }

        // init cipher
        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, NULL, NULL) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // set nonce length
        if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_AEAD_SET_IVLEN, (int) nonce_length, NULL) != 1) {
            ERROR("EVP_CIPHER_CTX_counterl failed");
            break;
        }

        // init key and nonce
        if (EVP_EncryptInit_ex(context->evp_cipher, cipher, NULL, key, nonce) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        // set aad
        if (aad) {
            int out_length = 0;
            if (EVP_EncryptUpdate(context->evp_cipher, NULL, &out_length, aad, (int) aad_length) != 1) {
                ERROR("EVP_EncryptUpdate failed");
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

symmetric_context_t* symmetric_create_aes_ecb_decrypt_context(const stored_key_t* stored_key) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_ecb();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_ecb();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ecb failed");
            break;
        }

        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, key, NULL) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_cbc_decrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != AES_BLOCK_SIZE) {
        ERROR("Bad iv_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_cbc();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_cbc();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_cbc failed");
            break;
        }

        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_ctr_decrypt_context(
        const stored_key_t* stored_key,
        const void* counter,
        size_t counter_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != AES_BLOCK_SIZE) {
        ERROR("Bad counter_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_ctr();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_ctr();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ctr failed");
            break;
        }

        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, key, counter) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_gcm_decrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != GCM_IV_LENGTH) {
        ERROR("Bad iv_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_gcm();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_gcm();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ctr failed");
            break;
        }

        // init cipher
        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, NULL, NULL) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // set iv length
        if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_GCM_SET_IVLEN, (int) iv_length, NULL) != 1) {
            ERROR("EVP_CIPHER_CTX_ctrl failed");
            break;
        }

        // init key and iv
        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        // set aad
        if (aad) {
            int out_length = 0;
            if (EVP_DecryptUpdate(context->evp_cipher, NULL, &out_length, aad, (int) aad_length) != 1) {
                ERROR("EVP_DecryptUpdate failed");
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_chacha20_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* counter,
        size_t counter_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != CHACHA20_COUNTER_LENGTH) {
        ERROR("Bad counter_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Bad nonce_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = EVP_chacha20();
        if (cipher == NULL) {
            ERROR("EVP_chacha20 failed");
            break;
        }

        uint8_t iv[CHACHA20_COUNTER_LENGTH + CHACHA20_NONCE_LENGTH];
        memcpy(iv, counter, counter_length);
        memcpy(iv + CHACHA20_COUNTER_LENGTH, nonce, nonce_length);
        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

symmetric_context_t* symmetric_create_chacha20_poly1305_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* aad,
        size_t aad_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Bad nonce_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;

        context->evp_cipher = EVP_CIPHER_CTX_new();
        if (context->evp_cipher == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
        if (cipher == NULL) {
            ERROR("EVP_chacha20_poly1305 failed");
            break;
        }

        // init cipher
        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, NULL, NULL) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // set nonce length
        if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_AEAD_SET_IVLEN, (int) nonce_length, NULL) != 1) {
            ERROR("EVP_CIPHER_CTX_ctrl failed");
            break;
        }

        // init key and nonce
        if (EVP_DecryptInit_ex(context->evp_cipher, cipher, NULL, key, nonce) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context->evp_cipher, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        // set aad
        if (aad) {
            int out_length = 0;
            if (EVP_DecryptUpdate(context->evp_cipher, NULL, &out_length, aad, (int) aad_length) != 1) {
                ERROR("EVP_DecryptUpdate failed");
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

bool symmetric_context_encrypt(
        const symmetric_context_t* context,
        void* out,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Bad cipher mode");
        return false;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        if (in_length % AES_BLOCK_SIZE != 0) {
            ERROR("Bad in_length");
            return false;
        }
    }

    int length = (int) in_length;
    if (EVP_EncryptUpdate(context->evp_cipher, out, &length, in, (int) in_length) != 1) {
        ERROR("EVP_EncryptUpdate failed");
        return false;
    }

    return true;
}

bool symmetric_context_encrypt_last(
        const symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Bad cipher mode");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Bad context algorithm");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && in_length > AES_BLOCK_SIZE) {
        ERROR("Bad in_length");
        return false;
    }

    if (out == NULL) {
        *out_length = in_length;
        return true;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    int length = (int) in_length;
    if (EVP_EncryptUpdate(context->evp_cipher, out, &length, in, (int) in_length) != 1) {
        ERROR("EVP_EncryptUpdate failed");
        return false;
    }

    *out_length = length;
    return true;
}

bool symmetric_context_decrypt(
        const symmetric_context_t* context,
        void* out,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Bad cipher mode");
        return false;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        if (in_length % AES_BLOCK_SIZE != 0) {
            ERROR("Bad in_length");
            return false;
        }
    }

    int length = (int) in_length;
    if (EVP_DecryptUpdate(context->evp_cipher, out, &length, in, (int) in_length) != 1) {
        ERROR("EVP_DecryptUpdate failed");
        return false;
    }

    return true;
}

bool symmetric_context_decrypt_last(
        const symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Bad cipher mode");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Bad context algorithm");
        return false;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && in_length > AES_BLOCK_SIZE) {
        ERROR("Bad in_length");
        return false;
    }

    if (out == NULL) {
        *out_length = in_length;
        return true;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    int length = (int) in_length;
    if (EVP_DecryptUpdate(context->evp_cipher, out, &length, in, (int) in_length) != 1) {
        ERROR("EVP_DecryptUpdate failed");
        return false;
    }

    *out_length = length;
    return true;
}

bool symmetric_context_set_iv(
        const symmetric_context_t* context,
        const void* iv,
        size_t iv_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
            context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
            context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
        if (iv_length != AES_BLOCK_SIZE) {
            ERROR("Bad iv_length");
            return false;
        }
    } else {
        ERROR("Bad cipher algorithm");
        return false;
    }

    if (context->cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
        if (EVP_EncryptInit_ex(context->evp_cipher, NULL, NULL, NULL, iv) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            return false;
        }
    } else if (context->cipher_mode == SA_CIPHER_MODE_DECRYPT) {
        if (EVP_DecryptInit_ex(context->evp_cipher, NULL, NULL, NULL, iv) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            return false;
        }
    } else {
        ERROR("Bad cipher mode");
        return false;
    }

    return true;
}

bool symmetric_context_get_tag(
        const symmetric_context_t* context,
        void* tag,
        size_t tag_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Bad cipher algorithm");
        return false;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Bad cipher mode");
        return false;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return false;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM && tag_length > AES_BLOCK_SIZE) {
        ERROR("Bad tag_length");
        return false;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && tag_length != CHACHA20_TAG_LENGTH) {
        ERROR("Bad tag_length");
        return false;
    }

    int length = 0;
    if (EVP_EncryptFinal_ex(context->evp_cipher, NULL, &length) != 1) {
        ERROR("EVP_EncryptFinal_ex failed");
        return false;
    }

    uint8_t local_tag[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_GCM_GET_TAG, sizeof(local_tag), local_tag) != 1) {
#else
    if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_AEAD_GET_TAG, sizeof(local_tag), local_tag) != 1) {
#endif
        ERROR("EVP_CIPHER_CTX_ctrl failed");
        return false;
    }

    memcpy(tag, local_tag, tag_length);

    return true;
}

bool symmetric_context_check_tag(
        const symmetric_context_t* context,
        const void* tag,
        size_t tag_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return false;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Bad cipher algorithm");
        return false;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Bad cipher mode");
        return false;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return false;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM && tag_length > AES_BLOCK_SIZE) {
        ERROR("Bad tag_length");
        return false;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && tag_length != CHACHA20_TAG_LENGTH) {
        ERROR("Bad tag_length");
        return false;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_GCM_SET_TAG, (int) tag_length, (void*) tag) != 1) {
#else
    if (EVP_CIPHER_CTX_ctrl(context->evp_cipher, EVP_CTRL_AEAD_SET_TAG, (int) tag_length, (void*) tag) != 1) {
#endif
        ERROR("EVP_CIPHER_CTX_ctrl failed");
        return false;
    }

    int length = 0;
    if (EVP_DecryptFinal_ex(context->evp_cipher, NULL, &length) != 1) {
        ERROR("EVP_DecryptFinal_ex failed");
        return false;
    }

    return true;
}

void symmetric_context_free(symmetric_context_t* context) {
    if (context == NULL) {
        return;
    }

    if (context->evp_cipher != NULL)
        EVP_CIPHER_CTX_free(context->evp_cipher);

    memory_internal_free(context);
}
