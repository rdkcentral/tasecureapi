/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

/*
 * Some code in this file is based off OpenSSL which is:
 * Copyright 2019-2021 The OpenSSL Project Authors
 * Licensed under the Apache License, Version 2.0
 */

#include "sa_provider_internal.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include "log.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <threads.h>

mtx_t mutex;
static once_flag flag = ONCE_FLAG_INIT;

static OSSL_LIB_CTX* lib_ctx = NULL;
static OSSL_PROVIDER* sa_provider = NULL;
static OSSL_PROVIDER* base_provider = NULL;

static OSSL_FUNC_provider_teardown_fn sa_provider_teardown;
static OSSL_FUNC_provider_get_params_fn sa_provider_get_params;
static OSSL_FUNC_provider_gettable_params_fn sa_provider_gettable_params;
static OSSL_FUNC_provider_query_operation_fn sa_provider_query_operation;
static OSSL_provider_init_fn sa_provider_init;

extern const OSSL_ALGORITHM sa_provider_asym_ciphers[];
extern const OSSL_ALGORITHM sa_provider_ciphers[];
extern const OSSL_ALGORITHM sa_provider_digests[];
extern const OSSL_ALGORITHM sa_provider_kdfs[];
extern const OSSL_ALGORITHM sa_provider_keyexchs[];
extern const OSSL_ALGORITHM sa_provider_keymgmt[];
extern const OSSL_ALGORITHM sa_provider_macs[];
extern const OSSL_ALGORITHM sa_provider_signatures[];

static void sa_provider_teardown(void* provctx) {
    OPENSSL_free(provctx);
}

static int sa_provider_get_params(
        ossl_unused void* provctx,
        OSSL_PARAM params[]) {

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, SA_PROVIDER_NAME)) {
        ERROR("OSSL_PARAM_set_utf8_ptr failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, SA_SPECIFICATION_STR)) {
        ERROR("OSSL_PARAM_set_utf8_ptr failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, SA_SPECIFICATION_STR)) {
        ERROR("OSSL_PARAM_set_utf8_ptr failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (param != NULL && !OSSL_PARAM_set_int(param, 1)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    return 1;
}

static const OSSL_PARAM* sa_provider_gettable_params(ossl_unused void* provctx) {
    static const OSSL_PARAM sa_provider_param_types[] = {
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
            OSSL_PARAM_END};

    return sa_provider_param_types;
}

static const OSSL_ALGORITHM* sa_provider_query_operation(
        ossl_unused void* provctx,
        int operation_id,
        int* no_store) {

    if (no_store == NULL) {
        ERROR("NULL no_store");
        return NULL;
    }

    *no_store = 0;
    switch (operation_id) {
        case OSSL_OP_ASYM_CIPHER:
            return sa_provider_asym_ciphers;

        case OSSL_OP_CIPHER:
            return sa_provider_ciphers;

        case OSSL_OP_DIGEST:
            return sa_provider_digests;

        case OSSL_OP_KDF:
            return sa_provider_kdfs;

        case OSSL_OP_KEYEXCH:
            return sa_provider_keyexchs;

        case OSSL_OP_KEYMGMT:
            return sa_provider_keymgmt;

        case OSSL_OP_MAC:
            return sa_provider_macs;

        case OSSL_OP_SIGNATURE:
            return sa_provider_signatures;

        default:
            return NULL;
    }
}

/* Functions we provide to the core */
static const OSSL_DISPATCH sa_provider_dispatch_table[] = {
        {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) sa_provider_teardown},
        {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) sa_provider_get_params},
        {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) sa_provider_gettable_params},
        {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) sa_provider_query_operation},
        {0, NULL}};

static int sa_provider_init(
        const OSSL_CORE_HANDLE* handle,
        const OSSL_DISPATCH* in,
        const OSSL_DISPATCH** out,
        void** provctx) {

    if (handle == NULL) {
        ERROR("NULL handle");
        return 0;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return 0;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return 0;
    }

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return 0;
    }

    OSSL_FUNC_core_get_libctx_fn* core_get_libctx = NULL;
    for (; in->function_id != 0; in++) {
        if (in->function_id == OSSL_FUNC_CORE_GET_LIBCTX) {
            core_get_libctx = OSSL_FUNC_core_get_libctx(in);
        }
    }

    if (*core_get_libctx == NULL) {
        ERROR("OSSL_FUNC_core_get_libctx failed");
        return 0;
    }

    *provctx = OPENSSL_malloc(sizeof(sa_provider_context));
    if (*provctx == NULL) {
        ERROR("OPENSSL_malloc failed");
        return 0;
    }

    sa_provider_context* provider_context = *provctx;
    provider_context->handle = handle;
    provider_context->lib_ctx = (OSSL_LIB_CTX*) core_get_libctx(handle);

    *out = sa_provider_dispatch_table;
    return 1;
}

static void sa_provider_shutdown() {
    if (mtx_lock(&mutex) != 0) {
        ERROR("mtx_lock failed");
        return;
    }

    if (sa_provider != NULL) {
        OSSL_PROVIDER_unload(sa_provider);
        sa_provider = NULL;
    }

    if (base_provider != NULL) {
        OSSL_PROVIDER_unload(base_provider);
        base_provider = NULL;
    }

    if (lib_ctx != NULL) {
        OSSL_LIB_CTX_free(lib_ctx);
        lib_ctx = NULL;
    }

    mtx_unlock(&mutex);
    mtx_destroy(&mutex);
}

static void sa_provider_load() {
    if (mtx_init(&mutex, mtx_plain | mtx_recursive) != thrd_success) {
        ERROR("mtx_init failed");
    }

    if (mtx_lock(&mutex) != 0) {
        ERROR("mtx_lock failed");
        return;
    }

    lib_ctx = OSSL_LIB_CTX_new();
    if (lib_ctx == NULL) {
        ERROR("OSSL_LIB_CTX_new failed");
        return;
    }

    if (OSSL_PROVIDER_add_builtin(lib_ctx, SA_PROVIDER_ID, sa_provider_init) != 1) {
        ERROR("OSSL_PROVIDER_add_builtin failed");
        return;
    }

    base_provider = OSSL_PROVIDER_load(lib_ctx, "base");
    if (base_provider == NULL) {
        ERROR("OSSL_PROVIDER_load failed");
        return;
    }

    sa_provider = OSSL_PROVIDER_load(lib_ctx, SA_PROVIDER_ID);
    if (sa_provider == NULL) {
        ERROR("OSSL_PROVIDER_load failed");
        return;
    }

    if (atexit(sa_provider_shutdown) != 0) {
        ERROR("atexit failed");
    }

    mtx_unlock(&mutex);
}

OSSL_LIB_CTX* sa_get_provider() {
    call_once(&flag, sa_provider_load);

    if (mtx_lock(&mutex) != 0) {
        ERROR("mtx_lock failed");
        return NULL;
    }

    OSSL_LIB_CTX* provider_context = lib_ctx;
    if (provider_context == NULL) {
        ERROR("NULL provider_context");
    }

    mtx_unlock(&mutex);
    return provider_context;
}

#endif
