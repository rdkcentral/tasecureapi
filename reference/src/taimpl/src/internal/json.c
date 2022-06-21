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

#include "json.h"
#include "log.h"
#include "porting/memory.h"
#include <memory.h>
#include <openssl/evp.h>
#include <yajl/yajl_parse.h>
#include <yajl/yajl_version.h>

#define MAX_KEY_LENGTH 255

struct json_value_s {
    json_type_e type;
    void* payload;
    size_t payload_length;
};

static int bool_callback(void* context, int boolean_value);

static int double_callback(void* context, double double_value);

static int end_array_callback(void* context);

static int end_map_callback(void* context);

#if YAJL_MAJOR < 2
static int integer_callback(void* context, long integer_value);
static int map_key_callback(void* context, const unsigned char* key, unsigned int key_length);
#else
static int integer_callback(void* context, long long integer_value);
static int map_key_callback(void* context, const unsigned char* key, size_t key_length);

#endif

static int null_callback(void* context);

static int start_array_callback(void* context);

static int start_map_callback(void* context);

#if YAJL_MAJOR < 2
static int string_callback(void* context, const unsigned char* string, unsigned int string_length);
#else

static int string_callback(void* context, const unsigned char* string, size_t string_length);

#endif

struct {
#if YAJL_MAJOR < 2
    yajl_parser_config parser_configuration;
#endif
    yajl_callbacks callbacks;
} global_json = {
// clang-format off
#if YAJL_MAJOR < 2
        .parser_configuration = {
                .allowComments = 0,
                .checkUTF8 = 1},
#endif
        .callbacks = {
                .yajl_boolean = bool_callback,
                .yajl_double = double_callback,
                .yajl_end_array = end_array_callback,
                .yajl_end_map = end_map_callback,
                .yajl_integer = integer_callback,
                .yajl_map_key = map_key_callback,
                .yajl_null = null_callback,
                .yajl_number = NULL,
                .yajl_start_array = start_array_callback,
                .yajl_start_map = start_map_callback,
                .yajl_string = string_callback
        }
        // clang-format on
};

typedef struct json_map_s {
    char* key;
    size_t key_length;
    json_value_t* value;
    struct json_map_s* next;
} json_map_t;

static json_map_t* json_map_new() {
    json_map_t* map = memory_internal_alloc(sizeof(json_map_t));
    if (map == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }

    memory_memset_unoptimizable(map, 0, sizeof(json_map_t));
    return map;
}

static void json_map_free(json_map_t* map) {
    if (map == NULL) {
        return;
    }

    memory_internal_free(map->key);
    json_value_free(map->value);
    json_map_free(map->next);
    memory_internal_free(map);
}

static size_t json_map_size(const json_map_t* map) {
    if (map->next == NULL) {
        return 0;
    }

    return 1 + json_map_size(map->next);
}

static json_map_t* json_map_last_key_value(json_map_t* map) {
    if (map == NULL) {
        return NULL;
    }

    if (map->next == NULL) {
        return map;
    }

    return json_map_last_key_value(map->next);
}

static json_map_t* json_map_add_key_value(json_map_t* map) {
    if (map == NULL) {
        ERROR("NULL map");
        return NULL;
    }

    json_map_t* key_value = json_map_new();
    if (key_value == NULL) {
        ERROR("json_map_new failed");
        return NULL;
    }

    json_map_t* last = json_map_last_key_value(map);
    last->next = key_value;

    return key_value;
}

static void json_map_set_key(
        json_map_t* map,
        char* key,
        size_t key_length) {
    if (map == NULL) {
        ERROR("NULL map");
        return;
    }

    memory_internal_free(map->key);
    map->key = key;
    map->key_length = key_length;
}

static void json_map_set_value(
        json_map_t* map,
        json_value_t* value) {
    if (map == NULL) {
        ERROR("NULL map");
        return;
    }

    json_value_free(map->value);
    map->value = value;
}

typedef struct json_array_s {
    json_value_t* value;
    struct json_array_s* next;
} json_array_t;

static json_array_t* json_array_new() {
    json_array_t* array = memory_internal_alloc(sizeof(json_array_t));
    if (array == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }

    memory_memset_unoptimizable(array, 0, sizeof(json_array_t));
    return array;
}

static void json_array_free(json_array_t* array) {
    if (array == NULL) {
        return;
    }

    json_array_free(array->next);
    json_value_free(array->value);
    memory_internal_free(array);
}

static size_t json_array_size(const json_array_t* array) {
    if (array->next == NULL) {
        return 0;
    }

    return 1 + json_array_size(array->next);
}

static void json_array_set_value(json_array_t* array, json_value_t* value) {
    if (array == NULL) {
        ERROR("NULL array");
        return;
    }

    json_value_free(array->value);
    array->value = value;
}

static json_array_t* json_array_last(json_array_t* array) {
    if (array == NULL) {
        return NULL;
    }

    if (array->next == NULL) {
        return array;
    }

    return json_array_last(array->next);
}

static json_array_t* json_array_add(
        json_array_t* array,
        json_value_t* value) {
    if (array == NULL) {
        ERROR("NULL array");
        return NULL;
    }

    json_array_t* last = json_array_last(array);

    json_array_t* new_entry = json_array_new();
    if (new_entry == NULL) {
        ERROR("json_array_new failed");
        return NULL;
    }

    last->next = new_entry;

    json_array_set_value(new_entry, value);

    return new_entry;
}

typedef struct json_stack_s {
    json_value_t* value;
    struct json_stack_s* previous;
} json_stack_t;

static json_stack_t* json_stack_new() {
    json_stack_t* stack = memory_internal_alloc(sizeof(json_stack_t));
    if (stack == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }

    memory_memset_unoptimizable(stack, 0, sizeof(json_stack_t));
    return stack;
}

static void json_stack_free(json_stack_t* stack) {
    if (stack == NULL) {
        return;
    }

    json_stack_free(stack->previous);
    json_value_free(stack->value);
    memory_internal_free(stack);
}

static void json_stack_set_value(
        json_stack_t* stack,
        json_value_t* value) {
    if (stack == NULL) {
        ERROR("NULL stack");
        return;
    }

    json_value_free(stack->value);
    stack->value = value;
}

static json_stack_t* json_stack_push(json_stack_t* top) {
    json_stack_t* newstack = json_stack_new();
    if (newstack == NULL) {
        ERROR("json_stack_new failed");
        return NULL;
    }

    newstack->previous = top;

    return newstack;
}

static json_stack_t* json_stack_pop(
        json_stack_t* top,
        json_value_t** value) {
    json_stack_t* new_top = top->previous;
    top->previous = NULL;

    if (value != NULL) {
        *value = top->value;
        top->value = NULL;
    }

    json_stack_free(top);

    return new_top;
}

typedef struct {
    yajl_handle yajl;
    json_stack_t* stack;
    json_value_t* root;
} json_parse_context_t;

static void json_parse_context_free(json_parse_context_t* context) {
    if (context == NULL) {
        return;
    }

    if (context->yajl) {
        yajl_free(context->yajl);
    }

    json_stack_free(context->stack);
    json_value_free(context->root);

    memory_internal_free(context);
}

static json_parse_context_t* json_parse_context_new() {
    bool status = false;
    json_parse_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(json_parse_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(json_parse_context_t));

#if YAJL_MAJOR < 2
        context->yajl = yajl_alloc(&global_json.callbacks, &global_json.parser_configuration, NULL, context);
#else
        context->yajl = yajl_alloc(&global_json.callbacks, NULL, context);
#endif
        if (context->yajl == NULL) {
            ERROR("yajl_alloc failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        json_parse_context_free(context);
        context = NULL;
    }

    return context;
}

static void json_parse_context_set_root(
        json_parse_context_t* context,
        json_value_t* root) {
    if (context == NULL) {
        ERROR("NULL context");
        json_value_free(root);
        return;
    }

    json_value_free(context->root);
    context->root = root;
}

static json_stack_t* json_parse_context_push(
        json_parse_context_t* context,
        json_value_t* val) {
    if (context == NULL) {
        ERROR("NULL context");
        return NULL;
    }

    json_stack_t* new_stack = json_stack_push(context->stack);
    if (new_stack == NULL) {
        ERROR("json_stack_push failed");
        return NULL;
    }

    json_stack_set_value(new_stack, val);

    context->stack = new_stack;

    return context->stack;
}

static void json_parse_context_set_value(
        json_parse_context_t* context,
        json_value_t* value) {
    do {
        if (context == NULL) {
            ERROR("NULL context");
            break;
        }

        if (context->stack == NULL) {
            json_parse_context_set_root(context, value);
            return;
        }

        // stack exists, but no value set. should never get here
        if (!context->stack->value) {
            ERROR("NULL context->stack->value");
            break;
        }

        // object on stack
        if (context->stack->value->type == JSON_TYPE_MAP) {
            json_map_t* obj = json_map_last_key_value((json_map_t*) (context->stack->value->payload));
            if (obj == NULL) {
                ERROR("json_map_last_key_value failed");
                break;
            }

            json_map_set_value(obj, value);
            return;
        }

        // array
        if (context->stack->value->type == JSON_TYPE_ARRAY) {
            json_array_t* arr = (json_array_t*) (context->stack->value->payload);
            if (arr == NULL) {
                ERROR("NULL arr");
                break;
            }

            json_array_add(arr, value);
            return;
        }

        ERROR("Invalid context stack state detected");
    } while (false);

    // since an error was detected, free the val
    json_value_free(value);
}

static json_stack_t* json_parse_context_pop(json_parse_context_t* context) {
    if (context == NULL) {
        ERROR("NULL context");
        return NULL;
    }

    if (context->stack == NULL) {
        ERROR("NULL stack");
        return NULL;
    }

    json_value_t* value = NULL;
    context->stack = json_stack_pop(context->stack, &value);

    json_parse_context_set_value(context, value);

    return context->stack;
}

static char* string_new(
        const void* start,
        size_t length) {
    char* string = memory_internal_alloc(length + 1);
    if (string == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }

    memcpy(string, start, length);
    string[length] = '\0';

    return string;
}

static json_value_t* json_value_new(
        json_type_e type,
        void* payload,
        size_t payload_length) {
    json_value_t* value = memory_internal_alloc(sizeof(json_value_t));
    if (value == NULL) {
        ERROR("memory_internal_alloc failed");
        return NULL;
    }
    memory_memset_unoptimizable(value, 0, sizeof(json_value_t));

    value->type = type;
    value->payload = payload;
    value->payload_length = payload_length;

    return value;
}

static json_value_t* json_value_new_bool(bool val) {
    json_value_t* value = NULL;
    bool* payload = NULL;
    do {
        payload = memory_internal_alloc(sizeof(bool));
        if (payload == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        *payload = val;

        value = json_value_new(JSON_TYPE_BOOL, payload, sizeof(bool));
        if (value == NULL) {
            ERROR("json_value_new failed");
            break;
        }

        // payload is now owned by the json_value_t
        payload = NULL;
    } while (false);

    memory_internal_free(payload);

    return value;
}

static json_value_t* json_value_new_double(double val) {
    json_value_t* value = NULL;
    double* payload = NULL;
    do {
        payload = memory_internal_alloc(sizeof(double));
        if (payload == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        *payload = val;

        value = json_value_new(JSON_TYPE_DOUBLE, payload, sizeof(double));
        if (value == NULL) {
            ERROR("json_value_new failed");
            break;
        }

        // payload is now owned by the json_value_t
        payload = NULL;
    } while (false);

    memory_internal_free(payload);

    return value;
}

static json_value_t* json_value_new_array() {
    json_value_t* value = NULL;
    json_array_t* payload = NULL;
    do {
        payload = json_array_new();
        if (payload == NULL) {
            ERROR("json_array_new failed");
            break;
        }

        value = json_value_new(JSON_TYPE_ARRAY, payload, sizeof(json_array_t));
        if (value == NULL) {
            ERROR("json_value_new failed");
            break;
        }

        // payload is now owned by the json_value_t
        payload = NULL;
    } while (false);

    json_array_free(payload);

    return value;
}

static json_value_t* json_value_new_map() {
    json_value_t* value = NULL;
    json_map_t* payload = NULL;
    do {
        payload = json_map_new();
        if (payload == NULL) {
            ERROR("json_map_new failed");
            break;
        }

        value = json_value_new(JSON_TYPE_MAP, payload, sizeof(json_map_t));
        if (value == NULL) {
            ERROR("json_value_new failed");
            break;
        }

        // payload is now owned by the json_value_t
        payload = NULL;
    } while (false);

    json_map_free(payload);

    return value;
}

static json_value_t* json_value_new_integer(long long val) {
    json_value_t* value = NULL;
    long long* payload = NULL;
    do {
        payload = memory_internal_alloc(sizeof(long long));
        if (payload == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        *payload = val;

        value = json_value_new(JSON_TYPE_INT, payload, sizeof(long long));
        if (value == NULL) {
            ERROR("json_value_new failed");
            break;
        }

        // payload is now owned by the json_value_t
        payload = NULL;
    } while (false);

    memory_internal_free(payload);

    return value;
}

static json_value_t* json_value_new_string(
        void* data,
        size_t data_length) {

    json_value_t* value = NULL;
    char* payload = NULL;
    do {
        payload = string_new(data, data_length);
        if (payload == NULL) {
            ERROR("string_new failed");
            break;
        }

        value = json_value_new(JSON_TYPE_STRING, payload, data_length);
        if (value == NULL) {
            ERROR("json_value_new failed");
            break;
        }

        // payload is now owned by json_value_t
        payload = NULL;
    } while (false);

    memory_internal_free(payload);

    return value;
}

static int bool_callback(
        void* context,
        int boolean_value) {
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_value_t* value = json_value_new_bool(boolean_value);
    if (value == NULL) {
        ERROR("json_value_new_bool failed");
        return 0;
    }

    json_parse_context_set_value(session, value);

    return 1;
}

static int double_callback(
        void* context,
        double double_value) {
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_value_t* value = json_value_new_double(double_value);
    if (value == NULL) {
        ERROR("json_value_new_double failed");
        return 0;
    }

    json_parse_context_set_value(session, value);

    return 1;
}

#if YAJL_MAJOR < 2
static int integer_callback(
        void* context,
        long integer_value) {
#else
static int integer_callback(
        void* context,
        long long integer_value) {
#endif
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_value_t* value = json_value_new_integer(integer_value);
    if (value == NULL) {
        ERROR("json_value_new_integer failed");
        return 0;
    }

    json_parse_context_set_value(session, value);

    return 1;
}

static int null_callback(void* context) {
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_parse_context_set_value(session, NULL);

    return 1;
}

#if YAJL_MAJOR < 2
static int string_callback(
        void* context,
        const unsigned char* string,
        unsigned int string_length) {
#else

static int string_callback(
        void* context,
        const unsigned char* string,
        size_t string_length) {
#endif
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_value_t* value = json_value_new_string((char*) string, string_length);
    if (value == NULL) {
        ERROR("json_value_new_string failed");
        return 0;
    }

    json_parse_context_set_value(session, value);

    return 1;
}

#if YAJL_MAJOR < 2
static int map_key_callback(
        void* context,
        const unsigned char* key,
        unsigned int key_length) {
#else

static int map_key_callback(
        void* context,
        const unsigned char* key,
        size_t key_length) {
#endif
    json_parse_context_t* session = (json_parse_context_t*) context;

    if (session->stack == NULL) {
        ERROR("NULL stack");
        return 0;
    }

    if (session->stack->value == NULL) {
        ERROR("NULL value");
        return 0;
    }

    if (session->stack->value->type != JSON_TYPE_MAP) {
        ERROR("value is not an obj");
        return 0;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return 0;
    }

    if (key_length > MAX_KEY_LENGTH) {
        ERROR("Bad key_length");
        return 0;
    }

    json_map_t* new_key_value = json_map_add_key_value((json_map_t*) session->stack->value->payload);
    if (new_key_value == NULL) {
        ERROR("json_map_add_key_value failed");
        return 0;
    }

    json_map_set_key(new_key_value, string_new(key, key_length), key_length);

    return 1;
}

static int start_map_callback(void* context) {
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_value_t* map = json_value_new_map();
    if (map == NULL) {
        ERROR("json_value_new_map failed");
        return 0;
    }

    json_stack_t* stack = json_parse_context_push(session, map);
    if (stack == NULL) {
        json_value_free(map);
        ERROR("json_parse_context_push failed");
        return 0;
    }

    return 1;
}

static int end_map_callback(void* context) {
    json_parse_context_t* session = (json_parse_context_t*) context;
    json_parse_context_pop(session);
    return 1;
}

static int start_array_callback(void* context) {
    json_parse_context_t* session = (json_parse_context_t*) context;

    json_value_t* value = json_value_new_array();
    if (value == NULL) {
        ERROR("json_value_new_array failed");
        return 0;
    }

    json_stack_t* stack = json_parse_context_push(session, value);
    if (stack == NULL) {
        json_value_free(value);
        ERROR("json_parse_context_push failed");
        return 0;
    }

    return 1;
}

static int end_array_callback(void* context) {
    json_parse_context_t* session = (json_parse_context_t*) context;
    json_parse_context_pop(session);
    return 1;
}

json_value_t* json_parse_bytes(
        const void* in,
        size_t in_length) {
    if (in == NULL) {
        ERROR("NULL in");
        return NULL;
    }

    json_value_t* value = NULL;
    json_parse_context_t* context = NULL;
    do {
        context = json_parse_context_new();
        if (context == NULL) {
            ERROR("json_parse_context_new failed");
            break;
        }

        yajl_status yajlstatus = yajl_parse(context->yajl, (const unsigned char*) in, in_length);
        if (yajl_status_ok != yajlstatus) {
            ERROR("yajl_parse failed");
            break;
        }

#if YAJL_MAJOR < 2
        yajlstatus = yajl_parse_complete(context->yajl);
#else
        yajlstatus = yajl_complete_parse(context->yajl);
#endif
        if (yajl_status_ok != yajlstatus) {
            ERROR("yajl_parse_complete failed");
            break;
        }

        value = context->root;
        context->root = NULL;
    } while (false);

    json_parse_context_free(context);

    return value;
}

void json_value_free(json_value_t* value) {
    if (value == NULL) {
        return;
    }

    if (value->type == JSON_TYPE_ARRAY) {
        json_array_free((json_array_t*) value->payload);
    } else if (value->type == JSON_TYPE_MAP) {
        json_map_free((json_map_t*) value->payload);
    } else {
        if (value->payload) {
            memory_memset_unoptimizable(value->payload, 0, value->payload_length);
            memory_internal_free(value->payload);
        }
    }

    memory_internal_free(value);
}

json_type_e json_value_get_type(const json_value_t* value) {
    if (value == NULL) {
        ERROR("NULL value");
        return (json_type_e) -1;
    }

    return value->type;
}

bool json_value_as_bool(const json_value_t* value) {
    if (value == NULL) {
        ERROR("NULL value");
        return false;
    }

    if (value->type != JSON_TYPE_BOOL) {
        ERROR("Bad type: %d", value->type);
        return false;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return false;
    }

    return *((bool*) value->payload);
}

double json_value_as_double(const json_value_t* value) {
    if (value == NULL) {
        ERROR("NULL value");
        return 0;
    }

    if (value->type != JSON_TYPE_DOUBLE) {
        ERROR("Bad type: %d", value->type);
        return 0;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return 0;
    }

    return *((double*) value->payload);
}

json_value_t** json_value_as_array(
        size_t* count,
        const json_value_t* value) {

    if (value == NULL) {
        ERROR("NULL value");
        return 0;
    }

    if (value->type != JSON_TYPE_ARRAY) {
        ERROR("Bad type: %d", value->type);
        return 0;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return 0;
    }

    const json_array_t* array_payload = (const json_array_t*) value->payload;
    size_t size = json_array_size(array_payload);

    json_value_t** values_array = memory_internal_alloc(sizeof(json_value_t*) * size);
    for (size_t i = 0; i < size; ++i) {
        array_payload = array_payload->next;
        values_array[i] = array_payload->value;
    }

    if (count != NULL) {
        *count = size;
    }

    return values_array;
}

json_key_value_t* json_value_as_map(
        size_t* count,
        const json_value_t* value) {

    if (value == NULL) {
        ERROR("NULL value");
        return 0;
    }

    if (value->type != JSON_TYPE_MAP) {
        ERROR("Bad type: %d", value->type);
        return 0;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return 0;
    }

    const json_map_t* map_payload = (const json_map_t*) value->payload;
    size_t size = json_map_size(map_payload);

    json_key_value_t* map_key_values = memory_internal_alloc(sizeof(json_key_value_t) * size);
    for (size_t i = 0; i < size; ++i) {
        map_payload = map_payload->next;
        map_key_values[i].key = map_payload->key;
        map_key_values[i].key_length = map_payload->key_length;
        map_key_values[i].value = map_payload->value;
    }

    if (count != NULL) {
        *count = size;
    }

    return map_key_values;
}

int64_t json_value_as_integer(const json_value_t* value) {
    if (value == NULL) {
        ERROR("NULL value");
        return 0;
    }

    if (value->type != JSON_TYPE_INT) {
        ERROR("Bad type: %d", value->type);
        return 0;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return 0;
    }

    return *((long long*) value->payload);
}

const char* json_value_as_string(
        size_t* size,
        const json_value_t* value) {
    if (value == NULL) {
        ERROR("NULL value");
        return NULL;
    }

    if (value->type != JSON_TYPE_STRING) {
        ERROR("Bad type: %d", value->type);
        return NULL;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return NULL;
    }

    if (size != NULL) {
        *size = value->payload_length;
    }

    return (const char*) value->payload;
}

const char* json_value_as_number(const json_value_t* value) {
    if (value == NULL) {
        ERROR("NULL value");
        return NULL;
    }

    if (value->type != JSON_TYPE_NUMBER) {
        ERROR("Bad type: %d", value->type);
        return NULL;
    }

    if (value->payload == NULL) {
        ERROR("NULL payload");
        return NULL;
    }

    return (const char*) value->payload;
}

const json_key_value_t* json_key_value_find(
        const char* key,
        const json_key_value_t* key_values,
        size_t count) {

    if (key == NULL) {
        ERROR("NULL key");
        return NULL;
    }

    size_t key_length = strnlen(key, MAX_KEY_LENGTH + 1);
    if (key_length == (MAX_KEY_LENGTH + 1)) {
        ERROR("Bad key");
        return NULL;
    }

    if (key_values == NULL) {
        ERROR("NULL key_values");
        return NULL;
    }

    for (size_t i = 0; i < count; ++i) {
        if (key_length == key_values[i].key_length && strncmp(key_values[i].key, key, key_length) == 0) {
            return &key_values[i];
        }
    }

    return NULL;
}

bool b64_decode(
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (*out_length != (in_length * 3) / 4) {
        ERROR("Invalid out_length");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    bool status = false;

    BIO* bio = NULL;
    BIO* b64 = NULL;
    do {
        b64 = BIO_new(BIO_f_base64());
        if (b64 == NULL) {
            ERROR("BIO_new failed");
            break;
        }
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

        bio = BIO_new_mem_buf((void*) in, (int) in_length);
        if (bio == NULL) {
            ERROR("BIO_new_mem_buf failed");
            break;
        }

        bio = BIO_push(b64, bio);
        b64 = NULL;

        int written = BIO_read(bio, out, (int) *out_length);
        if (written < 0) {
            ERROR("BIO_read failed");
            break;
        }

        *out_length = written;
        status = true;
    } while (false);

    BIO_free_all(b64);
    BIO_free_all(bio);

    if (!status) {
        memory_internal_free(out);
    }

    return status;
}

void string_to_lowercase(
        uint8_t* str,
        size_t length) {
    for (size_t i = 0; i < length; i++)
        if ('A' <= str[i] && str[i] <= 'Z')
            str[i] += 32;
}
