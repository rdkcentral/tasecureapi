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

#include "json.h"
#include "porting/memory.h"
#include "gtest/gtest.h"

namespace {
    TEST(Json, parseBoolTrue) {
        const char* json = "true";

        json_value_t* value;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_BOOL);
            EXPECT_EQ(json_value_as_bool(value), true);
        } while (false);

        json_value_free(value);
    }

    TEST(Json, parseBoolFalse) {
        const char* json = "false";

        json_value_t* value;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_BOOL);
            EXPECT_EQ(json_value_as_bool(value), false);
        } while (false);

        json_value_free(value);
    }

    TEST(Json, parseDouble) {
        const char* json = "1.1";

        json_value_t* value;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_DOUBLE);
            EXPECT_EQ(json_value_as_double(value), 1.1);
        } while (false);

        json_value_free(value);
    }

    TEST(Json, parseArrayEmpty) {
        const char* json = "[]";
        size_t const array_size = 0;

        json_value_t* value;
        json_value_t** array = nullptr;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_ARRAY);

            size_t size;
            array = json_value_as_array(&size, value);
            EXPECT_NE(array, nullptr);
            EXPECT_EQ(size, array_size);
        } while (false);

        json_value_free(value);
        memory_internal_free(array);
    }

    TEST(Json, parseArrayInt) {
        const char* json = "[1, 2, 3, 4]";
        size_t const array_size = 4;

        json_value_t* value;
        json_value_t** array = nullptr;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_ARRAY);

            size_t size;
            array = json_value_as_array(&size, value);
            EXPECT_NE(array, nullptr);
            EXPECT_EQ(size, array_size);

            if (array == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_as_integer(array[0]), 1);
            EXPECT_EQ(json_value_as_integer(array[1]), 2);
            EXPECT_EQ(json_value_as_integer(array[2]), 3);
            EXPECT_EQ(json_value_as_integer(array[3]), 4);
        } while (false);

        json_value_free(value);
        memory_internal_free(array);
    }

    TEST(Json, parseMapEmpty) {
        const char* json = "{}";
        size_t const map_size = 0;

        json_value_t* value;
        json_key_value_t* map = nullptr;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_MAP);

            size_t size;
            map = json_value_as_map(&size, value);
            EXPECT_NE(map, nullptr);
            EXPECT_EQ(size, map_size);
        } while (false);

        json_value_free(value);
        memory_internal_free(map);
    }

    TEST(Json, parseMapSimple) {
        const char* json = R"({ "first" : 1, "second" : 2, "third" : 3, "fourth" : 4 })";
        size_t const map_size = 4;

        json_value_t* value;
        json_key_value_t* map = nullptr;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_MAP);

            size_t size;
            map = json_value_as_map(&size, value);
            EXPECT_NE(map, nullptr);
            EXPECT_EQ(size, map_size);

            if (map == nullptr) {
                break;
            }

            EXPECT_STREQ(map[0].key, "first");
            EXPECT_EQ(json_value_as_integer(map[0].value), 1);
            EXPECT_STREQ(map[1].key, "second");
            EXPECT_EQ(json_value_as_integer(map[1].value), 2);
            EXPECT_STREQ(map[2].key, "third");
            EXPECT_EQ(json_value_as_integer(map[2].value), 3);
            EXPECT_STREQ(map[3].key, "fourth");
            EXPECT_EQ(json_value_as_integer(map[3].value), 4);
        } while (false);

        json_value_free(value);
        memory_internal_free(map);
    }

    TEST(Json, parseInt) {
        const char* json = "1";

        json_value_t* value;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_INT);
            EXPECT_EQ(json_value_as_integer(value), 1);
        } while (false);

        json_value_free(value);
    }

    TEST(Json, parseNull) {
        const char* json = "null";

        json_value_t* value = json_parse_bytes(json, strlen(json));

        EXPECT_EQ(value, nullptr);

        json_value_free(value);
    }

    TEST(Json, parseString) {
        const char* json = "\"string\"";

        json_value_t* value;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_STRING);
            EXPECT_STREQ(json_value_as_string(nullptr, value), "string");
        } while (false);

        json_value_free(value);
    }

    TEST(Json, parseNested) {
        const char* json = R"({"arr":[],"map":{},"bool":true,"dbl":1.0,"int":1,"str":"str","null":null})";

        json_value_t* value;
        json_key_value_t* collection = nullptr;
        json_value_t** array = nullptr;
        json_key_value_t* map = nullptr;

        do {
            value = json_parse_bytes(json, strlen(json));

            EXPECT_NE(value, nullptr);
            if (value == nullptr) {
                break;
            }

            EXPECT_EQ(json_value_get_type(value), JSON_TYPE_MAP);
            size_t collsize;
            collection = json_value_as_map(&collsize, value);
            EXPECT_EQ(collsize, 7);

            if (collection == nullptr) {
                break;
            }

            EXPECT_STREQ(collection[0].key, "arr");
            size_t arrsize;
            array = json_value_as_array(&arrsize, collection[0].value);
            EXPECT_NE(array, nullptr);

            EXPECT_STREQ(collection[1].key, "map");
            size_t mapsize;
            map = json_value_as_map(&mapsize, collection[1].value);
            EXPECT_NE(map, nullptr);

            EXPECT_STREQ(collection[2].key, "bool");
            EXPECT_EQ(json_value_as_bool(collection[2].value), true);

            EXPECT_STREQ(collection[3].key, "dbl");
            EXPECT_EQ(json_value_as_double(collection[3].value), 1.0);

            EXPECT_STREQ(collection[4].key, "int");
            EXPECT_EQ(json_value_as_integer(collection[4].value), 1);

            EXPECT_STREQ(collection[5].key, "str");
            EXPECT_STREQ(json_value_as_string(nullptr, collection[5].value), "str");

            EXPECT_STREQ(collection[6].key, "null");
            EXPECT_EQ(collection[6].value, nullptr);
        } while (false);

        json_value_free(value);
        memory_internal_free(collection);
        memory_internal_free(array);
        memory_internal_free(map);
    }
} // namespace
