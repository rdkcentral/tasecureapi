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
 * @file saimpl.h
 *
 * This file contains the functions implementing SecApi implementation functions
 */

#ifndef SAIMPL_H
#define SAIMPL_H

#include "sa_types.h"

/**
 * Retrieves the name of the SecApi implementation.
 *
 * @return the name of the SecApi implementation.
 */
const char* get_implementation_name();

/**
 * Retrieves the version of the SecApi implementation.
 *
 * @return the version of the SecApi implementation.
 */
const sa_version* get_implementation_version();

#endif // SAIMPL_H
