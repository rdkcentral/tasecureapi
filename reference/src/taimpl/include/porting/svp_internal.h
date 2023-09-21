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
 * @file svp.h
 *
 * This file contains the internal functions and structures implementing validation of and writing to secure
 * video pipeline buffers. Implementors shall replace this functionality with platform dependent
 * functionality.
 */

#ifndef SVP_H
#define SVP_H

#include "sa_types.h"
#include "porting/svp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the protected SVP memory location.
 *
 * @param[in] svp_memory the SVP memory.
 * @return the SVP buffer.
 */
void* svp_get_svp_memory(void* svp_memory);

/**
 * Get the protected SVP memory size.
 *
 * @param[in] svp_memory svp.
 * @return the buffer length.
 */
size_t svp_get_size(const void* svp_memory);

#ifdef __cplusplus
}
#endif

#endif // SVP_H
