/*
 * Copyright 2020-2024 Comcast Cable Communications Management, LLC
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
#ifndef SA_KEY_PROVISION_IMPL_H
#define SA_KEY_PROVISION_IMPL_H

sa_status sa_key_provision_preprocessing(
   const sa_key_type_ta ta_key_type,
   const void* in,
   const size_t in_length,
   void* parameters);
 
#endif // SA_KEY_PROVISION_IMPL_H
