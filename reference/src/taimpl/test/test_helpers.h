/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include "ta_sa.h"

#define MAX_CLIENT_SLOTS 256

namespace test_helpers {
    void rights_allow_all(sa_rights* rights);

    const sa_uuid* uuid();

    ta_client client();
} // namespace test_helpers

#endif // TEST_HELPERS_H
