/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __FMD_GENERATE_H
#define __FMD_GENERATE_H

#include "fmd/fmd.h"
#include "fmd/util.h"

#include <stddef.h>

int create_descriptor(const struct fmd_region* regions, size_t region_count,
                      int hash_type, struct image_fmd *out);

#endif // __FMD_GENERATE_H
