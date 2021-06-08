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

#ifndef _UTIL_H
#define _UTIL_H

#include "fmd.h"

#define MAX_REGION_COUNT 0xFF

#define FMD_SUCCESS 0x0
#define FMD_ERROR_INVALID_FORMAT 0x1
#define FMD_ERROR_INVALID_ARGUMENT 0x2
#define FMD_ERROR_UNKNOWN_VERSION 0x2
#define FMD_ERROR_UNKNOWN 0x2

struct image_fmd {
  struct fmd_header header;
  struct fmd_region_info region_info;
  struct fmd_region regions[MAX_REGION_COUNT];
};

#endif // _UTIL_H
