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

#include "fmd/generate.h"

#include <string.h>

int create_descriptor(const struct fmd_region* regions, size_t region_count,
                      int hash_type, struct image_fmd *out) {
  // Populate header
  out->header.tlv.tag = FMD_HEADER_TAG;
  out->header.tlv.length = sizeof(out->header);
  out->header.tlv.version = FMD_HEADER_VERSION;
  out->header.magic = FMD_MAGIC;
  out->header.descriptor_offset = 0;
  out->header.descriptor_area_size = sizeof(out->header) +
                                     sizeof(out->region_info) +
                                     (region_count * sizeof(struct fmd_region));

  // Populate region info
  out->region_info.tlv.tag = FMD_REGION_INFO_TAG;
  out->region_info.tlv.length = sizeof(out->region_info);
  out->region_info.tlv.version = FMD_REGION_INFO_VERSION;
  out->region_info.region_count = region_count;
  out->region_info.hash_type = hash_type;

  memcpy(out->regions, regions, sizeof(struct fmd_region) * region_count);

  return FMD_SUCCESS;
}

